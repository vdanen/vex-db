#!/usr/bin/env python3

import sqlite3
import argparse
import sys
from pathlib import Path

def connect_to_database(db_path="vex.db"):
    """Connect to the VEX database"""
    if not Path(db_path).exists():
        print(f"❌ Database file '{db_path}' not found!")
        print("Make sure to run 'import-vex.py' first to create and populate the database.")
        sys.exit(1)
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        return conn
    except sqlite3.Error as e:
        print(f"❌ Error connecting to database: {e}")
        sys.exit(1)

def build_query(component=None, year=None, exact=False, product=None, cpe=None, purl=None):
    """Build SQL query based on parameters"""
    base_query = """
    SELECT 
        a.cve,
        a.product,
        a.cpe,
        a.purl,
        a.state,
        a.reason,
        a.errata,
        a.components,
        c.public_date,
        c.cvss_score,
        c.severity
    FROM affects a
    LEFT JOIN cve c ON a.cve = c.cve
    """
    
    params = []
    where_conditions = []

    # Add component filter if provided
    if component:
        if exact:
            where_conditions.append("a.components LIKE ?")
            params.append(f"{component}%")
        else:
            where_conditions.append("a.components LIKE ?")
            params.append(f"%{component}%")
    
    # Add other filters
    if year:
        where_conditions.append("c.public_date LIKE ?")
        params.append(f"{year}%")
    
    if product:
        if exact:
            where_conditions.append("a.product LIKE ?")
            params.append(f"{product}")
        else:
            where_conditions.append("a.product LIKE ?")
            params.append(f"%{product}%")

    if cpe:
        if exact:
            where_conditions.append("a.cpe LIKE ?")
            params.append(f"{cpe}")
        else:
            where_conditions.append("a.cpe LIKE ?")
            params.append(f"%{cpe}%")

    if purl:
        if exact:
            where_conditions.append("a.purl LIKE ?")
            params.append(f"{purl}")
        else:
            where_conditions.append("a.purl LIKE ?")
            params.append(f"%{purl}%")

    # Add WHERE clause if any conditions exist
    if where_conditions:
        base_query += " WHERE " + " AND ".join(where_conditions)

    base_query += " ORDER BY a.cve DESC, a.product DESC, a.state"
    
    return base_query, params

def format_output(results, component, exact=False):
    """Format query results for display"""
    if not results:
        if component:
            print(f"🔍 No CVEs found affecting component '{component}'")
        else:
            print(f"🔍 No CVEs found matching the specified criteria")
        return
    
    # Convert all results to dictionaries for consistent handling
    dict_results = [dict(row) for row in results]

    # Group by product, then by CVE for deduplication
    products = {}
    cpes = {}

    for row in dict_results:
        product = row['product'] or 'Unknown Product'
        cpe = row['cpe'] or 'Unknown CPE'
        cve = row['cve'] or 'N/A'

        if product not in products:
            products[product] = {}
            cpes[product] = cpe

        if cve not in products[product]:
            products[product][cve] = []

        products[product][cve].append(row)

    # Normalize CVEs that have both 'affected' and 'wontfix' states
    normalized_products = {}
    for product, cves in products.items():
        normalized_products[product] = []

        for cve, entries in cves.items():
            if len(entries) > 1:
                # Check if we have both 'affected' and 'wontfix' states
                states = [entry['state'].lower() for entry in entries if entry['state']]
                affected_entry = None
                wontfix_entry = None
                other_entries = []

                for entry in entries:
                    state = entry['state'].lower() if entry['state'] else 'unknown'
                    if state == 'affected':
                        affected_entry = entry
                    elif state == 'wontfix':
                        wontfix_entry = entry
                    else:
                        other_entries.append(entry)

                # If we have both affected and wontfix, combine them
                if affected_entry and wontfix_entry:
                    combined_entry = affected_entry.copy()
                    reason = wontfix_entry['reason'] or ''
                    combined_entry['combined_state'] = 'affected_wontfix'
                    combined_entry['wontfix_reason'] = reason
                    normalized_products[product].append(combined_entry)

                    # Add any other entries separately
                    normalized_products[product].extend(other_entries)
                else:
                    # No affected+wontfix combination, add all entries as-is
                    normalized_products[product].extend(entries)
            else:
                # Single entry, add as-is
                normalized_products[product].extend(entries)

    total_cves = len(results)
    unique_cves = len(set(row['cve'] for row in results))
    
    # Display results summary
    if component:
        if exact:
            print(f"🔍 Found {total_cves} entries for component '{component}' ({unique_cves} unique CVEs) (exact match)")
        else:
            print(f"🔍 Found {total_cves} entries for component '{component}' ({unique_cves} unique CVEs) (fuzzy match)")
    else:
        print(f"🔍 Found {total_cves} entries matching criteria ({unique_cves} unique CVEs)")

    print("=" * 80)
    
    for product, entries in normalized_products.items():
        print(f"\n📦 {product} ({cpes[product]})")
        print("-" * 60)
        
        for entry in entries:
            cve = entry['cve'] or 'N/A'
            state = entry['state'] or 'unknown'
            reason = entry['reason'] or ''
            errata = entry['errata'] or ''
            components = entry['components'] or ''
            public_date = entry['public_date'] or 'N/A'
            cvss_score = entry['cvss_score'] or 'N/A'
            severity = entry['severity'] or 'N/A'
            
            # Handle combined affected+wontfix state
            if entry.get('combined_state') == 'affected_wontfix':
                state_icon = '❌⚠️'  # Combined icon
                wontfix_reason = entry.get('wontfix_reason', '')
                if wontfix_reason:
                    state_string = f"Affected:Wontfix: {wontfix_reason}"
                else:
                    state_string = f"Affected:Wontfix"
            else:
                # Format state with color indicators (original logic)
                state_icon = {
                    'fixed': '✅',
                    'affected': '❌',
                    'not_affected': '⚪',
                    'wontfix': '⚠️'
                }.get(state.lower(), '❓')

                if state.lower() == 'fixed':
                    state_string = f"Fixed in: {errata}"
                elif state.lower() == 'affected':
                    state_string = f"Affected"
                elif state.lower() == 'not_affected':
                    state_string = f"Not affected"
                    if reason:
                        state_string += f" {reason}"
                elif state.lower() == 'wontfix':
                    state_string = f"Wontfix"
                    if reason:
                        state_string += f": {reason}"
                else:
                    state_string = f"🔧 {state}"

            cvss_string = f"CVSS: {cvss_score} ({severity})"

            components_list = []
            if components:
                c = components.split(',')
                if component:
                    # Filter components to show only those matching the search term
                    for x in c:
                        if component in x:
                            components_list.append(x)
                else:
                    # Show all components when no component filter is specified
                    components_list = c

            cmps = ', '.join(components_list)
            if len(cmps) > 100:
                cmps = cmps[:100] + '...'
            print(f"  {state_icon} {cve:<15} | 📅 {public_date} | {state_string:<30} | {cvss_string:<21} | {cmps}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Query VEX database for CVEs affecting specific components, products, or other criteria",
        epilog="""
Examples:
  %(prog)s --component mysql                    # Find all CVEs affecting mysql component
  %(prog)s --component kernel --year 2024       # Find kernel CVEs from 2024
  %(prog)s --product "Red Hat Enterprise Linux" # Find all CVEs for a product
  %(prog)s --year 2024                          # Find all CVEs from 2024
  %(prog)s --component openssl --product "Red Hat Enterprise Linux"  # Filter by product
  %(prog)s --component kernel --product RHEL --year 2024  # Multiple filters
  %(prog)s --component openssl --database custom.db  # Use custom database file
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--component', '-x',
        dest='component',
        help='Component name to search for (supports partial matches, optional)'
    )
    
    parser.add_argument(
        '--year', '-y',
        type=int,
        help='Filter results by year (e.g., 2024)'
    )
    
    parser.add_argument(
        '--product', '-p',
        help='Filter results by product name (supports partial matches)'
    )

    parser.add_argument(
        '--cpe',
        help='Filter results by CPE (supports partial matches)'
    )
    parser.add_argument(
        '--purl',
        help='Filter results by PURL (supports partial matches)'
    )

    parser.add_argument(
        '--database', '-d',
        default='vex.db',
        help='Path to VEX database file (default: vex.db)'
    )
    
    parser.add_argument(
        '--format',
        choices=['table', 'json', 'csv'],
        default='table',
        help='Output format (default: table)'
    )
    
    parser.add_argument(
        '--count-only', '-c',
        action='store_true',
        help='Only show count of results, not detailed output'
    )

    parser.add_argument(
        '--exact', '-e',
        action='store_true',
        help='Do an exact filter match (works with components, products, cpes and purls); defaults to fuzzy match'
    )

    parser.add_argument(
        '--list-cpes',
        action='store_true',
        help='List all known CPEs'
    )
    
    args = parser.parse_args()
    
    # listing CPEs is a one-off
    if args.list_cpes:
        conn = connect_to_database(args.database)
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT cpe, product FROM affects ORDER BY product")
        results = cursor.fetchall()
        print(f"🔍 Listing {len(results)} unique CPEs in the database")
        print("-" * 80)
        for row in results:
            print(f"{row['product']} ==> {row['cpe']}")
        sys.exit(0)

    # Validate year
    if args.year and (args.year < 1999 or args.year > 2030):
        print(f"❌ Invalid year: {args.year}. Please use a reasonable year (1999-2030)")
        sys.exit(1)
    
    # Validate that only one of --product, --cpe, or --purl is used
    filter_args = [args.product, args.cpe, args.purl]
    filter_names = ['--product', '--cpe', '--purl']
    active_filters = [name for name, arg in zip(filter_names, filter_args) if arg is not None]

    if len(active_filters) > 1:
        print(f"❌ Error: Only one filter can be used at a time. You specified: {', '.join(active_filters)}")
        print("Please use only one of --product, --cpe, or --purl.")
        sys.exit(1)

    # Validate that at least one filter is provided
    all_filters = [args.component, args.product, args.cpe, args.purl, args.year]
    if not any(all_filters):
        print("❌ Error: At least one filter must be specified.")
        print("Use --component, --product, --cpe, --purl, or --year to filter results.")
        sys.exit(1)

    # Connect to database
    conn = connect_to_database(args.database)
    
    try:
        # Build and execute query
        query, params = build_query(args.component, args.year, args.exact, args.product, args.cpe, args.purl)
        
        # Display search criteria
        search_criteria = []
        if args.component:
            search_criteria.append(f"component: '{args.component}'")
        if args.year:
            search_criteria.append(f"year: {args.year}")
        if args.product:
            search_criteria.append(f"product: '{args.product}'")
        if args.cpe:
            search_criteria.append(f"CPE: '{args.cpe}'")
        if args.purl:
            search_criteria.append(f"PURL: '{args.purl}'")

        print(f"🔎 Searching with filters: {', '.join(search_criteria)}")
        print(f"🗄️  Database: {args.database}")
        print()
        
        cursor = conn.cursor()
        cursor.execute(query, params)
        results = cursor.fetchall()
        
        if args.count_only:
            unique_cves = len(set(row['cve'] for row in results))
            print(f"📊 Results: {len(results)} entries, {unique_cves} unique CVEs")
        elif args.format == 'json':
            import json
            output = []
            for row in results:
                output.append(dict(row))
            print(json.dumps(output, indent=2))
        elif args.format == 'csv':
            import csv
            import io
            output = io.StringIO()
            if results:
                writer = csv.DictWriter(output, fieldnames=results[0].keys())
                writer.writeheader()
                for row in results:
                    # Convert row to dict and modify components field for CSV
                    row_dict = dict(row)
                    if row_dict['components'] and ',' in row_dict['components']:
                        # Replace commas with spaces for CSV output only
                        row_dict['components'] = row_dict['components'].replace(',', ' ')
                    writer.writerow(row_dict)
            print(output.getvalue())
        else:
            format_output(results, args.component, args.exact)
            
    except sqlite3.Error as e:
        print(f"❌ Database query error: {e}")
        sys.exit(1)
    finally:
        conn.close()

if __name__ == "__main__":
    main()

