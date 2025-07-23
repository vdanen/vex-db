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

def build_query(component, year=None, exact=False, product=None):
    """Build SQL query based on parameters"""
    base_query = """
    SELECT 
        a.cve,
        a.product,
        a.state,
        a.reason,
        a.errata,
        a.components,
        c.public_date,
        c.cvss_score,
        c.severity
    FROM affects a
    LEFT JOIN cve c ON a.cve = c.cve
    WHERE a.components LIKE ?
    """
    
    if exact:
        params = [f"{component}-%"]
    else:
        params = [f"%{component}%"]
    
    if year:
        base_query += " AND c.public_date LIKE ?"
        params.append(f"{year}%")
    
    if product:
        base_query += " AND a.product LIKE ?"
        params.append(f"%{product}%")

    base_query += " ORDER BY a.product DESC, a.state"
    
    return base_query, params

def format_output(results, component, exact=False):
    """Format query results for display"""
    if not results:
        print(f"🔍 No CVEs found affecting component '{component}'")
        return
    
    # Group by product for better display
    products = {}
    for row in results:
        product = row['product'] or 'Unknown Product'
        if product not in products:
            products[product] = []
        products[product].append(row)
    
    total_cves = len(results)
    unique_cves = len(set(row['cve'] for row in results))
    
    if exact:
        print(f"🔍 Found {total_cves} entries for component '{component}' ({unique_cves} unique CVEs) (exact match)")
    else:
        print(f"🔍 Found {total_cves} entries for component '{component}' ({unique_cves} unique CVEs) (fuzzy match)")

    print("=" * 80)
    
    for product, entries in products.items():
        print(f"\n📦 {product}")
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
            
            # Format state with color indicators
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
                for x in c:
                    if component in x:
                        components_list.append(x)

            print(f"  {state_icon} {cve:<15} | 📅 {public_date} | {state_string:<30} | {cvss_string:<21} | {', '.join(components_list)}")
        print()

def main():
    parser = argparse.ArgumentParser(
        description="Query VEX database for CVEs affecting specific components",
        epilog="""
Examples:
  %(prog)s --component mysql                    # Find all CVEs affecting mysql component
  %(prog)s --component kernel --year 2024       # Find kernel CVEs from 2024
  %(prog)s --component openssl --product "Red Hat Enterprise Linux"  # Filter by product
  %(prog)s --component kernel --product RHEL --year 2024  # Multiple filters
  %(prog)s --component openssl --database custom.db  # Use custom database file
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--component', '-x',
        dest='component',
        help='Component name to search for (supports partial matches)'
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
        help='Do an exact match on the component name; defaults to fuzzy match'
    )
    
    args = parser.parse_args()
    
    # Validate year
    if args.year and (args.year < 1999 or args.year > 2030):
        print(f"❌ Invalid year: {args.year}. Please use a reasonable year (1999-2030)")
        sys.exit(1)
    
    # Connect to database
    conn = connect_to_database(args.database)
    
    try:
        # Build and execute query
        query, params = build_query(args.component, args.year, args.exact, args.product)
        
        print(f"🔎 Searching for component: '{args.component}'")
        if args.year:
            print(f"📅 Year filter: {args.year}")
        if args.product:
            print(f"📦 Product filter: '{args.product}'")
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

