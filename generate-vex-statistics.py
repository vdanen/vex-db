#!/usr/bin/env python3

import sqlite3
import argparse
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import statistics

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

def parse_release_date(date_str):
    """Parse release date in 'Month DD, YYYY' format"""
    try:
        return datetime.strptime(date_str, "%B %d, %Y")
    except ValueError:
        return None

def parse_public_date(date_str):
    """Parse public date in 'YYYY-MM-DD' format"""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return None

def get_days_of_risk_stats(conn, year):
    """Calculate days of risk statistics for each severity level"""
    query = """
    SELECT c.cve, c.public_date, c.severity, a.release_date
    FROM cve c
    INNER JOIN affects a ON c.cve = a.cve
    WHERE c.public_date LIKE ? 
    AND c.public_date IS NOT NULL 
    AND a.release_date IS NOT NULL 
    AND a.errata IS NOT NULL 
    AND a.errata != ''
    ORDER BY c.cve, a.release_date
    """
    
    cursor = conn.cursor()
    cursor.execute(query, (f"{year}%",))
    results = cursor.fetchall()
    
    # Group by CVE and find earliest errata for each
    cve_earliest_fix = {}
    for row in results:
        cve = row['cve']
        public_date = parse_public_date(row['public_date'])
        release_date = parse_release_date(row['release_date'])
        severity = row['severity'] or 'Unknown'
        
        if public_date and release_date:
            if cve not in cve_earliest_fix or release_date < cve_earliest_fix[cve]['release_date']:
                cve_earliest_fix[cve] = {
                    'public_date': public_date,
                    'release_date': release_date,
                    'severity': severity,
                    'days_of_risk': (release_date - public_date).days
                }
    
    # Group by severity and calculate statistics
    severity_stats = defaultdict(list)
    for cve_data in cve_earliest_fix.values():
        if cve_data['days_of_risk'] >= 0:  # Only positive days (no future fixes)
            severity_stats[cve_data['severity']].append(cve_data['days_of_risk'])
    
    # Calculate min, max, avg, median for each severity
    risk_stats = {}
    for severity, days_list in severity_stats.items():
        if days_list:
            risk_stats[severity] = {
                'min': min(days_list),
                'max': max(days_list),
                'avg': sum(days_list) / len(days_list),
                'median': statistics.median(days_list),
                'count': len(days_list)
            }
    
    return risk_stats

def get_cves_affecting_products(conn, year):
    """Get CVEs from a specific year that affect products, grouped by severity"""
    query = """
    SELECT DISTINCT c.cve, c.severity
    FROM cve c
    INNER JOIN affects a ON c.cve = a.cve
    WHERE c.public_date LIKE ? AND a.product IS NOT NULL AND a.product != ''
    """
    
    cursor = conn.cursor()
    cursor.execute(query, (f"{year}%",))
    results = cursor.fetchall()
    
    severity_counts = defaultdict(int)
    for row in results:
        severity = row['severity'] or 'Unknown'
        severity_counts[severity] += 1
    
    return dict(severity_counts), len(results)

def get_cves_not_affecting_products(conn, year):
    """Get CVEs from a specific year that do NOT affect any products, grouped by severity"""
    query = """
    SELECT DISTINCT c.cve, c.severity
    FROM cve c
    WHERE c.public_date LIKE ? 
    AND c.cve NOT IN (
        SELECT DISTINCT cve 
        FROM affects 
        WHERE product IS NOT NULL AND product != ''
    )
    """
    
    cursor = conn.cursor()
    cursor.execute(query, (f"{year}%",))
    results = cursor.fetchall()
    
    severity_counts = defaultdict(int)
    for row in results:
        severity = row['severity'] or 'Unknown'
        severity_counts[severity] += 1
    
    return dict(severity_counts), len(results)

def get_errata_statistics(conn, year):
    """Get errata released in a specific year, aggregated by highest severity"""
    # Get all errata released in the specified year with their associated CVE severities
    # Note: release_date is in format "Month DD, YYYY", so we match the year at the end
    query = """
    SELECT DISTINCT a.errata, c.severity
    FROM affects a
    INNER JOIN cve c ON a.cve = c.cve
    WHERE a.release_date LIKE ? 
    AND a.errata IS NOT NULL 
    AND a.errata != ''
    ORDER BY a.errata, c.severity
    """
    
    cursor = conn.cursor()
    cursor.execute(query, (f"%, {year}",))
    results = cursor.fetchall()
    
    # Group by errata and find the highest severity for each
    errata_severities = defaultdict(list)
    for row in results:
        errata = row['errata']
        severity = row['severity'] or 'Unknown'
        errata_severities[errata].append(severity)
    
    # Define severity hierarchy (highest to lowest)
    severity_hierarchy = {
        'Critical': 4,
        'Important': 3,
        'Moderate': 2,
        'Low': 1,
        'Unknown': 0
    }
    
    # Find the highest severity for each errata
    errata_highest_severity = {}
    for errata, severities in errata_severities.items():
        highest_severity = max(severities, key=lambda x: severity_hierarchy.get(x, 0))
        errata_highest_severity[errata] = highest_severity
    
    # Count by highest severity
    severity_counts = defaultdict(int)
    for severity in errata_highest_severity.values():
        severity_counts[severity] += 1
    
    return dict(severity_counts), len(errata_highest_severity)

def get_top_cwes(conn, year, limit=10):
    """Get the top CWEs for a specific year"""
    query = """
    SELECT c.cwe, COUNT(*) as count
    FROM cve c
    WHERE c.public_date LIKE ? 
    AND c.cwe IS NOT NULL 
    AND c.cwe != ''
    GROUP BY c.cwe
    ORDER BY count DESC, c.cwe ASC
    LIMIT ?
    """
    
    cursor = conn.cursor()
    cursor.execute(query, (f"{year}%", limit))
    results = cursor.fetchall()
    
    return [(row['cwe'], row['count']) for row in results]

def get_total_unique_cwes_count(conn, year):
    """Get the total count of unique CWEs for a specific year"""
    query = """
    SELECT COUNT(DISTINCT c.cwe) as unique_cwe_count
    FROM cve c
    WHERE c.public_date LIKE ? 
    AND c.cwe IS NOT NULL 
    AND c.cwe != ''
    """
    
    cursor = conn.cursor()
    cursor.execute(query, (f"{year}%",))
    result = cursor.fetchone()
    
    return result['unique_cwe_count'] if result else 0

def get_cve_details_by_severity(conn, year):
    """Get detailed CVE information for each severity level"""
    query = """
    SELECT c.cve, c.public_date, c.severity, a.product, a.components, 
           a.errata, a.release_date
    FROM cve c
    INNER JOIN affects a ON c.cve = a.cve
    WHERE c.public_date LIKE ? 
    AND a.product IS NOT NULL 
    AND a.product != ''
    ORDER BY c.cve, a.release_date
    """
    
    cursor = conn.cursor()
    cursor.execute(query, (f"{year}%",))
    results = cursor.fetchall()
    
    # Group by CVE and severity, finding the fastest fix for each CVE
    cve_details = defaultdict(lambda: defaultdict(list))
    
    for row in results:
        cve = row['cve']
        severity = row['severity'] or 'Unknown'
        public_date = row['public_date']
        product = row['product']
        components = row['components']
        errata = row['errata']
        release_date = row['release_date']
        
        # Parse dates for comparison
        pub_date_obj = parse_public_date(public_date)
        rel_date_obj = parse_release_date(release_date) if release_date else None
        
        cve_info = {
            'cve': cve,
            'public_date': public_date,
            'product': product,
            'components': components,
            'errata': errata,
            'release_date': release_date,
            'release_date_obj': rel_date_obj
        }
        
        # Only add if we have valid dates and errata
        if pub_date_obj and rel_date_obj and errata:
            cve_details[severity][cve].append(cve_info)
    
    # For each CVE, keep only the fastest fix
    fastest_fixes = defaultdict(list)
    for severity, cves in cve_details.items():
        for cve, fixes in cves.items():
            if fixes:
                # Sort by release date and take the first (fastest) fix
                fastest_fix = min(fixes, key=lambda x: x['release_date_obj'])
                fastest_fixes[severity].append(fastest_fix)
    
    # Sort CVEs within each severity by public date
    for severity in fastest_fixes:
        fastest_fixes[severity].sort(key=lambda x: x['public_date'])
    
    return dict(fastest_fixes)

def format_severity_table(severity_counts, title, risk_stats=None):
    """Format severity statistics as a table with optional days of risk data"""
    print(f"\n📊 {title}")
    if risk_stats:
        print("=" * 105)
    else:
        print("=" * 60)
    
    # Define the expected severity levels in order
    severity_order = ['Critical', 'Important', 'Moderate', 'Low', 'Unknown']
    
    total = sum(severity_counts.values())
    if total == 0:
        print("   No data found for this category.")
        return
    
    if risk_stats:
        print(f"{'Severity':<12} {'Count':<8} {'%':<6} {'Days of Risk (Min/Max/Avg/Median)':<50} {'Fixed CVEs (%)':<15}")
        print("-" * 105)
    else:
        print(f"{'Severity':<12} {'Count':<8} {'Percentage':<12}")
        print("-" * 35)
    
    for severity in severity_order:
        count = severity_counts.get(severity, 0)
        if count > 0:
            percentage = (count / total) * 100
            
            if risk_stats and severity in risk_stats:
                risk_data = risk_stats[severity]
                min_days = risk_data['min']
                max_days = risk_data['max']
                avg_days = risk_data['avg']
                median_days = risk_data['median']
                fixed_count = risk_data['count']
                fixed_percentage = (fixed_count / count) * 100
                
                risk_str = f"{min_days:>3}/{max_days:>3}/{avg_days:>5.1f}/{median_days:>5.1f} days"
                fixed_str = f"{fixed_count} ({fixed_percentage:.1f}%)"
                print(f"{severity:<12} {count:<8} {percentage:>4.1f}%  {risk_str:<50} {fixed_str:<15}")
            elif risk_stats:
                # Severity exists but no risk data (no errata available)
                fixed_str = f"0 (0.0%)"
                print(f"{severity:<12} {count:<8} {percentage:>4.1f}%  {'No errata data available':<50} {fixed_str:<15}")
            else:
                print(f"{severity:<12} {count:<8} {percentage:>6.1f}%")
    
    if risk_stats:
        print("-" * 105)
        print(f"{'Total':<12} {total:<8} {'100.0%':<6}")
    else:
        print("-" * 35)
        print(f"{'Total':<12} {total:<8} {'100.0%':>12}")

def format_cwe_table(cwe_data, title):
    """Format CWE statistics as a table"""
    print(f"\n🔍 {title}")
    print("=" * 50)
    
    if not cwe_data:
        print("   No CWE data found for this year.")
        return
    
    total_cves = sum(count for _, count in cwe_data)
    
    print(f"{'Rank':<6} {'CWE':<12} {'Count':<8} {'Percentage':<12}")
    print("-" * 40)
    
    for rank, (cwe, count) in enumerate(cwe_data, 1):
        percentage = (count / total_cves) * 100
        print(f"{rank:<6} {cwe:<12} {count:<8} {percentage:>6.1f}%")
    
    print("-" * 40)
    print(f"{'':>18} {total_cves:<8} {'100.0%':>12}")

def format_cve_debug_output(cve_details, severity_counts, year):
    """Format detailed CVE information for debug mode"""
    severity_order = ['Critical', 'Important', 'Moderate', 'Low', 'Unknown']
    
    for severity in severity_order:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"\n🔍 {severity} CVEs in {year} ({count} total)")
            print("=" * 80)
            
            if severity in cve_details:
                cves = cve_details[severity]
                print(f"{'CVE':<15} {'Public Date':<12} {'Product(Component)':<40} {'Errata(Release Date)':<25}")
                print("-" * 92)
                
                for cve_info in cves:
                    cve = cve_info['cve']
                    public_date = cve_info['public_date']
                    product = cve_info['product']
                    components = cve_info['components']
                    errata = cve_info['errata']
                    release_date = cve_info['release_date']
                    
                    # Format component - take first component if multiple
                    if components:
                        first_component = components.split(',')[0].strip()
                        product_component = f"{product}({first_component})"
                    else:
                        product_component = f"{product}(N/A)"
                    
                    # Truncate long product names
                    if len(product_component) > 38:
                        product_component = product_component[:35] + "..."
                    
                    errata_release = f"{errata}({release_date})"
                    
                    print(f"{cve:<15} {public_date:<12} {product_component:<40} {errata_release:<25}")
            else:
                print("No CVEs with errata fixes found for this severity level.")

def main():
    parser = argparse.ArgumentParser(
        description="Generate VEX database statistics for a specific year including CVE severity breakdowns, errata statistics, and top CWEs",
        epilog="""
Examples:
  %(prog)s --year 2024                          # Generate statistics for 2024
  %(prog)s --year 2023 --database custom.db    # Use custom database file
  %(prog)s --year 2022 --debug                  # Show detailed CVE listings for each severity
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--year', '-y',
        type=int,
        required=True,
        help='Year to generate statistics for (e.g., 2024)'
    )
    
    parser.add_argument(
        '--database', '-d',
        default='vex.db',
        help='Path to VEX database file (default: vex.db)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Show detailed CVE listings for each severity level'
    )
    
    args = parser.parse_args()

    # Validate year
    if args.year < 1999 or args.year > 2030:
        print(f"❌ Invalid year: {args.year}. Please use a reasonable year (1999-2030)")
        sys.exit(1)
    
    # Connect to database
    conn = connect_to_database(args.database)
    
    try:
        print(f"🗄️  Database: {args.database}")
        print(f"📅 Generating statistics for year: {args.year}")
        
        # Get days of risk statistics
        risk_stats = get_days_of_risk_stats(conn, args.year)
        
        # 1. CVEs affecting products (with days of risk)
        product_severity_counts, product_total = get_cves_affecting_products(conn, args.year)
        format_severity_table(
            product_severity_counts, 
            f"CVEs Discovered in {args.year} That Affected Products",
            risk_stats
        )
        
        # 2. CVEs NOT affecting products (no risk stats since they don't have errata)
        no_product_severity_counts, no_product_total = get_cves_not_affecting_products(conn, args.year)
        format_severity_table(
            no_product_severity_counts, 
            f"CVEs Discovered in {args.year} That Did NOT Affect Products"
        )
        
        # 3. Errata statistics
        errata_severity_counts, errata_total = get_errata_statistics(conn, args.year)
        format_severity_table(
            errata_severity_counts, 
            f"Errata Released in {args.year} (Aggregated by Highest Severity)"
        )
        
        # 4. Top 10 CWEs
        top_cwes = get_top_cwes(conn, args.year, 10)
        format_cwe_table(
            top_cwes,
            f"Top 10 CWEs (Common Weakness Enumerations) in {args.year}"
        )
        
        # Debug output - detailed CVE listings
        if args.debug:
            cve_details = get_cve_details_by_severity(conn, args.year)
            format_cve_debug_output(cve_details, product_severity_counts, args.year)
        
        # Summary
        total_cves = product_total + no_product_total
        unique_cwes = get_total_unique_cwes_count(conn, args.year)
        total_fixed_cves = sum(stats['count'] for stats in risk_stats.values())
        
        print(f"\n📈 Summary for {args.year}")
        print("=" * 40)
        print(f"Total CVEs discovered:           {total_cves:>6}")
        print(f"  - Affecting products:          {product_total:>6}")
        print(f"  - Not affecting products:      {no_product_total:>6}")
        print(f"CVEs fixed with errata:          {total_fixed_cves:>6}")
        print(f"Total errata released:           {errata_total:>6}")
        print(f"Unique CWEs identified:          {unique_cwes:>6}")
        
        if risk_stats:
            all_days = []
            for stats in risk_stats.values():
                # We need to reconstruct the days list to calculate overall stats
                # For now, we'll show the range across all severities
                all_days.extend([stats['min'], stats['max']])
            
            if all_days:
                overall_min = min(stats['min'] for stats in risk_stats.values())
                overall_max = max(stats['max'] for stats in risk_stats.values())
                print(f"Days of risk range:              {overall_min:>3}-{overall_max} days")
        
            
    except sqlite3.Error as e:
        print(f"❌ Database query error: {e}")
        sys.exit(1)
    finally:
        conn.close()

if __name__ == "__main__":
    main() 