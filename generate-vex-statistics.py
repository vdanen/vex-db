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


def get_days_of_risk_stats(conn, year, product=None, cpe=None):
    """Calculate days of risk statistics for each severity level (excluding CVEs marked as only 'not_affected')"""
    # Build WHERE conditions for product/CPE filtering
    where_conditions = ["c.public_date LIKE ?"]
    where_conditions.extend([
        "c.public_date IS NOT NULL",
        "a.release_date IS NOT NULL", 
        "a.errata IS NOT NULL",
        "a.errata != ''"
    ])
    params = [f"{year}%"]
    
    if product:
        where_conditions.append("a.product LIKE ?")
        params.append(f"%{product}%")
    
    if cpe:
        where_conditions.append("a.cpe LIKE ?")
        params.append(f"%{cpe}%")
    
    # Get all fixed CVEs
    query = f"""
    SELECT c.cve, c.public_date, c.severity, a.release_date
    FROM cve c
    INNER JOIN affects a ON c.cve = a.cve
    WHERE {' AND '.join(where_conditions)}
    ORDER BY c.cve, a.release_date
    """

    # Build WHERE conditions for not_affected query
    not_affected_where = ["c.public_date LIKE ?", "a.product IS NOT NULL", "a.product != ''"]
    not_affected_params = [f"{year}%"]
    
    if product:
        not_affected_where.append("a.product LIKE ?")
        not_affected_params.append(f"%{product}%")
    
    if cpe:
        not_affected_where.append("a.cpe LIKE ?")
        not_affected_params.append(f"%{cpe}%")

    # Get CVEs that are only 'not_affected'
    query_only_not_affected = f"""
    SELECT c.cve
    FROM cve c
    INNER JOIN affects a ON c.cve = a.cve
    WHERE {' AND '.join(not_affected_where)}
    GROUP BY c.cve
    HAVING COUNT(*) = COUNT(CASE WHEN a.state = 'not_affected' THEN 1 END)
    AND COUNT(CASE WHEN a.state = 'not_affected' THEN 1 END) > 0
    """

    cursor = conn.cursor()
    cursor.execute(query, params)
    all_results = cursor.fetchall()

    # Get CVEs that are only 'not_affected'
    cursor.execute(query_only_not_affected, not_affected_params)
    only_not_affected = {row['cve'] for row in cursor.fetchall()}

    # Filter out CVEs that are only 'not_affected'
    results = [row for row in all_results if row['cve'] not in only_not_affected]

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


def get_cves_affecting_products(conn, year, product=None, cpe=None):
    """Get CVEs from a specific year that actually affect products (excluding those marked as only 'not_affected'), grouped by severity"""
    # Build WHERE conditions for product/CPE filtering
    where_conditions = ["c.public_date LIKE ?", "a.product IS NOT NULL", "a.product != ''"]
    params = [f"{year}%"]
    
    if product:
        where_conditions.append("a.product LIKE ?")
        params.append(f"%{product}%")
    
    if cpe:
        where_conditions.append("a.cpe LIKE ?")
        params.append(f"%{cpe}%")

    # First, get all CVEs that have affects data
    query_all = f"""
    SELECT DISTINCT c.cve, c.severity
    FROM cve c
    INNER JOIN affects a ON c.cve = a.cve
    WHERE {' AND '.join(where_conditions)}
    """

    # Then find CVEs that are marked as ONLY 'not_affected' across all products
    query_only_not_affected = f"""
    SELECT c.cve
    FROM cve c
    INNER JOIN affects a ON c.cve = a.cve
    WHERE {' AND '.join(where_conditions)}
    GROUP BY c.cve
    HAVING COUNT(*) = COUNT(CASE WHEN a.state = 'not_affected' THEN 1 END)
    AND COUNT(CASE WHEN a.state = 'not_affected' THEN 1 END) > 0
    """

    cursor = conn.cursor()

    # Get all CVEs
    cursor.execute(query_all, params)
    all_results = cursor.fetchall()

    # Get CVEs that are only 'not_affected'
    cursor.execute(query_only_not_affected, params)
    only_not_affected = {row['cve'] for row in cursor.fetchall()}

    # Filter out CVEs that are only 'not_affected'
    filtered_results = [row for row in all_results if row['cve'] not in only_not_affected]

    severity_counts = defaultdict(int)
    for row in filtered_results:
        severity = row['severity'] or 'Unknown'
        severity_counts[severity] += 1

    return dict(severity_counts), len(filtered_results)


def get_cves_not_affecting_products(conn, year, product=None, cpe=None):
    """Get CVEs from a specific year that are marked as only 'not_affected' for the specified product/CPE, grouped by severity"""
    # Build WHERE conditions for product/CPE filtering
    where_conditions = ["c.public_date LIKE ?", "a.product IS NOT NULL", "a.product != ''"]
    params = [f"{year}%"]
    
    if product:
        where_conditions.append("a.product LIKE ?")
        params.append(f"%{product}%")
    
    if cpe:
        where_conditions.append("a.cpe LIKE ?")
        params.append(f"%{cpe}%")

    # Get CVEs that are marked as ONLY 'not_affected' across all matching records
    query = f"""
    SELECT c.cve, c.severity
    FROM cve c
    INNER JOIN affects a ON c.cve = a.cve
    WHERE {' AND '.join(where_conditions)}
    GROUP BY c.cve, c.severity
    HAVING COUNT(*) = COUNT(CASE WHEN a.state = 'not_affected' THEN 1 END)
    AND COUNT(CASE WHEN a.state = 'not_affected' THEN 1 END) > 0
    """

    cursor = conn.cursor()
    cursor.execute(query, params)
    results = cursor.fetchall()

    severity_counts = defaultdict(int)
    for row in results:
        severity = row['severity'] or 'Unknown'
        severity_counts[severity] += 1

    return dict(severity_counts), len(results)


def get_errata_statistics(conn, year, product=None, cpe=None):
    """Get errata released in a specific year, aggregated by highest severity"""
    # Build WHERE conditions for product/CPE filtering
    where_conditions = ["a.release_date LIKE ?", "a.errata IS NOT NULL", "a.errata != ''"]
    params = [f"%, {year}"]
    
    if product:
        where_conditions.append("a.product LIKE ?")
        params.append(f"%{product}%")
    
    if cpe:
        where_conditions.append("a.cpe LIKE ?")
        params.append(f"%{cpe}%")

    # Get all errata released in the specified year with their associated CVE severities
    # Note: release_date is in format "Month DD, YYYY", so we match the year at the end
    query = f"""
    SELECT DISTINCT a.errata, c.severity
    FROM affects a
    INNER JOIN cve c ON a.cve = c.cve
    WHERE {' AND '.join(where_conditions)}
    ORDER BY a.errata, c.severity
    """

    cursor = conn.cursor()
    cursor.execute(query, params)
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


def get_top_cwes(conn, year, limit=10, product=None, cpe=None):
    """Get the top CWEs for a specific year"""
    if product or cpe:
        # When filtering by product/CPE, we need to join with affects table
        where_conditions = ["c.public_date LIKE ?", "c.cwe IS NOT NULL", "c.cwe != ''"]
        params = [f"{year}%"]
        
        if product:
            where_conditions.append("a.product LIKE ?")
            params.append(f"%{product}%")
        
        if cpe:
            where_conditions.append("a.cpe LIKE ?")
            params.append(f"%{cpe}%")
        
        params.append(limit)
        
        query = f"""
        SELECT c.cwe, COUNT(DISTINCT c.cve) as count
        FROM cve c
        INNER JOIN affects a ON c.cve = a.cve
        WHERE {' AND '.join(where_conditions)}
        GROUP BY c.cwe
        ORDER BY count DESC, c.cwe ASC
        LIMIT ?
        """
    else:
        # Original query when no product/CPE filter
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
        params = [f"{year}%", limit]

    cursor = conn.cursor()
    cursor.execute(query, params)
    results = cursor.fetchall()

    return [(row['cwe'], row['count']) for row in results]


def get_total_unique_cwes_count(conn, year, product=None, cpe=None):
    """Get the total count of unique CWEs for a specific year"""
    if product or cpe:
        # When filtering by product/CPE, we need to join with affects table
        where_conditions = ["c.public_date LIKE ?", "c.cwe IS NOT NULL", "c.cwe != ''"]
        params = [f"{year}%"]
        
        if product:
            where_conditions.append("a.product LIKE ?")
            params.append(f"%{product}%")
        
        if cpe:
            where_conditions.append("a.cpe LIKE ?")
            params.append(f"%{cpe}%")
        
        query = f"""
        SELECT COUNT(DISTINCT c.cwe) as unique_cwe_count
        FROM cve c
        INNER JOIN affects a ON c.cve = a.cve
        WHERE {' AND '.join(where_conditions)}
        """
    else:
        # Original query when no product/CPE filter
        query = """
        SELECT COUNT(DISTINCT c.cwe) as unique_cwe_count
        FROM cve c
        WHERE c.public_date LIKE ?
        AND c.cwe IS NOT NULL
        AND c.cwe != ''
        """
        params = [f"{year}%"]

    cursor = conn.cursor()
    cursor.execute(query, params)
    result = cursor.fetchone()

    return result['unique_cwe_count'] if result else 0


def get_cve_details_by_severity(conn, year, product=None, cpe=None):
    """Get detailed CVE information for each severity level"""
    # Build WHERE conditions for product/CPE filtering
    where_conditions = ["c.public_date LIKE ?", "a.product IS NOT NULL", "a.product != ''"]
    params = [f"{year}%"]
    
    if product:
        where_conditions.append("a.product LIKE ?")
        params.append(f"%{product}%")
    
    if cpe:
        where_conditions.append("a.cpe LIKE ?")
        params.append(f"%{cpe}%")

    # First get all CVEs that have affects data
    query_all = f"""
    SELECT DISTINCT c.cve, c.public_date, c.severity
    FROM cve c
    INNER JOIN affects a ON c.cve = a.cve
    WHERE {' AND '.join(where_conditions)}
    """

    # Then get CVEs with errata (fixed CVEs)
    fixed_where_conditions = where_conditions + ["a.errata IS NOT NULL", "a.errata != ''"]
    query_fixed = f"""
    SELECT c.cve, c.public_date, c.severity, a.product, a.components,
           a.errata, a.release_date
    FROM cve c
    INNER JOIN affects a ON c.cve = a.cve
    WHERE {' AND '.join(fixed_where_conditions)}
    ORDER BY c.cve, a.release_date
    """

    # Get state information for all CVEs
    query_states = f"""
    SELECT c.cve, c.severity, a.state
    FROM cve c
    INNER JOIN affects a ON c.cve = a.cve
    WHERE {' AND '.join(where_conditions)}
    """

    # Get CVEs that are only 'not_affected'
    query_only_not_affected = f"""
    SELECT c.cve
    FROM cve c
    INNER JOIN affects a ON c.cve = a.cve
    WHERE {' AND '.join(where_conditions)}
    GROUP BY c.cve
    HAVING COUNT(*) = COUNT(CASE WHEN a.state = 'not_affected' THEN 1 END)
    AND COUNT(CASE WHEN a.state = 'not_affected' THEN 1 END) > 0
    """

    cursor = conn.cursor()

    # Get all CVEs that affect products
    cursor.execute(query_all, params)
    all_cves_raw = cursor.fetchall()

    # Get fixed CVEs with errata details
    cursor.execute(query_fixed, params)
    fixed_results_raw = cursor.fetchall()

    # Get state information
    cursor.execute(query_states, params)
    state_results_raw = cursor.fetchall()

    # Get CVEs that are only 'not_affected'
    cursor.execute(query_only_not_affected, params)
    only_not_affected = {row['cve'] for row in cursor.fetchall()}

    # Filter out CVEs that are only 'not_affected'
    all_cves = [row for row in all_cves_raw if row['cve'] not in only_not_affected]
    fixed_results = [row for row in fixed_results_raw if row['cve'] not in only_not_affected]
    state_results = [row for row in state_results_raw if row['cve'] not in only_not_affected]

    # Collect state information per CVE
    cve_states = defaultdict(set)
    for row in state_results:
        cve = row['cve']
        state = row['state']
        if state:
            cve_states[cve].add(state)

    # Initialize structure with all CVEs as unfixed
    cve_details = defaultdict(lambda: defaultdict(dict))

    for row in all_cves:
        cve = row['cve']
        severity = row['severity'] or 'Unknown'
        public_date = row['public_date']

        # Determine the status of this unfixed CVE
        states = cve_states.get(cve, set())
        if states == {'not_affected'}:
            cve_status = 'not_affected'
        elif 'affected' in states or 'wontfix' in states:
            cve_status = 'needs_attention'
        elif states:
            cve_status = 'mixed'
        else:
            cve_status = 'unknown'

        cve_details[severity][cve] = {
            'cve': cve,
            'public_date': public_date,
            'product': None,
            'components': None,
            'errata': None,
            'release_date': None,
            'fixed': False,
            'states': states,
            'cve_status': cve_status
        }

    # Update with fix information for fixed CVEs
    for row in fixed_results:
        cve = row['cve']
        severity = row['severity'] or 'Unknown'
        product = row['product']
        components = row['components']
        errata = row['errata']
        release_date = row['release_date']

        # Parse dates for comparison
        pub_date_obj = parse_public_date(row['public_date'])
        rel_date_obj = parse_release_date(release_date) if release_date else None

        if cve in cve_details[severity] and pub_date_obj and rel_date_obj:
            if not cve_details[severity][cve]['fixed']:
                # First fix found
                cve_details[severity][cve].update({
                    'product': product,
                    'components': components,
                    'errata': errata,
                    'release_date': release_date,
                    'release_date_obj': rel_date_obj,
                    'fixed': True
                })
            elif cve_details[severity][cve].get('release_date_obj'):
                # Check if this is a faster fix
                if rel_date_obj < cve_details[severity][cve]['release_date_obj']:
                    cve_details[severity][cve].update({
                        'product': product,
                        'components': components,
                        'errata': errata,
                        'release_date': release_date,
                        'release_date_obj': rel_date_obj
                    })

    # Convert to list format for easier processing, sorted by fixed status and CVE
    result = defaultdict(list)
    for severity, cves in cve_details.items():
        # Sort: fixed CVEs first, then unfixed, then by CVE name
        sorted_cves = sorted(cves.values(), key=lambda x: (not x['fixed'], x['cve']))
        result[severity] = sorted_cves

    return dict(result)


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
            print(f"\n🔍 {severity} CVEs in {year} That Actually Affect Products ({count} total)")
            print("=" * 100)

            if severity in cve_details:
                cves = cve_details[severity]

                # Separate fixed and unfixed CVEs
                fixed_cves = [cve for cve in cves if cve['fixed']]
                unfixed_cves = [cve for cve in cves if not cve['fixed']]

                # Show fixed CVEs first
                if fixed_cves:
                    print(f"\n  ✅ Fixed CVEs ({len(fixed_cves)} of {count}):")
                    print(f"  {'CVE':<15} {'Public Date':<12} {'Product(Component)':<40} {'Errata(Release Date)':<25}")
                    print("  " + "-" * 92)

                    for cve_info in fixed_cves:
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

                        print(f"  {cve:<15} {public_date:<12} {product_component:<40} {errata_release:<25}")

                # Show unfixed CVEs - categorize by status
                if unfixed_cves:
                    # Categorize unfixed CVEs
                    not_affected_cves = [cve for cve in unfixed_cves if cve['cve_status'] == 'not_affected']
                    needs_attention_cves = [cve for cve in unfixed_cves if cve['cve_status'] == 'needs_attention']
                    mixed_cves = [cve for cve in unfixed_cves if cve['cve_status'] == 'mixed']
                    unknown_cves = [cve for cve in unfixed_cves if cve['cve_status'] == 'unknown']

                    print(f"\n  ❌ Unfixed CVEs ({len(unfixed_cves)} of {count}):")

                    # Show not affected CVEs
                    if not_affected_cves:
                        print(f"\n    🟢 Not Affected ({len(not_affected_cves)}):")
                        print(f"    {'CVE':<15} {'Public Date':<12}")
                        print("    " + "-" * 27)
                        for cve_info in not_affected_cves:
                            cve = cve_info['cve']
                            public_date = cve_info['public_date']
                            print(f"    {cve:<15} {public_date:<12}")

                    # Show CVEs that need attention (affected/wontfix)
                    if needs_attention_cves:
                        print(f"\n    🔴 Need Attention - Affected/WontFix ({len(needs_attention_cves)}):")
                        print(f"    {'CVE':<15} {'Public Date':<12} {'States':<20}")
                        print("    " + "-" * 47)
                        for cve_info in needs_attention_cves:
                            cve = cve_info['cve']
                            public_date = cve_info['public_date']
                            states_str = ', '.join(sorted(cve_info['states']))
                            print(f"    {cve:<15} {public_date:<12} {states_str:<20}")

                    # Show mixed status CVEs
                    if mixed_cves:
                        print(f"\n    🟡 Mixed Status ({len(mixed_cves)}):")
                        print(f"    {'CVE':<15} {'Public Date':<12} {'States':<20}")
                        print("    " + "-" * 47)
                        for cve_info in mixed_cves:
                            cve = cve_info['cve']
                            public_date = cve_info['public_date']
                            states_str = ', '.join(sorted(cve_info['states']))
                            print(f"    {cve:<15} {public_date:<12} {states_str:<20}")

                    # Show unknown status CVEs
                    if unknown_cves:
                        print(f"\n    ❓ Unknown Status ({len(unknown_cves)}):")
                        print(f"    {'CVE':<15} {'Public Date':<12}")
                        print("    " + "-" * 27)
                        for cve_info in unknown_cves:
                            cve = cve_info['cve']
                            public_date = cve_info['public_date']
                            print(f"    {cve:<15} {public_date:<12}")

                if not fixed_cves and not unfixed_cves:
                    print("  No CVE data found for this severity level.")
            else:
                print("  No CVEs found for this severity level.")


def main():
    parser = argparse.ArgumentParser(
        description="Generate VEX database statistics for a specific year including CVE severity breakdowns, errata statistics, and top CWEs",
        epilog="""
Examples:
  %(prog)s --year 2024                                        # Generate statistics for 2024
  %(prog)s --year 2023 --database custom.db                  # Use custom database file
  %(prog)s --year 2022 --debug                                # Show detailed CVE listings for each severity
  %(prog)s --year 2024 --product "Red Hat Enterprise Linux"  # Filter by product name
  %(prog)s --year 2024 --cpe "cpe:/o:redhat:enterprise_linux" # Filter by CPE identifier
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

    parser.add_argument(
        '--product', '-p',
        help='Filter results by product name (supports partial matches)'
    )

    parser.add_argument(
        '--cpe',
        help='Filter results by CPE (supports partial matches)'
    )

    args = parser.parse_args()

    # Validate year
    if args.year < 1999 or args.year > 2030:
        print(f"❌ Invalid year: {args.year}. Please use a reasonable year (1999-2030)")
        sys.exit(1)

    # Validate that only one of --product or --cpe is used
    if args.product and args.cpe:
        print("❌ Error: Only one filter can be used at a time. You specified both --product and --cpe.")
        print("Please use only one of --product or --cpe.")
        sys.exit(1)

    # Connect to database
    conn = connect_to_database(args.database)

    try:
        print(f"🗄️  Database: {args.database}")
        print(f"📅 Generating statistics for year: {args.year}")
        
        # Show filtering criteria if specified
        filter_info = []
        if args.product:
            filter_info.append(f"product: '{args.product}'")
        if args.cpe:
            filter_info.append(f"CPE: '{args.cpe}'")
        
        if filter_info:
            print(f"🔍 Filtering by: {', '.join(filter_info)}")

        # Get days of risk statistics
        risk_stats = get_days_of_risk_stats(conn, args.year, args.product, args.cpe)

        # 1. CVEs affecting products (with days of risk)
        product_severity_counts, product_total = get_cves_affecting_products(conn, args.year, args.product, args.cpe)
        
        title_suffix = ""
        if args.product:
            title_suffix = f" (Product: {args.product})"
        elif args.cpe:
            title_suffix = f" (CPE: {args.cpe})"
            
        format_severity_table(
            product_severity_counts,
            f"CVEs Discovered in {args.year} That Actually Affect Products{title_suffix}",
            risk_stats
        )

        # 2. CVEs marked as not affecting products (no risk stats since they don't have errata)
        no_product_severity_counts, no_product_total = get_cves_not_affecting_products(conn, args.year, args.product, args.cpe)
        format_severity_table(
            no_product_severity_counts,
            f"CVEs Discovered in {args.year} Marked as NOT Affecting Products{title_suffix}"
        )

        # 3. Errata statistics
        errata_severity_counts, errata_total = get_errata_statistics(conn, args.year, args.product, args.cpe)
        format_severity_table(
            errata_severity_counts,
            f"Errata Released in {args.year} (Aggregated by Highest Severity){title_suffix}"
        )

        # 4. Top 10 CWEs
        top_cwes = get_top_cwes(conn, args.year, 10, args.product, args.cpe)
        format_cwe_table(
            top_cwes,
            f"Top 10 CWEs (Common Weakness Enumerations) in {args.year}{title_suffix}"
        )

        # Debug output - detailed CVE listings
        if args.debug:
            cve_details = get_cve_details_by_severity(conn, args.year, args.product, args.cpe)
            format_cve_debug_output(cve_details, product_severity_counts, args.year)

        # Summary
        total_cves = product_total + no_product_total
        unique_cwes = get_total_unique_cwes_count(conn, args.year, args.product, args.cpe)
        total_fixed_cves = sum(stats['count'] for stats in risk_stats.values())

        print(f"\n📈 Summary for {args.year}")
        print("=" * 40)
        print(f"Total CVEs discovered:           {total_cves:>6}")
        print(f"  - Actually affecting products: {product_total:>6}")
        print(f"  - Marked as not affecting:     {no_product_total:>6}")
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