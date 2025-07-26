#!/usr/bin/env python
"""
Example script demonstrating how to use VEX datasets uploaded to HuggingFace Hub.

This script shows various ways to query, analyze, and use VEX vulnerability data
for AI/ML applications, security analysis, and reporting.
"""

from datasets import load_dataset
import pandas as pd
import json
from collections import Counter
import argparse

def load_vex_dataset(repo_id):
    """Load VEX datasets from HuggingFace Hub (separate CVE and affects repositories)"""
    print(f"Loading datasets for: {repo_id}")
    
    cve_repo_id = f"{repo_id}-cve"
    affects_repo_id = f"{repo_id}-affects"
    
    try:
        # Load CVE dataset
        print(f"Loading CVE data from: {cve_repo_id}")
        cve_dataset = load_dataset(cve_repo_id)
        cve_data = cve_dataset['train']
        print(f"✅ Loaded CVE dataset with {len(cve_data)} records")
        
        # Load affects dataset
        print(f"Loading affects data from: {affects_repo_id}")
        affects_dataset = load_dataset(affects_repo_id)
        affects_data = affects_dataset['train']
        print(f"✅ Loaded affects dataset with {len(affects_data)} records")
        
        # Create a simple container to mimic the old DatasetDict structure
        class VexDataset:
            def __init__(self, cve_data, affects_data):
                self.data = {
                    'cve': cve_data,
                    'affects': affects_data
                }
            
            def __getitem__(self, key):
                return self.data[key]
        
        return VexDataset(cve_data, affects_data)
        
    except Exception as e:
        print(f"❌ Error loading datasets: {e}")
        print(f"Make sure both {cve_repo_id} and {affects_repo_id} exist")
        return None

def basic_dataset_info(dataset):
    """Display basic information about the dataset"""
    print("\n" + "="*60)
    print("DATASET OVERVIEW")
    print("="*60)
    
    cve_data = dataset['cve']
    affects_data = dataset['affects']
    
    print(f"Total CVEs: {len(cve_data)}")
    print(f"Total product relationships: {len(affects_data)}")
    
    # CVE columns
    print(f"\nCVE dataset columns: {cve_data.column_names}")
    print(f"Affects dataset columns: {affects_data.column_names}")
    
    # Convert to pandas for analysis
    cve_df = cve_data.to_pandas()
    affects_df = affects_data.to_pandas()
    
    # Severity distribution
    print(f"\nSeverity distribution:")
    severity_counts = cve_df['severity'].value_counts()
    for severity, count in severity_counts.items():
        print(f"  {severity}: {count}")
    
    # State distribution
    print(f"\nProduct state distribution:")
    state_counts = affects_df['state'].value_counts()
    for state, count in state_counts.items():
        print(f"  {state}: {count}")
    
    # CVSS score statistics
    cvss_scores = cve_df['cvss_score'].dropna()
    if len(cvss_scores) > 0:
        print(f"\nCVSS Score statistics:")
        print(f"  Mean: {cvss_scores.mean():.2f}")
        print(f"  Median: {cvss_scores.median():.2f}")
        print(f"  Min: {cvss_scores.min():.2f}")
        print(f"  Max: {cvss_scores.max():.2f}")

def query_specific_cve(dataset, cve_id):
    """Query information for a specific CVE"""
    print(f"\n" + "="*60)
    print(f"CVE DETAILS: {cve_id}")
    print("="*60)
    
    # Get CVE information
    cve_info = dataset['cve'].filter(lambda x: x['cve'] == cve_id)
    if len(cve_info) == 0:
        print(f"❌ CVE {cve_id} not found in dataset")
        return
    
    cve_record = cve_info[0]
    print(f"CVE: {cve_record['cve']}")
    print(f"CVSS Score: {cve_record['cvss_score']}")
    print(f"Severity: {cve_record['severity']}")
    print(f"Public Date: {cve_record['public_date']}")
    print(f"Description: {cve_record['description'][:200]}...")
    
    # Get affected products
    affected_products = dataset['affects'].filter(lambda x: x['cve'] == cve_id)
    print(f"\nAffected Products ({len(affected_products)}):")
    
    # Group by state
    affects_df = affected_products.to_pandas()
    for state in affects_df['state'].unique():
        state_products = affects_df[affects_df['state'] == state]
        print(f"\n  {state.upper()} ({len(state_products)}):")
        for _, product in state_products.iterrows():
            print(f"    • {product['product']}")
            if product['components']:
                print(f"      Components: {product['components']}")
            if product['errata']:
                print(f"      Errata: {product['errata']}")

def analyze_high_severity_cves(dataset):
    """Analyze high severity CVEs"""
    print(f"\n" + "="*60)
    print("HIGH SEVERITY CVE ANALYSIS")
    print("="*60)
    
    # Filter high severity CVEs
    high_severity = dataset['cve'].filter(lambda x: x['severity'] in ['High', 'Critical'])
    print(f"High/Critical severity CVEs: {len(high_severity)}")
    
    if len(high_severity) == 0:
        print("No high/critical severity CVEs found")
        return
    
    # Convert to pandas for analysis
    high_df = high_severity.to_pandas()
    
    # Top CVEs by CVSS score
    top_cvss = high_df.nlargest(5, 'cvss_score')
    print(f"\nTop 5 CVEs by CVSS score:")
    for _, cve in top_cvss.iterrows():
        print(f"  {cve['cve']}: {cve['cvss_score']} ({cve['severity']})")
    
    # Get affects data for high severity CVEs
    high_cve_ids = high_df['cve'].tolist()
    high_affects = dataset['affects'].filter(lambda x: x['cve'] in high_cve_ids)
    high_affects_df = high_affects.to_pandas()
    
    # Most affected products
    product_counts = high_affects_df['product'].value_counts().head(10)
    print(f"\nMost affected products (High/Critical CVEs):")
    for product, count in product_counts.items():
        print(f"  {product}: {count} CVEs")

def search_by_product(dataset, product_search):
    """Search for CVEs affecting a specific product"""
    print(f"\n" + "="*60)
    print(f"PRODUCT SEARCH: '{product_search}'")
    print("="*60)
    
    # Search in affects data
    matching_affects = dataset['affects'].filter(
        lambda x: product_search.lower() in x['product'].lower()
    )
    
    if len(matching_affects) == 0:
        print(f"No products found matching '{product_search}'")
        return
    
    # Get unique CVEs
    cve_ids = list(set([x['cve'] for x in matching_affects]))
    print(f"Found {len(cve_ids)} CVEs affecting products matching '{product_search}'")
    
    # Get CVE details
    matching_cves = dataset['cve'].filter(lambda x: x['cve'] in cve_ids)
    cve_df = matching_cves.to_pandas()
    
    # Sort by CVSS score (descending)
    cve_df = cve_df.sort_values('cvss_score', ascending=False)
    
    print(f"\nTop 10 CVEs by CVSS score:")
    for _, cve in cve_df.head(10).iterrows():
        print(f"  {cve['cve']}: {cve['cvss_score']} ({cve['severity']}) - {cve['public_date']}")

def export_analysis_report(dataset, output_file):
    """Export comprehensive analysis report"""
    print(f"\n" + "="*60)
    print("GENERATING ANALYSIS REPORT")
    print("="*60)
    
    cve_df = dataset['cve'].to_pandas()
    affects_df = dataset['affects'].to_pandas()
    
    # Merge data for comprehensive analysis
    merged_df = pd.merge(cve_df, affects_df, on='cve', how='inner')
    
    # Handle date range calculation safely
    public_dates = cve_df['public_date'].dropna()
    if len(public_dates) > 0:
        # Filter out any non-string values and convert to datetime for proper comparison
        valid_dates = public_dates[public_dates.astype(str).str.match(r'^\d{4}-\d{2}-\d{2}')]
        if len(valid_dates) > 0:
            date_range = {
                'earliest': str(valid_dates.min()),
                'latest': str(valid_dates.max())
            }
        else:
            date_range = {'earliest': None, 'latest': None}
    else:
        date_range = {'earliest': None, 'latest': None}
    
    report = {
        'summary': {
            'total_cves': len(cve_df),
            'total_product_relationships': len(affects_df),
            'unique_products': affects_df['product'].nunique(),
            'date_range': date_range
        },
        'severity_distribution': cve_df['severity'].value_counts().to_dict(),
        'state_distribution': affects_df['state'].value_counts().to_dict(),
        'cvss_statistics': {
            'mean': float(cve_df['cvss_score'].mean()) if cve_df['cvss_score'].notna().any() else None,
            'median': float(cve_df['cvss_score'].median()) if cve_df['cvss_score'].notna().any() else None,
            'min': float(cve_df['cvss_score'].min()) if cve_df['cvss_score'].notna().any() else None,
            'max': float(cve_df['cvss_score'].max()) if cve_df['cvss_score'].notna().any() else None
        },
        'top_affected_products': affects_df['product'].value_counts().head(20).to_dict(),
        'high_severity_cves': cve_df[cve_df['severity'].isin(['High', 'Critical'])]['cve'].tolist()
    }
    
    # Save report
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"✅ Analysis report saved to: {output_file}")
    print(f"   Report includes:")
    print(f"   • Dataset summary statistics")
    print(f"   • Severity and state distributions")
    print(f"   • CVSS score statistics")
    print(f"   • Top affected products")
    print(f"   • High severity CVE list")

def ai_ml_examples(dataset):
    """Show examples of how to use the dataset for AI/ML applications"""
    print(f"\n" + "="*60)
    print("AI/ML APPLICATION EXAMPLES")
    print("="*60)
    
    cve_df = dataset['cve'].to_pandas()
    
    print("1. Text Analysis of Vulnerability Descriptions:")
    descriptions = cve_df['description'].dropna()
    if len(descriptions) > 0:
        # Simple keyword analysis
        all_text = ' '.join(descriptions).lower()
        common_words = ['buffer', 'overflow', 'injection', 'authentication', 'privilege', 'escalation']
        word_counts = {word: all_text.count(word) for word in common_words}
        print("   Common vulnerability keywords:")
        for word, count in sorted(word_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"     {word}: {count} occurrences")
    
    print(f"\n2. Classification Data Preparation:")
    print("   # Prepare data for severity classification")
    print("   X = cve_df['description'].fillna('')")
    print("   y = cve_df['severity']")
    print("   # Use with scikit-learn, transformers, etc.")
    
    print(f"\n3. Time Series Analysis:")
    print("   # Analyze vulnerability trends over time")
    print("   cve_df['public_date'] = pd.to_datetime(cve_df['public_date'])")
    print("   monthly_counts = cve_df.groupby(cve_df['public_date'].dt.to_period('M')).size()")
    
    print(f"\n4. Product Risk Assessment:")
    affects_df = dataset['affects'].to_pandas()
    print("   # Calculate risk scores per product")
    print("   merged = pd.merge(cve_df, affects_df, on='cve')")
    print("   risk_scores = merged.groupby('product')['cvss_score'].agg(['mean', 'count', 'max'])")

def dataset_version_info(dataset):
    """Show dataset versioning and update information"""
    print(f"\n" + "="*60)
    print("DATASET VERSION INFO")
    print("="*60)
    
    cve_df = dataset['cve'].to_pandas()
    
    # Analyze update dates
    update_dates = pd.to_datetime(cve_df['updated_date'], errors='coerce').dropna()
    if len(update_dates) > 0:
        print(f"Dataset freshness:")
        print(f"  Latest update: {update_dates.max().strftime('%Y-%m-%d')}")
        print(f"  Oldest update: {update_dates.min().strftime('%Y-%m-%d')}")
        print(f"  Records with update info: {len(update_dates)}/{len(cve_df)}")
    
    # Analyze publication dates
    pub_dates = pd.to_datetime(cve_df['public_date'], errors='coerce').dropna()
    if len(pub_dates) > 0:
        print(f"\nCVE date range:")
        print(f"  Newest CVE: {pub_dates.max().strftime('%Y-%m-%d')}")
        print(f"  Oldest CVE: {pub_dates.min().strftime('%Y-%m-%d')}")
        
        # CVEs by year
        yearly_counts = pub_dates.dt.year.value_counts().sort_index()
        print(f"\nCVEs by year:")
        for year, count in yearly_counts.tail(5).items():
            print(f"  {year}: {count} CVEs")
    
    # Check for recent additions (CVEs from last 30 days)
    if len(pub_dates) > 0:
        recent_threshold = pd.Timestamp.now() - pd.Timedelta(days=30)
        recent_cves = pub_dates[pub_dates > recent_threshold]
        print(f"\nRecent CVEs (last 30 days): {len(recent_cves)}")

def main():
    parser = argparse.ArgumentParser(
        description='Example usage of VEX datasets from HuggingFace Hub',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --repo-id "username/vex-dataset"
  %(prog)s --repo-id "username/vex-dataset" --cve CVE-2022-48632
  %(prog)s --repo-id "username/vex-dataset" --product "Red Hat"
  %(prog)s --repo-id "username/vex-dataset" --export-report analysis.json
        """
    )
    
    parser.add_argument(
        '--repo-id',
        required=True,
        help='HuggingFace dataset repository ID (e.g., "username/vex-dataset")'
    )
    
    parser.add_argument(
        '--cve',
        help='Query specific CVE (e.g., CVE-2022-48632)'
    )
    
    parser.add_argument(
        '--product',
        help='Search for products containing this term'
    )
    
    parser.add_argument(
        '--show-version-info',
        action='store_true',
        help='Show dataset version and update information'
    )
    
    parser.add_argument(
        '--export-report',
        help='Export analysis report to JSON file'
    )
    
    parser.add_argument(
        '--ai-examples',
        action='store_true',
        help='Show AI/ML application examples'
    )
    
    args = parser.parse_args()
    
    # Load dataset
    dataset = load_vex_dataset(args.repo_id)
    if dataset is None:
        return
    
    # Basic dataset information
    basic_dataset_info(dataset)
    
    # Version information
    if args.show_version_info:
        dataset_version_info(dataset)
    
    # Specific queries based on arguments
    if args.cve:
        query_specific_cve(dataset, args.cve)
    
    if args.product:
        search_by_product(dataset, args.product)
    
    # Analysis
    analyze_high_severity_cves(dataset)
    
    if args.ai_examples:
        ai_ml_examples(dataset)
    
    if args.export_report:
        export_analysis_report(dataset, args.export_report)

if __name__ == "__main__":
    main() 