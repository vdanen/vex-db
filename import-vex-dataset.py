#!/usr/bin/env python

from vex import Vex, VexPackages
import json
import datetime
import argparse
import os
from pathlib import Path
import pandas as pd
from datasets import Dataset, DatasetDict, load_dataset
from huggingface_hub import HfApi, login, repo_exists
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def process_vex_data(vex_obj, packages):
    """Process VEX data and return structured data for both CVE and affects tables"""
    
    # Extract CVE information
    cve_id = vex_obj.cve
    
    # Get CVSS score and metrics from global_cvss
    cvss_score = None
    cvss_metrics = None
    if hasattr(vex_obj, 'global_cvss') and vex_obj.global_cvss:
        cvss_score = float(vex_obj.global_cvss.baseScore)
        cvss_metrics = vex_obj.global_cvss.vectorString
    
    # Get severity
    severity = vex_obj.global_impact if hasattr(vex_obj, 'global_impact') else None
    
    # Get dates
    public_date = vex_obj.release_date if hasattr(vex_obj, 'release_date') else None
    updated_date = vex_obj.updated if hasattr(vex_obj, 'updated') else None
    
    # Get description from notes
    description = None
    statement = None
    mitigation = None
    if hasattr(vex_obj, 'notes') and vex_obj.notes:
        if 'description' in vex_obj.notes:
            desc_dict = vex_obj.notes['description']
            # Get the first description value
            description = list(desc_dict.values())[0] if desc_dict else None
        
        if 'summary' in vex_obj.notes:
            summary_dict = vex_obj.notes['summary'] 
            # Use summary if no description
            if not description and summary_dict:
                description = list(summary_dict.values())[0]
    
    # Use VEX object statement if available
    if hasattr(vex_obj, 'statement') and vex_obj.statement:
        statement = vex_obj.statement
    
    if hasattr(packages, 'mitigation') and packages.mitigation:
        for x in packages.mitigation:
            mitigation = x.details
    
    # Create CVE record
    cve_record = {
        'cve': cve_id,
        'cvss_score': cvss_score,
        'cvss_metrics': cvss_metrics,
        'severity': severity,
        'public_date': public_date,
        'updated_date': updated_date,
        'description': description,
        'mitigation': mitigation,
        'statement': statement
    }
    
    # Process affects records
    affects_records = []
    
    # Handle fixes
    if hasattr(packages, 'fixes') and packages.fixes:
        for fix in packages.fixes:
            affects_record = {
                'cve': cve_id,
                'product': fix.product,
                'cpe': fix.cpe,
                'purl': fix.purl,
                'errata': fix.id,
                'release_date': fix.date,
                'state': 'fixed',
                'reason': None,
                'components': ','.join(fix.components) if fix.components else None
            }
            affects_records.append(affects_record)

    # Handle wontfix
    if hasattr(packages, 'wontfix') and packages.wontfix:
        for wontfix in packages.wontfix:
            affects_record = {
                'cve': cve_id,
                'product': wontfix.product,
                'cpe': wontfix.cpe,
                'purl': wontfix.purl,
                'errata': None,
                'release_date': None,
                'state': 'wontfix',
                'reason': wontfix.reason,
                'components': wontfix.component
            }
            affects_records.append(affects_record)

    # Handle not_affected
    if hasattr(packages, 'not_affected') and packages.not_affected:
        for not_affected in packages.not_affected:
            affects_record = {
                'cve': cve_id,
                'product': not_affected.product,
                'cpe': not_affected.cpe,
                'purl': not_affected.purl,
                'errata': None,
                'release_date': None,
                'state': 'not_affected',
                'reason': None,
                'components': ','.join(not_affected.components) if not_affected.components else None
            }
            affects_records.append(affects_record)

    # Handle affected
    if hasattr(packages, 'affected') and packages.affected:
        for affected in packages.affected:
            affects_record = {
                'cve': cve_id,
                'product': affected.product,
                'cpe': affected.cpe,
                'purl': affected.purl,
                'errata': None,
                'release_date': None,
                'state': 'affected',
                'reason': None,
                'components': ','.join(affected.components) if affected.components else None
            }
            affects_records.append(affects_record)
    
    return cve_record, affects_records


def process_vex_file(file_path):
    """Process a single VEX file and return structured data"""
    try:
        logger.info(f"Processing VEX file: {file_path}")
        
        with open(file_path, 'r') as f:
            data = json.load(f)
            vex = Vex(data)
            packages = VexPackages(vex.raw)
        
        logger.info(f"  Parsed VEX data for CVE: {vex.cve}")
        
        # Process the data
        cve_record, affects_records = process_vex_data(vex, packages)
        
        return cve_record, affects_records
        
    except Exception as e:
        logger.error(f"Error processing file {file_path}: {e}")
        return None, None


def find_vex_files(path):
    """Find all VEX files in a directory (recursively)"""
    vex_files = []
    path_obj = Path(path)
    
    if path_obj.is_file():
        if path_obj.suffix.lower() == '.json':
            return [str(path_obj)]
        else:
            logger.warning(f"{path} is not a JSON file")
            return []
    
    elif path_obj.is_dir():
        # Recursively find all .json files
        json_files = list(path_obj.rglob('*.json'))
        
        # Filter for files that look like VEX files (optional - could check content)
        for json_file in json_files:
            vex_files.append(str(json_file))
        
        logger.info(f"Found {len(vex_files)} JSON files in {path}")
        return vex_files
    
    else:
        logger.error(f"{path} does not exist or is not accessible")
        return []


def load_existing_dataset(repo_id, token=None):
    """Load existing datasets from HuggingFace Hub if they exist"""
    try:
        # Login if token provided
        if token:
            login(token=token)
        
        # Check for separate CVE and affects repositories
        cve_repo_id = f"{repo_id}-cve"
        affects_repo_id = f"{repo_id}-affects"
        
        cve_dataset = None
        affects_dataset = None
        
        # Try to load CVE dataset
        if repo_exists(cve_repo_id, repo_type="dataset"):
            logger.info(f"Loading existing CVE dataset: {cve_repo_id}")
            cve_dataset = load_dataset(cve_repo_id)
            logger.info(f"  Loaded CVE dataset with {len(cve_dataset['train'])} records")
        else:
            logger.info(f"CVE dataset {cve_repo_id} does not exist")
        
        # Try to load affects dataset
        if repo_exists(affects_repo_id, repo_type="dataset"):
            logger.info(f"Loading existing affects dataset: {affects_repo_id}")
            affects_dataset = load_dataset(affects_repo_id)
            logger.info(f"  Loaded affects dataset with {len(affects_dataset['train'])} records")
        else:
            logger.info(f"Affects dataset {affects_repo_id} does not exist")
        
        # If neither dataset exists, return None
        if cve_dataset is None and affects_dataset is None:
            logger.info(f"No existing datasets found - will create new ones")
            return None
        
        # Convert to our expected format (DatasetDict-like structure)
        existing_data = {}
        if cve_dataset is not None:
            existing_data['cve'] = cve_dataset['train']  # Default split is 'train'
        if affects_dataset is not None:
            existing_data['affects'] = affects_dataset['train']  # Default split is 'train'
        
        # Create a simple dict that mimics DatasetDict behavior
        class DatasetContainer:
            def __init__(self, data):
                self.data = data
            
            def __getitem__(self, key):
                return self.data.get(key)
            
            def get(self, key, default=None):
                return self.data.get(key, default)
        
        return DatasetContainer(existing_data)
        
    except Exception as e:
        logger.warning(f"Could not load existing datasets for {repo_id}: {e}")
        logger.info("Will create new datasets")
        return None


def merge_datasets(existing_dataset, new_cve_records, new_affects_records, update_mode='update'):
    """Merge new data with existing dataset"""
    
    if existing_dataset is None:
        # No existing dataset, just create new one
        logger.info("Creating new dataset from scratch")
        return create_dataset_from_records(new_cve_records, new_affects_records)
    
    logger.info(f"Merging data using mode: {update_mode}")
    
    # Convert existing data to pandas
    existing_cve_df = existing_dataset['cve'].to_pandas()
    existing_affects_df = existing_dataset['affects'].to_pandas()
    
    # Convert new data to pandas
    new_cve_df = pd.DataFrame(new_cve_records)
    new_affects_df = pd.DataFrame(new_affects_records)
    
    if update_mode == 'append':
        # Simple append - add all new records (may create duplicates)
        logger.info("Appending new records to existing dataset")
        merged_cve_df = pd.concat([existing_cve_df, new_cve_df], ignore_index=True)
        merged_affects_df = pd.concat([existing_affects_df, new_affects_df], ignore_index=True)
        
    elif update_mode == 'update':
        # Update existing records and add new ones
        logger.info("Updating existing records and adding new ones")
        
        # For CVE data: update existing CVEs or add new ones
        merged_cve_df = existing_cve_df.copy()
        for _, new_cve in new_cve_df.iterrows():
            cve_id = new_cve['cve']
            if cve_id in existing_cve_df['cve'].values:
                # Update existing CVE
                logger.debug(f"Updating existing CVE: {cve_id}")
                merged_cve_df.loc[merged_cve_df['cve'] == cve_id] = new_cve
            else:
                # Add new CVE
                logger.debug(f"Adding new CVE: {cve_id}")
                merged_cve_df = pd.concat([merged_cve_df, new_cve.to_frame().T], ignore_index=True)
        
        # For affects data: remove old entries for updated CVEs and add new ones
        updated_cves = new_cve_df['cve'].tolist()
        merged_affects_df = existing_affects_df[~existing_affects_df['cve'].isin(updated_cves)]
        merged_affects_df = pd.concat([merged_affects_df, new_affects_df], ignore_index=True)
        
    elif update_mode == 'replace':
        # Replace entire dataset with new data
        logger.info("Replacing entire dataset with new data")
        merged_cve_df = new_cve_df
        merged_affects_df = new_affects_df
    
    else:
        raise ValueError(f"Unknown update_mode: {update_mode}")
    
    # Remove duplicates
    logger.info("Removing duplicates...")
    initial_cve_count = len(merged_cve_df)
    initial_affects_count = len(merged_affects_df)
    
    merged_cve_df = merged_cve_df.drop_duplicates(subset=['cve'], keep='last')
    merged_affects_df = merged_affects_df.drop_duplicates(keep='last')
    
    logger.info(f"Removed {initial_cve_count - len(merged_cve_df)} duplicate CVE records")
    logger.info(f"Removed {initial_affects_count - len(merged_affects_df)} duplicate affects records")
    
    logger.info(f"Final merged dataset:")
    logger.info(f"  Total CVE records: {len(merged_cve_df)}")
    logger.info(f"  Total affects records: {len(merged_affects_df)}")
    
    # Convert back to HuggingFace datasets
    cve_dataset = Dataset.from_pandas(merged_cve_df)
    affects_dataset = Dataset.from_pandas(merged_affects_df)
    
    # Create a DatasetDict to maintain the relational structure
    dataset_dict = DatasetDict({
        'cve': cve_dataset,
        'affects': affects_dataset
    })
    
    return dataset_dict


def create_dataset_from_records(cve_records, affects_records):
    """Create HuggingFace datasets from processed records"""
    
    # Create DataFrames
    cve_df = pd.DataFrame(cve_records)
    affects_df = pd.DataFrame(affects_records)
    
    logger.info(f"Created CVE dataset with {len(cve_df)} records")
    logger.info(f"Created affects dataset with {len(affects_df)} records")
    
    # Convert to HuggingFace datasets
    cve_dataset = Dataset.from_pandas(cve_df)
    affects_dataset = Dataset.from_pandas(affects_df)
    
    # Create a DatasetDict to maintain the relational structure
    dataset_dict = DatasetDict({
        'cve': cve_dataset,
        'affects': affects_dataset
    })
    
    return dataset_dict


def upload_to_huggingface(dataset_dict, repo_id, token=None, private=False):
    """Upload dataset to HuggingFace Hub as separate CVE and affects datasets"""
    try:
        # Login if token provided
        if token:
            login(token=token)
        
        api = HfApi()
        
        # Create separate repository names for CVE and affects data
        cve_repo_id = f"{repo_id}-cve"
        affects_repo_id = f"{repo_id}-affects"
        
        success_count = 0
        
        # Upload CVE dataset
        logger.info(f"Uploading CVE dataset to: {cve_repo_id}")
        try:
            # Create repository if it doesn't exist
            if not repo_exists(cve_repo_id, repo_type="dataset"):
                api.create_repo(repo_id=cve_repo_id, repo_type="dataset", private=private)
                logger.info(f"Created new repository: {cve_repo_id}")
            else:
                logger.info(f"Repository {cve_repo_id} already exists - updating")
            
            # Upload CVE dataset  
            dataset_dict['cve'].push_to_hub(cve_repo_id, private=private)
            logger.info(f"✅ Successfully uploaded CVE data")
            success_count += 1
            
        except Exception as e:
            logger.error(f"❌ Error uploading CVE dataset: {e}")
        
        # Upload affects dataset
        logger.info(f"Uploading affects dataset to: {affects_repo_id}")
        try:
            # Create repository if it doesn't exist
            if not repo_exists(affects_repo_id, repo_type="dataset"):
                api.create_repo(repo_id=affects_repo_id, repo_type="dataset", private=private)
                logger.info(f"Created new repository: {affects_repo_id}")
            else:
                logger.info(f"Repository {affects_repo_id} already exists - updating")
            
            # Upload affects dataset
            dataset_dict['affects'].push_to_hub(affects_repo_id, private=private)
            logger.info(f"✅ Successfully uploaded affects data")
            success_count += 1
            
        except Exception as e:
            logger.error(f"❌ Error uploading affects dataset: {e}")
        
        if success_count == 2:
            logger.info(f"🎉 Successfully uploaded both datasets!")
            logger.info(f"🔗 CVE data: https://huggingface.co/datasets/{cve_repo_id}")
            logger.info(f"🔗 Affects data: https://huggingface.co/datasets/{affects_repo_id}")
            return True
        else:
            logger.error(f"❌ Only {success_count}/2 datasets uploaded successfully")
            return False
        
    except Exception as e:
        logger.error(f"Error uploading to HuggingFace: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Process VEX (Vulnerability Exploitability eXchange) data and upload to HuggingFace',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s cve-2022-48632.json --repo-id "myuser/vex-dataset"
  %(prog)s /path/to/vex/directory --repo-id "myuser/vex-dataset" --private
  %(prog)s /path/to/vex/directory --repo-id "myuser/vex-dataset" --update-mode update
  %(prog)s /path/to/vex/directory --repo-id "myuser/vex-dataset" --token "hf_..."
        """
    )
    
    parser.add_argument(
        'path',
        help='Path to VEX file or directory containing VEX files'
    )
    
    parser.add_argument(
        '--repo-id',
        required=True,
        help='HuggingFace repository ID (e.g., "username/dataset-name")'
    )
    
    parser.add_argument(
        '--token',
        help='HuggingFace API token (or use "huggingface-cli login")'
    )
    
    parser.add_argument(
        '--private',
        action='store_true',
        help='Make the dataset private (default: public)'
    )
    
    parser.add_argument(
        '--update-mode',
        choices=['update', 'append', 'replace'],
        default='update',
        help='How to handle existing dataset: update (default), append, or replace'
    )
    
    parser.add_argument(
        '--recursive', 
        action='store_true', 
        default=True,
        help='Recursively search directories for VEX files (default: True)'
    )
    
    parser.add_argument(
        '--no-recursive',
        dest='recursive',
        action='store_false',
        help='Only process files in the specified directory, not subdirectories'
    )
    
    parser.add_argument(
        '--continue-on-error',
        action='store_true',
        default=True,
        help='Continue processing other files if one fails (default: True)'
    )
    
    parser.add_argument(
        '--save-local',
        help='Save dataset locally to this directory before uploading'
    )
    
    args = parser.parse_args()
    
    # Find VEX files to process
    if not args.recursive and os.path.isdir(args.path):
        # Non-recursive: only direct files in directory
        path_obj = Path(args.path)
        vex_files = [str(f) for f in path_obj.glob('*.json')]
        logger.info(f"Found {len(vex_files)} JSON files in {args.path} (non-recursive)")
    else:
        # Recursive or single file
        vex_files = find_vex_files(args.path)
    
    if not vex_files:
        logger.error("No VEX files found to process.")
        return
    
    # Load existing dataset if it exists
    existing_dataset = load_existing_dataset(args.repo_id, args.token)
    
    # Process files
    cve_records = []
    affects_records = []
    successful_imports = 0
    failed_imports = 0
    
    logger.info(f"Starting processing of {len(vex_files)} file(s)...")
    logger.info("=" * 60)
    
    for i, vex_file in enumerate(vex_files, 1):
        logger.info(f"[{i}/{len(vex_files)}] Processing: {os.path.basename(vex_file)}")
        
        cve_record, file_affects_records = process_vex_file(vex_file)
        
        if cve_record is not None:
            cve_records.append(cve_record)
            affects_records.extend(file_affects_records)
            successful_imports += 1
        else:
            failed_imports += 1
            if not args.continue_on_error:
                logger.error(f"Stopping due to error in {vex_file}")
                break
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("PROCESSING SUMMARY:")
    logger.info(f"  Total files processed: {successful_imports + failed_imports}")
    logger.info(f"  Successful imports: {successful_imports}")
    logger.info(f"  Failed imports: {failed_imports}")
    logger.info(f"  New CVE records: {len(cve_records)}")
    logger.info(f"  New affects records: {len(affects_records)}")
    
    if successful_imports == 0:
        logger.error("No data to upload")
        return
    
    # Merge with existing dataset
    logger.info("Creating/updating HuggingFace dataset...")
    dataset_dict = merge_datasets(existing_dataset, cve_records, affects_records, args.update_mode)
    
    # Save locally if requested
    if args.save_local:
        logger.info(f"Saving dataset locally to {args.save_local}")
        dataset_dict.save_to_disk(args.save_local)
    
    # Upload to HuggingFace
    logger.info("Uploading to HuggingFace...")
    success = upload_to_huggingface(
        dataset_dict, 
        args.repo_id, 
        token=args.token, 
        private=args.private
    )
    
    if success:
        if existing_dataset is not None:
            logger.info(f"✅ Successfully updated datasets on HuggingFace!")
        else:
            logger.info(f"✅ Successfully created new datasets on HuggingFace!")
        
        # Print usage example
        logger.info("\n" + "=" * 60)
        logger.info("USAGE EXAMPLE:")
        logger.info("from datasets import load_dataset")
        logger.info(f"# Load CVE data")
        logger.info(f"cve_dataset = load_dataset('{args.repo_id}-cve')")
        logger.info(f"cve_data = cve_dataset['train']")
        logger.info(f"# Load affects data")  
        logger.info(f"affects_dataset = load_dataset('{args.repo_id}-affects')")
        logger.info(f"affects_data = affects_dataset['train']")
        logger.info("# Query specific CVE")
        logger.info("cve_info = cve_data.filter(lambda x: x['cve'] == 'CVE-2022-48632')")
        logger.info("# Get all affects for a CVE")
        logger.info("affects_info = affects_data.filter(lambda x: x['cve'] == 'CVE-2022-48632')")
    else:
        logger.error("❌ Failed to upload datasets to HuggingFace")


if __name__ == "__main__":
    main() 