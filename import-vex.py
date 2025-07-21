#!/usr/bin/env python

from vex import Vex, VexPackages
import json
import datetime
import argparse
import os
import glob
from pathlib import Path

# SQLAlchemy imports for database operations
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
import sqlite3

# Default database configuration
DEFAULT_DATABASE_URL = "sqlite:///vex.db"

# Global database objects - will be initialized in main()
engine = None
SessionLocal = None

def initialize_database(database_url=DEFAULT_DATABASE_URL):
    """Initialize database connection"""
    global engine, SessionLocal
    engine = create_engine(database_url)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def insert_vex_data(vex_obj, packages):
    """Insert VEX data into the database"""
    session = SessionLocal()
    
    try:
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
        
        # Insert CVE record
        cve_insert = text("""
            INSERT OR REPLACE INTO cve 
            (cve, cvss_score, cvss_metrics, severity, public_date, updated_date, description, mitigation, statement)
            VALUES (:cve, :cvss_score, :cvss_metrics, :severity, :public_date, :updated_date, :description, :mitigation, :statement)
        """)
        
        session.execute(cve_insert, {
            'cve': cve_id,
            'cvss_score': cvss_score,
            'cvss_metrics': cvss_metrics,
            'severity': severity,
            'public_date': public_date,
            'updated_date': updated_date,
            'description': description,
            'mitigation': mitigation,
            'statement': statement
        })
        
        # handle fixes first
        if hasattr(packages, 'fixes') and packages.fixes:
            for fix in packages.fixes:
                print(f'DEBUG: {fix}')
                status_type = 'fixed'

                affects_insert = text("""
                    INSERT INTO affects 
                    (cve, product, errata, release_date, state, components)
                    VALUES (:cve, :product, :errata, :release_date, :state, :components)
                """)
                
                session.execute(affects_insert, {
                    'cve': cve_id,
                    'product': fix.product,
                    'errata': fix.id,
                    'release_date': fix.date,
                    'state': 'fixed',
                    'components': ','.join(fix.components)
                })

        # handle known_affected next
        if hasattr(packages, 'wontfix') and packages.wontfix:
            for wontfix in packages.wontfix:
                print(f'DEBUG: {wontfix}')
                status_type = 'wontfix'

                affects_insert = text("""
                    INSERT INTO affects 
                    (cve, product, reason, state, components)
                    VALUES (:cve, :product, :reason, :state, :components)
                """)

                session.execute(affects_insert, {
                    'cve': cve_id,
                    'product': wontfix.product,
                    'reason': wontfix.reason,
                    'state': 'wontfix',
                    'components': wontfix.component
                })

        # handle not affected next
        if hasattr(packages, 'not_affected') and packages.not_affected:
            for not_affected in packages.not_affected:
                print(f'DEBUG: {not_affected}')
                status_type = 'not_affected'

                affects_insert = text("""
                    INSERT INTO affects 
                    (cve, product, state, components)
                    VALUES (:cve, :product, :state, :components)
                """)

                session.execute(affects_insert, {
                    'cve': cve_id,
                    'product': not_affected.product,
                    'state': 'not_affected',
                    'components': ','.join(not_affected.components)
                })

        # handle affected last
        if hasattr(packages, 'affected') and packages.affected:
            for affected in packages.affected:
                print(f'DEBUG: {affected}')
                status_type = 'affected'

                affects_insert = text("""
                    INSERT INTO affects 
                    (cve, product, state, components)
                    VALUES (:cve, :product, :state, :components)
                """)

                session.execute(affects_insert, {
                    'cve': cve_id,
                    'product': affected.product,
                    'state': 'affected',
                    'components': ','.join(affected.components)
                })
        
        # Commit the transaction
        session.commit()
        print(f"Successfully imported VEX data for {cve_id}")
        return True
        
    except Exception as e:
        session.rollback()
        print(f"Error importing VEX data: {e}")
        return False
    finally:
        session.close()

def process_vex_file(file_path):
    """Process a single VEX file"""
    try:
        print(f"Processing VEX file: {file_path}")
        
        with open(file_path, 'r') as f:
            data = json.load(f)
            vex = Vex(data)
            packages = VexPackages(vex.raw)
        
        print(f"  Parsed VEX data for CVE: {vex.cve}")
        print(f"  Severity: {vex.global_impact}")
        print(f"  Release Date: {vex.release_date}")
        print(f"  CVSS Score: {vex.global_cvss.baseScore if hasattr(vex, 'global_cvss') and vex.global_cvss else 'None'}")
        
        # Get description for display
        description = None
        if hasattr(vex, 'notes') and vex.notes and 'description' in vex.notes:
            desc_dict = vex.notes['description']
            description = list(desc_dict.values())[0] if desc_dict else None
        
        print(f"  Description: {description[:100] + '...' if description and len(description) > 100 else description}")
        
        # Insert the data into the database
        success = insert_vex_data(vex, packages)
        return success
        
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
        return False

def find_vex_files(path):
    """Find all VEX files in a directory (recursively)"""
    vex_files = []
    path_obj = Path(path)
    
    if path_obj.is_file():
        if path_obj.suffix.lower() == '.json':
            return [str(path_obj)]
        else:
            print(f"Warning: {path} is not a JSON file")
            return []
    
    elif path_obj.is_dir():
        # Recursively find all .json files
        json_files = list(path_obj.rglob('*.json'))
        
        # Filter for files that look like VEX files (optional - could check content)
        for json_file in json_files:
            vex_files.append(str(json_file))
        
        print(f"Found {len(vex_files)} JSON files in {path}")
        return vex_files
    
    else:
        print(f"Error: {path} does not exist or is not accessible")
        return []

def main():
    parser = argparse.ArgumentParser(
        description='Import VEX (Vulnerability Exploitability eXchange) data into database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s cve-2022-48632.json                    # Import single file
  %(prog)s /path/to/vex/directory                 # Import all JSON files in directory
  %(prog)s /path/to/vex/directory --recursive     # Import recursively (default)
  %(prog)s /path/to/vex/directory --no-recursive  # Import only direct files
        """
    )
    
    parser.add_argument(
        'path',
        help='Path to VEX file or directory containing VEX files'
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
        '--database-url',
        default=DEFAULT_DATABASE_URL,
        help=f'Database connection URL (default: {DEFAULT_DATABASE_URL})'
    )
    
    args = parser.parse_args()
    
    # Initialize database connection
    initialize_database(args.database_url)
    if args.database_url != DEFAULT_DATABASE_URL:
        print(f"Using database: {args.database_url}")
    
    # Find VEX files to process
    if not args.recursive and os.path.isdir(args.path):
        # Non-recursive: only direct files in directory
        path_obj = Path(args.path)
        vex_files = [str(f) for f in path_obj.glob('*.json')]
        print(f"Found {len(vex_files)} JSON files in {args.path} (non-recursive)")
    else:
        # Recursive or single file
        vex_files = find_vex_files(args.path)
    
    if not vex_files:
        print("No VEX files found to process.")
        return
    
    # Process files
    successful_imports = 0
    failed_imports = 0
    
    print(f"\nStarting import of {len(vex_files)} file(s)...")
    print("=" * 60)
    
    for i, vex_file in enumerate(vex_files, 1):
        print(f"\n[{i}/{len(vex_files)}] Processing: {os.path.basename(vex_file)}")
        
        success = process_vex_file(vex_file)
        
        if success:
            successful_imports += 1
        else:
            failed_imports += 1
            if not args.continue_on_error:
                print(f"Stopping due to error in {vex_file}")
                break
    
    # Summary
    print("\n" + "=" * 60)
    print("IMPORT SUMMARY:")
    print(f"  Total files processed: {successful_imports + failed_imports}")
    print(f"  Successful imports: {successful_imports}")
    print(f"  Failed imports: {failed_imports}")
    
    if successful_imports > 0:
        print(f"\n✅ Successfully imported {successful_imports} VEX file(s)")
    if failed_imports > 0:
        print(f"❌ Failed to import {failed_imports} VEX file(s)")

if __name__ == "__main__":
    main()
