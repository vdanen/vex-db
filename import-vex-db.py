#!/usr/bin/env python

from vex import Vex, VexPackages
import json
import datetime
import argparse
import os
import glob
from pathlib import Path
from tqdm import tqdm

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
        if not cve_id:
            raise ValueError("No CVE ID found in VEX data")
        
        # Get CVSS score and metrics from global_cvss
        cvss_score = None
        cvss_metrics = None
        if hasattr(vex_obj, 'global_cvss') and vex_obj.global_cvss:
            try:
                base_score = vex_obj.global_cvss.baseScore
                if base_score and str(base_score).strip():
                    cvss_score = float(base_score)
            except (ValueError, TypeError):
                # Invalid CVSS score - set to None and continue
                cvss_score = None

            cvss_metrics = vex_obj.global_cvss.vectorString if hasattr(vex_obj.global_cvss, 'vectorString') else None
        
        # Get severity
        severity = vex_obj.global_impact if hasattr(vex_obj, 'global_impact') else None

        # Get CWE
        cwe = vex_obj.cwe_id if hasattr(vex_obj, 'cwe_id') else None

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
            (cve, cvss_score, cvss_metrics, severity, cwe, public_date, updated_date, description, mitigation, statement)
            VALUES (:cve, :cvss_score, :cvss_metrics, :severity, :cwe, :public_date, :updated_date, :description, :mitigation, :statement)
        """)
        
        session.execute(cve_insert, {
            'cve': cve_id,
            'cvss_score': cvss_score,
            'cvss_metrics': cvss_metrics,
            'severity': severity,
            'cwe': cwe,
            'public_date': public_date,
            'updated_date': updated_date,
            'description': description,
            'mitigation': mitigation,
            'statement': statement
        })
        
        # handle fixes first
        if hasattr(packages, 'fixes') and packages.fixes:
            for fix in packages.fixes:
                affects_insert = text("""
                    INSERT INTO affects 
                    (cve, product, cpe, purl, errata, release_date, state, components)
                    VALUES (:cve, :product, :cpe, :purl, :errata, :release_date, :state, :components)
                """)
                
                session.execute(affects_insert, {
                    'cve': cve_id,
                    'product': fix.product,
                    'cpe': fix.cpe,
                    'purl': fix.purl,
                    'errata': fix.id,
                    'release_date': fix.date,
                    'state': 'fixed',
                    'components': ','.join(fix.components) if fix.components else None
                })

        # handle wontfix products
        if hasattr(packages, 'wontfix') and packages.wontfix:
            for wontfix in packages.wontfix:
                affects_insert = text("""
                    INSERT INTO affects 
                    (cve, product, cpe, purl, reason, state, components)
                    VALUES (:cve, :product, :cpe, :purl, :reason, :state, :components)
                """)

                session.execute(affects_insert, {
                    'cve': cve_id,
                    'product': wontfix.product,
                    'cpe': wontfix.cpe,
                    'purl': wontfix.purl,
                    'reason': wontfix.reason,
                    'state': 'wontfix',
                    'components': wontfix.component if hasattr(wontfix, 'component') else None
                })

        # handle not affected products
        if hasattr(packages, 'not_affected') and packages.not_affected:
            for not_affected in packages.not_affected:
                affects_insert = text("""
                    INSERT INTO affects 
                    (cve, product, cpe, purl, state, components)
                    VALUES (:cve, :product, :cpe, :purl, :state, :components)
                """)

                session.execute(affects_insert, {
                    'cve': cve_id,
                    'product': not_affected.product,
                    'cpe': not_affected.cpe,
                    'purl': not_affected.purl,
                    'state': 'not_affected',
                    'components': ','.join(not_affected.components) if not_affected.components else None
                })

        # handle affected products
        if hasattr(packages, 'affected') and packages.affected:
            for affected in packages.affected:
                affects_insert = text("""
                    INSERT INTO affects 
                    (cve, product, cpe, purl, state, components)
                    VALUES (:cve, :product, :cpe, :purl, :state, :components)
                """)

                session.execute(affects_insert, {
                    'cve': cve_id,
                    'product': affected.product,
                    'cpe': affected.cpe,
                    'purl': affected.purl,
                    'state': 'affected',
                    'components': ','.join(affected.components) if affected.components else None
                })
        
        # Commit the transaction
        session.commit()
        return True
        
    except Exception as e:
        session.rollback()
        print(f"Error importing VEX data: {e}")
        return False
    finally:
        session.close()


def process_vex_file(file_path, verbose=False):
    """Process a single VEX file"""
    try:
        if verbose:
            print(f"Processing VEX file: {file_path}")
        
        with open(file_path, 'r') as f:
            data = json.load(f)
            try:
                vex = Vex(data)
                packages = VexPackages(vex.raw)
            except KeyError as e:
                if str(e) == "'names'":
                    # Known issue with VEX reader library when acknowledgments don't have 'names' field
                    error_msg = f"VEX reader library issue with acknowledgments format in {os.path.basename(file_path)}: {e}"
                    if verbose:
                        print(f"  ❌ {error_msg}")
                    return False, os.path.basename(file_path), "error", error_msg
                else:
                    raise  # Re-raise other KeyErrors
            except Exception as e:
                error_msg = f"VEX reader parsing error in {os.path.basename(file_path)}: {e}"
                if verbose:
                    print(f"  ❌ {error_msg}")
                return False, os.path.basename(file_path), "error", error_msg

        if verbose:
            print(f"  Parsed VEX data for CVE: {vex.cve}")
            print(f"  Severity: {vex.global_impact}")
            print(f"  Release Date: {vex.release_date}")

            # Safe CVSS score display
            cvss_display = 'None'
            if hasattr(vex, 'global_cvss') and vex.global_cvss:
                base_score = getattr(vex.global_cvss, 'baseScore', None)
                if base_score and str(base_score).strip():
                    cvss_display = str(base_score)
            print(f"  CVSS Score: {cvss_display}")

            # Get description for display
            description = None
            if hasattr(vex, 'notes') and vex.notes and 'description' in vex.notes:
                desc_dict = vex.notes['description']
                description = list(desc_dict.values())[0] if desc_dict else None

            print(f"  Description: {description[:100] + '...' if description and len(description) > 100 else description}")
        
        # Check if this VEX file has any affected products
        has_affected_products = (
            (hasattr(packages, 'fixes') and packages.fixes) or
            (hasattr(packages, 'affected') and packages.affected) or
            (hasattr(packages, 'wontfix') and packages.wontfix) or
            (hasattr(packages, 'not_affected') and packages.not_affected)
        )
        
        if not has_affected_products:
            if verbose:
                print(f"  ⚠️ Skipping {vex.cve}: No affected products found")
                print(f"     This VEX file contains no actionable vulnerability information")
            return True, vex.cve, "skipped"  # Return success since this is expected behavior
        
        if verbose:
            # Count products for display
            total_products = (
                len(packages.fixes or []) +
                len(packages.affected or []) +
                len(packages.wontfix or []) +
                len(packages.not_affected or [])
            )
            print(f"  Products: {total_products} total (fixes: {len(packages.fixes or [])}, affected: {len(packages.affected or [])}, wontfix: {len(packages.wontfix or [])}, not_affected: {len(packages.not_affected or [])})")
        
        # Insert the data into the database
        success = insert_vex_data(vex, packages)
        return success, vex.cve, "imported" if success else "failed"
        
    except (OSError, IOError) as e:
        error_msg = f"File reading error in {os.path.basename(file_path)}: {e}"
        if verbose:
            print(f"  ❌ {error_msg}")
        return False, os.path.basename(file_path), "error", error_msg
    except json.JSONDecodeError as e:
        error_msg = f"JSON parsing error in {os.path.basename(file_path)}: {e}"
        if verbose:
            print(f"  ❌ {error_msg}")
        return False, os.path.basename(file_path), "error", error_msg
    except Exception as e:
        error_msg = f"Unexpected error processing {os.path.basename(file_path)}: {e}"
        if verbose:
            print(f"  ❌ {error_msg}")
        return False, os.path.basename(file_path), "error", error_msg


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
  %(prog)s cve-2022-48632.json                    # Import single file (auto-verbose)
  %(prog)s /path/to/vex/directory                 # Import with progress bar
  %(prog)s /path/to/vex/directory --verbose       # Import with detailed output
  %(prog)s /path/to/vex/directory --recursive     # Import recursively (default)
  %(prog)s /path/to/vex/directory --no-recursive  # Import only direct files

Output Modes:
  Single file imports automatically show detailed output.
  Multiple file imports show a progress bar by default.
  Use --verbose to show detailed output for multiple files.
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
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed output for each file (default for single files)'
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
    skipped_imports = 0
    errors = []  # Store errors to display at the end or immediately in verbose mode

    # Determine if we should use verbose mode
    # Use verbose for single files or when explicitly requested
    use_verbose = args.verbose or len(vex_files) == 1
    
    print(f"\nStarting import of {len(vex_files)} file(s)...")
    if not use_verbose:
        print("Use --verbose for detailed output per file")
    print("=" * 60)
    
    # Create progress bar if not verbose mode
    if use_verbose:
        # Verbose mode - detailed output for each file
        for i, vex_file in enumerate(vex_files, 1):
            print(f"\n[{i}/{len(vex_files)}] Processing: {os.path.basename(vex_file)}")

            result = process_vex_file(vex_file, verbose=True)
            if len(result) == 4:  # Error case
                success, cve_name, status, error_msg = result
                errors.append(error_msg)
            else:
                success, cve_name, status = result

            if success and status == "imported":
                successful_imports += 1
            elif success and status == "skipped":
                skipped_imports += 1
            else:
                failed_imports += 1
                if not args.continue_on_error:
                    print(f"Stopping due to error in {vex_file}")
                    break
    else:
        # Progress bar mode - compact output
        with tqdm(vex_files, desc="Processing VEX files",
                  bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}') as pbar:
            for vex_file in pbar:
                filename = os.path.basename(vex_file)
                pbar.set_postfix_str(f"Current: {filename[:40]}{'...' if len(filename) > 40 else ''}")

                result = process_vex_file(vex_file, verbose=False)
                if len(result) == 4:  # Error case
                    success, cve_name, status, error_msg = result
                    # Print error above progress bar
                    tqdm.write(f"❌ ERROR in {filename}: {error_msg}")
                    errors.append(error_msg)
                else:
                    success, cve_name, status = result

                if success and status == "imported":
                    successful_imports += 1
                    pbar.set_postfix_str(f"✅ Imported: {cve_name}")
                elif success and status == "skipped":
                    skipped_imports += 1
                    pbar.set_postfix_str(f"⚠️ Skipped: {cve_name} (no affected products)")
                else:
                    failed_imports += 1
                    pbar.set_postfix_str(f"❌ Failed: {filename}")
                    if not args.continue_on_error:
                        tqdm.write(f"Stopping due to error in {vex_file}")
                        break
    
    # Summary
    print("\n" + "=" * 60)
    print("IMPORT SUMMARY:")
    total_processed = successful_imports + failed_imports + skipped_imports
    print(f"  Total files processed: {total_processed}")
    print(f"  Successful imports: {successful_imports}")
    print(f"  Skipped (no affected products): {skipped_imports}")
    print(f"  Failed imports: {failed_imports}")
    
    if successful_imports > 0:
        print(f"\n✅ Successfully imported {successful_imports} VEX file(s)")
    if skipped_imports > 0:
        print(f"⚠️ Skipped {skipped_imports} VEX file(s) (no affected products)")
    if failed_imports > 0:
        print(f"❌ Failed to import {failed_imports} VEX file(s)")
        if not use_verbose and errors:
            print("\nERROR DETAILS:")
            for i, error in enumerate(errors[-10:], 1):  # Show last 10 errors
                print(f"  {i}. {error}")
            if len(errors) > 10:
                print(f"  ... and {len(errors) - 10} more errors")

if __name__ == "__main__":
    main()
