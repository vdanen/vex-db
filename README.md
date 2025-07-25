# VEX Database Project

This project downloads and processes VEX (Vulnerability Exploitability eXchange) files from Red Hat's security data, extracts vulnerability information using the `vex-reader` Python module, and stores the data in a configurable database.

## Features

- **Downloads VEX files** from Red Hat's CSAF v2 VEX archive
- **Parses VEX data** using the `vex-reader` Python module
- **Extracts comprehensive data** including:
  - CVE ID and details
  - CVSS scores and metrics
  - Vulnerability descriptions and statements
  - Affected products and components
  - Vulnerability status (fixed, known_affected, known_not_affected)
- **Supports multiple databases**: PostgreSQL, MySQL, and SQLite
- **Database schema** optimized for VEX data structure
- **Command line interface** for single file or batch directory processing
- **Recursive directory traversal** for processing VEX archives
- **Error handling** with continue-on-error support for batch processing

## Database Schema

### CVE Table
- `cve` (VARCHAR(18), PRIMARY KEY) - CVE identifier
- `cvss_score` (FLOAT) - CVSS base score
- `cvss_metrics` (VARCHAR(48)) - CVSS vector string
- `severity` (VARCHAR(10)) - Vulnerability severity (Low, Moderate, Important, Critical)
- `public_date` (TEXT) - Public release date
- `updated_date` (TEXT) - Last update date
- `description` (TEXT) - Vulnerability description
- `mitigation` (TEXT) - Mitigation information
- `statement` (TEXT) - Vendor statement

### Affects Table
- `cve` (VARCHAR(18)) - CVE identifier (foreign key)
- `product` (TEXT) - Affected product/component name
- `errata` (TEXT) - Associated errata/advisory
- `release_date` (TEXT) - Fix release date
- `state` (TEXT) - Status (fixed, wontfix, not_affected, affected)
- `reason` (TEXT) - Reason for status (e.g., wontfix reason)
- `components` (TEXT) - Affected components (comma-separated)

## Setup

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Create virtual environment** (recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Initialize database**:
   ```bash
   sqlite3 vex.db < vex-db.sql
   ```

## Database Configuration

The project supports multiple database backends. Use the `--database-url` argument or edit the DEFAULT_DATABASE_URL in `import-vex.py`:

### SQLite (default)
```bash
python import-vex.py file.json --database-url "sqlite:///vex.db"
```

### PostgreSQL
```bash
python import-vex.py file.json --database-url "postgresql://username:password@localhost:5432/vex_database"
```

### MySQL
```bash
python import-vex.py file.json --database-url "mysql://username:password@localhost:3306/vex_database"
```

## Usage

### Command Line Interface

The script supports flexible command line arguments for processing single files or directories:

```bash
python import-vex.py [OPTIONS] PATH
```

#### Single File Import
```bash
python import-vex.py cve-2022-48632.json
```

#### Directory Import (Recursive)
```bash
python import-vex.py /path/to/vex/directory
```

#### Directory Import (Non-Recursive)
```bash
python import-vex.py /path/to/vex/directory --no-recursive
```

#### Custom Database
```bash
python import-vex.py vex_files/ --database-url "postgresql://user:pass@localhost/vexdb"
```

### Command Line Options

- `--recursive` - Recursively search directories (default: True)
- `--no-recursive` - Only process files in specified directory
- `--continue-on-error` - Continue processing if one file fails (default: True)  
- `--database-url URL` - Specify database connection string

### Example Output

#### Single File Processing
```
Processing VEX file: cve-2022-48632.json
  Parsed VEX data for CVE: CVE-2022-48632
  Severity: Low
  Release Date: 2024-04-27
  CVSS Score: 5.5
  Description: A flaw was found in the Linux kernel...
Successfully imported VEX data for CVE-2022-48632

✅ Successfully imported 1 VEX file(s)
```

#### Directory Processing
```
Found 4 JSON files in vex_archive/

Starting import of 4 file(s)...
============================================================

[1/4] Processing: cve-2022-48632.json
  Parsed VEX data for CVE: CVE-2022-48632
  Successfully imported VEX data for CVE-2022-48632

[2/4] Processing: cve-2023-12345.json
  Parsed VEX data for CVE: CVE-2023-12345
  Successfully imported VEX data for CVE-2023-12345

...

============================================================
IMPORT SUMMARY:
  Total files processed: 4
  Successful imports: 3
  Failed imports: 1

✅ Successfully imported 3 VEX file(s)
❌ Failed to import 1 VEX file(s)
```

## Data Sources

- **VEX Archive**: https://security.access.redhat.com/data/csaf/v2/vex/csaf_vex_2025-07-12.tar.zst
- **Example VEX File**: https://security.access.redhat.com/data/csaf/v2/vex/2025/cve-2025-0050.json

## Processing VEX Archives

To process the full Red Hat VEX archive:

1. **Download and extract the archive**:
   ```bash
   wget https://security.access.redhat.com/data/csaf/v2/vex/csaf_vex_2025-07-12.tar.zst
   tar -xf csaf_vex_2025-07-12.tar.zst
   ```

2. **Process all VEX files**:
   ```bash
   python import-vex.py extracted_vex_directory/ --recursive
   ```

3. **Monitor progress** - The script will show progress for each file and provide a summary.

## Database Queries

### View imported CVEs
```sql
SELECT cve, cvss_score, severity, public_date, substr(description, 1, 100) as description_preview 
FROM cve;
```

### View affected products by state
```sql
SELECT state, COUNT(*) as count, COUNT(DISTINCT cve) as unique_cves
FROM affects 
GROUP BY state;
```

### Find products affected by specific CVE
```sql
SELECT cve, product, state, components, errata
FROM affects 
WHERE cve = 'CVE-2022-48632' 
ORDER BY state;
```

### Summary statistics
```sql
SELECT 
  (SELECT COUNT(*) FROM cve) as total_cves,
  (SELECT COUNT(*) FROM affects) as total_product_entries,
  (SELECT COUNT(DISTINCT product) FROM affects) as unique_products;
```

## Error Handling

The script includes robust error handling:

- **Invalid JSON files** are skipped with error messages
- **Malformed VEX data** is logged but doesn't stop processing
- **Database errors** are caught and reported per file
- **Missing fields** are handled gracefully with NULL values
- **Batch processing** continues even if individual files fail

## Querying the Database

### Component Query Script

Use `query-vex.py` to search for CVEs affecting specific components:

  ```bash
  # Search for all CVEs affecting mysql component
  python query-vex.py --component mysql

  # Search for kernel CVEs from 2024
  python query-vex.py --component kernel --year 2024

  # Filter by severity (critical, important, moderate, low)
  python query-vex.py --component mysql --severity critical

  # Filter by product and component
  python query-vex.py --component mysql --product "Red Hat Enterprise Linux"

  # Multiple filters combined (component, product, year, severity)
  python query-vex.py --component kernel --product RHEL --year 2024 --severity important

  # Query all CVEs for a product (no component required)
  python query-vex.py --product "Red Hat Enterprise Linux 9"

  # Query all CVEs from a specific year (no component required)
  python query-vex.py --year 2024

  # Filter by severity and year without component
  python query-vex.py --year 2024 --severity critical

  # Combine product and year filters without component
  python query-vex.py --product "Red Hat Enterprise Linux 9" --year 2024

  # Get only the count of results
  python query-vex.py --component kernel --count-only

  # Export results as JSON
  python query-vex.py --component mysql --format json > mysql-cves.json
  ```

  #### Query Options
  - `--component` (optional): Component name to search for (supports partial matching)
  - `--year`: Filter by publication year (e.g., 2024)
  - `--product`: Filter by product name (supports partial matching)
  - `--severity`: Filter by vulnerability severity (critical, important, moderate, low)
  - `--exact`: Use exact component matching instead of fuzzy matching
  - `--format`: Output format (table, json, csv)
  - `--count-only`: Show only result counts

  **Note**: At least one filter (`--component`, `--product`, `--cpe`, `--purl`, `--severity`, or `--year`) must be specified.

  #### Output Format
  The script displays results grouped by product and ordered by state, showing:
  - ✅ **Fixed CVEs** with errata information
  - ❌ **Affected CVEs** 
  - ⚪ **Not Affected CVEs**
  - ⚠️ **Won't Fix CVEs** with reasons
  - CVE ID, CVSS score, severity, and publication date
  - Complete component lists for each CVE

## Project Structure

- `import-vex.py` - Main import script with CLI interface
- `query-vex.py` - Query script for searching CVEs
- `vex-db.sql` - Database schema definition
- `vex.db` - SQLite database file (created after first run)
- `cve-2022-48632.json` - Example VEX data file

## Performance Considerations

- **SQLite**: Good for testing and small datasets (< 1GB)
- **PostgreSQL**: Recommended for production and large datasets
- **Batch size**: Process 1000-5000 files per batch for optimal performance
- **Memory usage**: ~50-100MB for typical VEX files
- **Processing speed**: ~10-50 files per second depending on file size
