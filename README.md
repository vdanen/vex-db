# VEX Database Project

This project downloads and processes VEX (Vulnerability Exploitability eXchange) files from Red Hat's security data, extracts vulnerability information using the `vex-reader` Python module, and stores the data in a configurable database or uploads it as a dataset to HuggingFace Hub.

## Features

- **Downloads VEX files** from Red Hat's CSAF v2 VEX archive
- **Parses VEX data** using the `vex-reader` Python module
- **Extracts comprehensive data** including:
  - CVE ID and details
  - CVSS scores and metrics
  - Vulnerability descriptions and statements
  - Affected products and components
  - Vulnerability status (fixed, known_affected, known_not_affected)
- **Dual output options**:
  - **Database storage**: PostgreSQL, MySQL, and SQLite support
  - **HuggingFace datasets**: Upload structured datasets for AI/ML use cases
- **Database schema** optimized for VEX data structure
- **Command line interface** for single file and batch processing

## Database Schema

### CVE Table
- `cve` (VARCHAR): CVE identifier (primary key)
- `cvss_score` (FLOAT): CVSS v3.1 base score
- `cvss_metrics` (VARCHAR): CVSS vector string
- `severity` (VARCHAR): Vulnerability severity (Low, Medium, High, Critical)
- `public_date` (TEXT): Public disclosure date
- `updated_date` (TEXT): Last update date
- `description` (TEXT): Vulnerability description
- `mitigation` (TEXT): Mitigation information
- `statement` (TEXT): VEX statement

### Affects Table
- `cve` (VARCHAR): CVE identifier (foreign key)
- `product` (TEXT): Affected product name
- `cpe` (TEXT): Common Platform Enumeration identifier
- `purl` (TEXT): Package URL
- `errata` (TEXT): Errata/advisory identifier
- `release_date` (TEXT): Fix release date
- `state` (TEXT): Status (fixed, affected, not_affected, wontfix)
- `reason` (TEXT): Reason for status
- `components` (TEXT): Affected components

## HuggingFace Dataset Structure

The HuggingFace datasets are uploaded as **two separate but related datasets** to work around schema limitations:

- **`{repo-id}-cve`**: Contains CVE metadata (1 record per CVE)
- **`{repo-id}-affects`**: Contains product/component relationships (multiple records per CVE)

This structure maintains the relational integrity while being compatible with HuggingFace's dataset format requirements.

### Example Dataset Names
If you upload to `myorg/vex-security-data`, you'll get:
- `myorg/vex-security-data-cve` - CVE information
- `myorg/vex-security-data-affects` - Product relationships

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd vex-db
   ```

2. **Create virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize database (for database usage):**
   ```bash
   ./initialize.sh
   ```

## Usage

### Database Import (`import-vex.py`)

Import VEX files into a database:

```bash
# Single file
python import-vex.py cve-2022-48632.json

# Directory (recursive)
python import-vex.py /path/to/vex/files/

# Directory (non-recursive)
python import-vex.py /path/to/vex/files/ --no-recursive

# Custom database
python import-vex.py /path/to/vex/files/ --database-url "postgresql://user:pass@host:port/db"

# Continue on errors
python import-vex.py /path/to/vex/files/ --continue-on-error
```

### HuggingFace Dataset Upload (`import-vex-dataset.py`)

Process VEX files and upload to HuggingFace Hub:

```bash
# Single file (create new dataset)  
python import-vex-dataset.py cve-2022-48632.json --repo-id "username/vex-dataset"

# Directory (recursive)
python import-vex-dataset.py /path/to/vex/files/ --repo-id "username/vex-dataset"

# Update existing dataset with new VEX files
python import-vex-dataset.py new-vex-files/ --repo-id "username/vex-dataset" --update-mode update

# Append new data without replacing existing records
python import-vex-dataset.py new-vex-files/ --repo-id "username/vex-dataset" --update-mode append

# Replace entire dataset with new data
python import-vex-dataset.py new-vex-files/ --repo-id "username/vex-dataset" --update-mode replace

# Private dataset
python import-vex-dataset.py /path/to/vex/files/ --repo-id "username/vex-dataset" --private

# With authentication token
python import-vex-dataset.py /path/to/vex/files/ --repo-id "username/vex-dataset" --token "hf_..."

# Save locally before upload
python import-vex-dataset.py /path/to/vex/files/ --repo-id "username/vex-dataset" --save-local "./dataset"
```

#### Update Modes

The script supports three update modes when working with existing datasets:

- **`update` (default)**: Updates existing CVE records and adds new ones. For existing CVEs, replaces all associated product relationships with new data.
- **`append`**: Simply adds all new records to the existing dataset (may create duplicates).
- **`replace`**: Completely replaces the existing dataset with new data.

#### Dataset Update Workflow

1. **Check if dataset exists**: Script automatically detects existing datasets
2. **Load existing data**: Downloads current dataset if it exists
3. **Merge data**: Combines new and existing data based on update mode
4. **Remove duplicates**: Eliminates duplicate CVE records
5. **Upload updated dataset**: Pushes merged dataset back to HuggingFace

#### Authentication for HuggingFace

Before uploading datasets, authenticate with HuggingFace:

```bash
# Option 1: Use CLI login
huggingface-cli login

# Option 2: Pass token directly
python import-vex-dataset.py ... --token "hf_your_token_here"
```

### Query Database

Query the database using the provided script:

```bash
# Query specific CVE
python query-vex.py --cve CVE-2022-48632

# Search by product
python query-vex.py --product "Red Hat Enterprise Linux"

# Search by severity
python query-vex.py --severity "High"

# Search by CVSS score range
python query-vex.py --cvss-min 7.0 --cvss-max 10.0
```

### Using HuggingFace Dataset

Once uploaded, use the datasets in your AI/ML projects:

```python
from datasets import load_dataset

# Load the datasets (they are stored as separate repositories)
cve_dataset = load_dataset("username/vex-dataset-cve")
affects_dataset = load_dataset("username/vex-dataset-affects") 

# Access the data (default split is 'train')
cve_data = cve_dataset['train']
affects_data = affects_dataset['train']

print(f"Total CVEs: {len(cve_data)}")
print(f"Total product relationships: {len(affects_data)}")

# Query specific CVE
cve_info = cve_data.filter(lambda x: x['cve'] == 'CVE-2022-48632')
print(cve_info[0])

# Get all products affected by a CVE
affected_products = affects_data.filter(lambda x: x['cve'] == 'CVE-2022-48632')
for product in affected_products:
    print(f"Product: {product['product']}, State: {product['state']}")

# Filter by severity
high_severity = cve_data.filter(lambda x: x['severity'] == 'High')
print(f"High severity CVEs: {len(high_severity)}")

# Convert to pandas for analysis
import pandas as pd
cve_df = cve_data.to_pandas()
affects_df = affects_data.to_pandas()

# Join data for analysis
merged_df = pd.merge(cve_df, affects_df, on='cve', how='inner')
print(merged_df.head())
```

## Database Configuration

### SQLite (Default)
```bash
python import-vex.py data/ --database-url "sqlite:///vex.db"
```

### PostgreSQL
```bash
python import-vex.py data/ --database-url "postgresql://user:password@localhost:5432/vex_db"
```

### MySQL
```bash
python import-vex.py data/ --database-url "mysql+pymysql://user:password@localhost:3306/vex_db"
```

## Example Data Processing

The scripts process VEX files and extract:

- **CVE metadata**: ID, CVSS scores, severity, dates, descriptions
- **Product relationships**: Which products are affected, fixed, or not affected
- **Component details**: Specific software components and versions
- **Advisory information**: Errata, release dates, mitigation details

## Use Cases

### Database Approach
- **Enterprise security teams**: Query and analyze vulnerability data
- **Compliance reporting**: Generate reports on security posture
- **Integration**: Connect with existing security tools and workflows

### HuggingFace Dataset Approach
- **AI/ML research**: Train models on vulnerability data
- **Natural language processing**: Analyze vulnerability descriptions
- **Automated classification**: Build systems to categorize vulnerabilities
- **Trend analysis**: Study vulnerability patterns over time
- **Chatbots and Q&A systems**: Build AI assistants for security information

## Project Structure

```
vex-db/
├── import-vex.py              # Database import script
├── import-vex-dataset.py      # HuggingFace dataset upload script
├── query-vex.py               # Database query script
├── initialize.sh              # Database initialization
├── vex-db.sql                 # Database schema
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── test/                      # Test data
    ├── cve-2022-48632.json   # Sample VEX file
    └── run_tests.py          # Test suite
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the GPLv3 License - see the LICENSE file for details.

## Acknowledgments

- **Red Hat Security Team** for providing VEX data
- **vex-reader** library for VEX parsing capabilities
- **HuggingFace** for dataset hosting and AI/ML infrastructure
