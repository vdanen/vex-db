# VEX Database

A toolkit for downloading, storing, querying, and analyzing [Red Hat VEX](https://security.access.redhat.com/data/csaf/v2/vex/) (Vulnerability Exploitability eXchange) data. Import VEX files into a local SQLite database, query them from the command line, generate statistics, or upload structured datasets to HuggingFace Hub.

## Quick Start

```bash
git clone <repository-url>
cd vex-db
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Initialize the Database

The `initialize.sh` script downloads the latest VEX archive from Red Hat, creates the SQLite database, and imports everything:

```bash
./initialize.sh
```

This takes a while on the first run (the archive is large). When it finishes you'll have a `vex.db` file ready to query.

> **Updating:** Run `initialize.sh` again at any time to pull a fresh archive. It drops and recreates the tables, so you always get a clean import.

## Usage

### Query CVEs

```bash
# Look up a specific CVE
python query-vex.py --cve CVE-2024-1234

# Find CVEs affecting a component
python query-vex.py --component openssl

# Filter by product and year
python query-vex.py --product "Red Hat Enterprise Linux" --year 2024

# Filter by severity
python query-vex.py --severity critical --year 2025

# Output as JSON or CSV
python query-vex.py --component kernel --format json
```

### Generate Statistics

```bash
# Severity breakdown, top CWEs, days-of-risk, and errata stats for a year
python generate-vex-statistics.py --year 2024

# Filter to a specific product
python generate-vex-statistics.py --year 2024 --product "Red Hat Enterprise Linux"

# Show outstanding unfixed CVEs (Critical, Important, Moderate ≥ CVSS 7.0)
python generate-vex-statistics.py --year 2024 --outstanding

# Launch the interactive web dashboard (requires Flask)
python generate-vex-statistics.py --interactive
```

### Import a Subset Manually

If you already have VEX JSON files and just want to import them:

```bash
# Create the tables (only needed once)
sqlite3 vex.db < vex-db.sql

# Import a single file
python import-vex-db.py cve-2024-1234.json

# Import a directory of files
python import-vex-db.py ./vex-2024-10-01/
```

## Database Schema

Two tables — `cve` for vulnerability metadata, `affects` for per-product status:

| `cve` | | `affects` | |
|---|---|---|---|
| `cve` | CVE ID (PK) | `cve` | CVE ID (FK) |
| `cvss_score` | CVSS v3 base score | `product` | Product name |
| `cvss_metrics` | CVSS vector string | `cpe` | CPE identifier |
| `severity` | Low / Moderate / Important / Critical | `purl` | Package URL |
| `cwe` | CWE identifier(s) | `errata` | Advisory ID |
| `public_date` | Disclosure date | `release_date` | Fix release date |
| `updated_date` | Last updated | `state` | fixed / affected / not_affected / wontfix |
| `description` | Vulnerability description | `reason` | Reason for status |
| `mitigation` | Mitigation details | `components` | Affected components |
| `statement` | Vendor statement | | |

## Project Structure

```
vex-db/
├── initialize.sh               # Download, create DB, and import
├── import-vex-db.py             # Import VEX JSON → SQLite
├── import-vex-dataset.py        # Import VEX JSON → HuggingFace Hub
├── query-vex.py                 # CLI queries against the database
├── generate-vex-statistics.py   # Statistics & web dashboard
├── vex-db.sql                   # Table definitions
├── requirements.txt             # Python dependencies
└── docs/
    ├── sql.md                   # SQL schema details & advanced queries
    └── huggingface.md           # HuggingFace dataset upload guide
```

## Further Reading

- **[docs/sql.md](docs/sql.md)** — SQL schema details, database configuration (PostgreSQL, MySQL), and example queries.
- **[docs/huggingface.md](docs/huggingface.md)** — Uploading VEX data as HuggingFace datasets for AI/ML use cases.

## License

GPLv3 — see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Red Hat Product Security](https://www.redhat.com/en/blog/channel/security) for providing VEX data
- [vex-reader](https://pypi.org/project/vex-reader/) for VEX parsing
- [HuggingFace](https://huggingface.co/) for dataset hosting
