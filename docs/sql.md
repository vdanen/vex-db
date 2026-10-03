# SQL Schema & Database Details

This document covers the database schema in depth, alternative database backends, and useful SQL queries for working with VEX data.

## Schema Definition

The full schema lives in [`vex-db.sql`](../vex-db.sql) and is applied automatically by `initialize.sh`. To apply it manually:

```bash
sqlite3 vex.db < vex-db.sql
```

> **Warning:** This drops and recreates both tables, erasing any existing data.

### `cve` Table

| Column | Type | Description |
|---|---|---|
| `cve` | `VARCHAR(18)` | CVE identifier — **primary key** |
| `cvss_score` | `FLOAT` | CVSS v3.1 base score |
| `cvss_metrics` | `VARCHAR(48)` | CVSS vector string (e.g. `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| `severity` | `VARCHAR(10)` | Red Hat severity rating: `Low`, `Moderate`, `Important`, or `Critical` |
| `cwe` | `TEXT` | CWE identifier(s) (e.g. `CWE-79`) |
| `public_date` | `TEXT` | Public disclosure date (`YYYY-MM-DD`) |
| `updated_date` | `TEXT` | Last update timestamp |
| `description` | `TEXT` | Vulnerability description |
| `mitigation` | `TEXT` | Mitigation guidance |
| `statement` | `TEXT` | Red Hat's VEX statement |

### `affects` Table

| Column | Type | Description |
|---|---|---|
| `cve` | `VARCHAR(18)` | CVE identifier (references `cve.cve`) |
| `product` | `TEXT` | Affected product name |
| `cpe` | `TEXT` | Common Platform Enumeration identifier |
| `purl` | `TEXT` | Package URL |
| `errata` | `TEXT` | Errata/advisory identifier (e.g. `RHSA-2024:1234`) |
| `release_date` | `TEXT` | Fix release date (`Month DD, YYYY` format) |
| `state` | `TEXT` | One of `fixed`, `affected`, `not_affected`, `wontfix` |
| `reason` | `TEXT` | Reason for the status (used with `wontfix`) |
| `components` | `TEXT` | Comma-separated list of affected components |

## Database Backends

The import script uses SQLAlchemy, so you can point it at any supported database.

### SQLite (default)

```bash
python import-vex-db.py ./vex-data/ --database-url "sqlite:///vex.db"
```

### PostgreSQL

```bash
python import-vex-db.py ./vex-data/ --database-url "postgresql://user:password@localhost:5432/vex_db"
```

You'll need to create the tables first. Adapt `vex-db.sql` for PostgreSQL syntax or use an ORM migration.

### MySQL

```bash
python import-vex-db.py ./vex-data/ --database-url "mysql+pymysql://user:password@localhost:3306/vex_db"
```

Install the driver: `pip install pymysql`.

## Import Options

```bash
# Single file (auto-verbose)
python import-vex-db.py cve-2024-1234.json

# Recursive directory import (default)
python import-vex-db.py /path/to/vex/files/

# Non-recursive (top-level files only)
python import-vex-db.py /path/to/vex/files/ --no-recursive

# Verbose output for every file
python import-vex-db.py /path/to/vex/files/ --verbose
```

## Example Queries

### CVEs by severity for a given year

```sql
SELECT severity, COUNT(*) as count
FROM cve
WHERE public_date LIKE '2024%'
GROUP BY severity
ORDER BY count DESC;
```

### Products affected by a specific CVE

```sql
SELECT product, cpe, state, errata, release_date
FROM affects
WHERE cve = 'CVE-2024-1234'
ORDER BY product;
```

### Unfixed Critical CVEs

```sql
SELECT DISTINCT c.cve, c.cvss_score, c.public_date, a.product
FROM cve c
INNER JOIN affects a ON c.cve = a.cve
WHERE c.severity = 'Critical'
  AND a.state IN ('affected', 'wontfix')
  AND c.cve NOT IN (
    SELECT cve FROM affects WHERE state = 'fixed'
  )
ORDER BY c.cvss_score DESC;
```

### Top CWEs in a year

```sql
SELECT cwe, COUNT(*) as count
FROM cve
WHERE public_date LIKE '2024%'
  AND cwe IS NOT NULL AND cwe != ''
GROUP BY cwe
ORDER BY count DESC
LIMIT 10;
```

### Days of risk (time from disclosure to first fix)

```sql
SELECT
  c.cve,
  c.severity,
  c.public_date,
  MIN(a.release_date) AS first_fix,
  CAST(julianday(MIN(a.release_date)) - julianday(c.public_date) AS INTEGER) AS days_of_risk
FROM cve c
INNER JOIN affects a ON c.cve = a.cve
WHERE a.errata IS NOT NULL AND a.errata != ''
  AND c.public_date LIKE '2024%'
GROUP BY c.cve
ORDER BY days_of_risk DESC
LIMIT 20;
```

### Count of errata by severity

```sql
SELECT c.severity, COUNT(DISTINCT a.errata) AS errata_count
FROM affects a
INNER JOIN cve c ON a.cve = c.cve
WHERE a.release_date LIKE '%, 2024'
  AND a.errata IS NOT NULL AND a.errata != ''
GROUP BY c.severity
ORDER BY errata_count DESC;
```
