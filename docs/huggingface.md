# HuggingFace Dataset Upload

The `import-vex-dataset.py` script processes VEX files and uploads them as structured datasets to [HuggingFace Hub](https://huggingface.co/), making the data available for AI/ML workflows.

## Dataset Structure

VEX data is uploaded as **two separate but related datasets** (HuggingFace datasets are flat tables, so the relational structure is split):

| Repository | Contents | Cardinality |
|---|---|---|
| `{repo-id}-cve` | CVE metadata | 1 record per CVE |
| `{repo-id}-affects` | Product/component relationships | Multiple records per CVE |

For example, uploading to `myorg/vex-data` creates:
- `myorg/vex-data-cve`
- `myorg/vex-data-affects`

## Authentication

Authenticate with HuggingFace before uploading:

```bash
# Option 1: Interactive login (saved for future use)
huggingface-cli login

# Option 2: Pass a token directly
python import-vex-dataset.py ... --token "hf_your_token_here"
```

## Upload Examples

```bash
# Create a new dataset from a directory of VEX files
python import-vex-dataset.py ./vex-data/ --repo-id "myorg/vex-data"

# Single file
python import-vex-dataset.py cve-2024-1234.json --repo-id "myorg/vex-data"

# Private dataset
python import-vex-dataset.py ./vex-data/ --repo-id "myorg/vex-data" --private

# Save a local copy before uploading
python import-vex-dataset.py ./vex-data/ --repo-id "myorg/vex-data" --save-local ./dataset-backup
```

## Update Modes

When a dataset already exists on HuggingFace, the script can merge new data in three ways:

| Mode | Flag | Behaviour |
|---|---|---|
| **Update** (default) | `--update-mode update` | Upserts CVE records; replaces affects rows for updated CVEs. |
| **Append** | `--update-mode append` | Adds all new records as-is (may create duplicates). |
| **Replace** | `--update-mode replace` | Drops all existing data and uploads only the new data. |

```bash
# Update existing dataset with new files
python import-vex-dataset.py new-vex-files/ --repo-id "myorg/vex-data" --update-mode update

# Full replace
python import-vex-dataset.py ./vex-data/ --repo-id "myorg/vex-data" --update-mode replace
```

### Update Workflow

1. The script checks whether the dataset repositories already exist.
2. If they do, existing data is downloaded.
3. New and existing data are merged according to the update mode.
4. Duplicates are removed.
5. The merged dataset is pushed back to HuggingFace.

## Using the Dataset

```python
from datasets import load_dataset

# Load both tables
cve_data = load_dataset("myorg/vex-data-cve")["train"]
affects_data = load_dataset("myorg/vex-data-affects")["train"]

print(f"Total CVEs: {len(cve_data)}")
print(f"Total product relationships: {len(affects_data)}")
```

### Query a specific CVE

```python
cve = cve_data.filter(lambda x: x["cve"] == "CVE-2024-1234")
print(cve[0])

affected = affects_data.filter(lambda x: x["cve"] == "CVE-2024-1234")
for row in affected:
    print(f"  {row['product']}  state={row['state']}  errata={row['errata']}")
```

### Filter by severity

```python
critical = cve_data.filter(lambda x: x["severity"] == "Critical")
print(f"Critical CVEs: {len(critical)}")
```

### Convert to Pandas for analysis

```python
import pandas as pd

cve_df = cve_data.to_pandas()
affects_df = affects_data.to_pandas()

# Join for a single merged view
merged = pd.merge(cve_df, affects_df, on="cve", how="inner")
print(merged.head())
```

## Use Cases

- **AI/ML research** — train models on structured vulnerability data
- **NLP** — analyze vulnerability descriptions and statements
- **Automated classification** — build systems to categorize or triage CVEs
- **Trend analysis** — study vulnerability patterns over time
- **Security chatbots** — build Q&A assistants backed by real VEX data
