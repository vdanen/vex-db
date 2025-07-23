# VEX Database Test Suite

This directory contains automated tests for the VEX database import and query functionality.

## Test Files

- `run_tests.py` - Main test suite that validates import and query functionality
- `cve-2022-48632.json` - Sample VEX data file for testing
- `README.md` - This file

## Running Tests

### Run All Tests
```bash
cd test/
python run_tests.py
```

### Alternative: Run from project root
```bash
python test/run_tests.py
```

## What the Tests Do

1. **Setup**: Creates a temporary SQLite database with the VEX schema
2. **Import Test**: Uses `import-vex.py` to import the test CVE data
3. **Query Tests**: Uses `query-vex.py` to validate various query functionality:
   - Component queries
   - JSON output format
   - CSV output format (with space-separated components)
   - Query filters (year, exact matching)
   - Validation error handling
4. **Cleanup**: Removes temporary database files

## Expected Output

When all tests pass, you should see:
```
🧪 Starting VEX Database Test Suite
==================================================
🔧 Setting up test environment...
   📁 Temporary database: /tmp/vex_test_XXXXXX.db
   ✅ Database schema initialized

📥 Testing VEX data import...
   🏃 Running: python import-vex.py test/cve-2022-48632.json --database-url sqlite:///tmp/vex_test_XXXXXX.db
   ✅ Successfully imported 1 CVE(s) and X affected product(s)
✅ Import VEX Data: PASSED

🔍 Testing component queries...
   🏃 Running: python query-vex.py --component kernel --database /tmp/vex_test_XXXXXX.db --count-only
   ✅ Component query successful
✅ Query by Component: PASSED

📄 Testing JSON output format...
   🏃 Running: python query-vex.py --component kernel --database /tmp/vex_test_XXXXXX.db --format json
   ✅ JSON output valid with X records
✅ JSON Output: PASSED

📊 Testing CSV output format...
   🏃 Running: python query-vex.py --component kernel --database /tmp/vex_test_XXXXXX.db --format csv
   ✅ CSV output valid with X lines
✅ CSV Output: PASSED

🔧 Testing query filters...
   🏃 Running: python query-vex.py --component kernel --year 2024 --database /tmp/vex_test_XXXXXX.db --count-only
   🏃 Running: python query-vex.py --component kernel --exact --database /tmp/vex_test_XXXXXX.db --count-only
   ✅ Query filters working
✅ Query Filters: PASSED

⚠️  Testing validation and error handling...
   🏃 Running: python query-vex.py --component kernel --product RHEL --cpe cpe:test --database /tmp/vex_test_XXXXXX.db
   ✅ Validation errors handled correctly
✅ Validation Errors: PASSED

   🗑️  Cleaned up temporary database: /tmp/vex_test_XXXXXX.db
==================================================
🏁 Test Results: 6 passed, 0 failed
🎉 All tests passed!
```

## Test Requirements

- Python 3.6+
- All dependencies from `requirements.txt` installed
- `import-vex.py` and `query-vex.py` scripts in parent directory
- `vex-db.sql` schema file in parent directory

## Troubleshooting

If tests fail:

1. **Import Errors**: Check that `import-vex.py` works standalone
2. **Query Errors**: Check that `query-vex.py` works standalone  
3. **Schema Errors**: Ensure `vex-db.sql` exists in parent directory
4. **Permission Errors**: Check write permissions for temporary files

## Adding New Tests

To add new test cases:

1. Add a new test method to the `VexTestSuite` class
2. Add the test to the `tests` list in `run_all_tests()`
3. Follow the existing pattern of returning `True` for success, `False` for failure 