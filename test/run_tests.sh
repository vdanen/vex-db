#!/bin/bash

# VEX Database Test Suite Runner
# This script runs the automated test suite for the VEX database project

echo "🧪 VEX Database Test Suite"
echo "=========================="

# Check if we're in the right directory
if [ ! -f "run_tests.py" ]; then
    echo "❌ Error: run_tests.py not found. Please run this script from the test/ directory."
    exit 1
fi

# Check if parent scripts exist
if [ ! -f "../import-vex.py" ] || [ ! -f "../query-vex.py" ] || [ ! -f "../vex-db.sql" ]; then
    echo "❌ Error: Required scripts not found in parent directory."
    echo "   Make sure import-vex.py, query-vex.py, and vex-db.sql exist in the parent directory."
    exit 1
fi

# Check if test data exists
if [ ! -f "cve-2022-48632.json" ]; then
    echo "❌ Error: Test data file cve-2022-48632.json not found."
    exit 1
fi

# Run the tests
echo "🚀 Starting test execution..."
echo ""

python3 run_tests.py
exit_code=$?

echo ""
if [ $exit_code -eq 0 ]; then
    echo "✅ All tests completed successfully!"
else
    echo "❌ Some tests failed. Check the output above for details."
fi

exit $exit_code 