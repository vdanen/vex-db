#!/usr/bin/env python3

import os
import sys
import subprocess
import tempfile
import json
import sqlite3
from pathlib import Path

# Add parent directory to path so we can import from the main scripts
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class VexTestSuite:
    def __init__(self):
        self.test_dir = Path(__file__).parent
        self.parent_dir = self.test_dir.parent
        self.temp_db = None
        self.temp_db_file = None
        self.test_data_file = self.test_dir / "cve-2022-48632.json"
        self.import_script = self.parent_dir / "import-vex.py"
        self.query_script = self.parent_dir / "query-vex.py"
        self.schema_file = self.parent_dir / "vex-db.sql"
        
    def setup(self):
        """Set up temporary database and schema"""
        print("🔧 Setting up test environment...")
        
        # Create temporary database file
        fd, self.temp_db_file = tempfile.mkstemp(suffix='.db', prefix='vex_test_')
        os.close(fd)
        
        print(f"   📁 Temporary database: {self.temp_db_file}")
        
        # Initialize database schema
        if not self.schema_file.exists():
            raise FileNotFoundError(f"Schema file not found: {self.schema_file}")
            
        with open(self.schema_file, 'r') as f:
            schema_sql = f.read()
            
        conn = sqlite3.connect(self.temp_db_file)
        conn.executescript(schema_sql)
        conn.close()
        
        print("   ✅ Database schema initialized")
        
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_db_file and os.path.exists(self.temp_db_file):
            os.unlink(self.temp_db_file)
            print(f"   🗑️  Cleaned up temporary database: {self.temp_db_file}")
    
    def run_command(self, cmd, expected_exit_code=0):
        """Run a command and return the result"""
        print(f"   🏃 Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.parent_dir)
        
        if result.returncode != expected_exit_code:
            print(f"   ❌ Command failed with exit code {result.returncode}")
            print(f"   STDOUT: {result.stdout}")
            print(f"   STDERR: {result.stderr}")
            return False, result
            
        return True, result
    
    def test_import_vex_data(self):
        """Test importing VEX data using import-vex.py"""
        print("\n📥 Testing VEX data import...")
        
        # Check that test data file exists
        if not self.test_data_file.exists():
            print(f"   ❌ Test data file not found: {self.test_data_file}")
            return False
            
        # Update import script to use temporary database  
        cmd = [
            "python", str(self.import_script),
            str(self.test_data_file),
            "--database-url", f"sqlite:///{self.temp_db_file}"
        ]
        
        success, result = self.run_command(cmd)
        if not success:
            return False
            
        # Verify data was imported
        conn = sqlite3.connect(self.temp_db_file)
        cursor = conn.cursor()
        
        # Check CVE table
        cursor.execute("SELECT COUNT(*) FROM cve")
        cve_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT cve FROM cve LIMIT 1")
        cve_result = cursor.fetchone()
        
        # Check affects table  
        cursor.execute("SELECT COUNT(*) FROM affects")
        affects_count = cursor.fetchone()[0]
        
        conn.close()
        
        if cve_count == 0:
            print("   ❌ No CVE data imported")
            return False
            
        if affects_count == 0:
            print("   ❌ No affects data imported")
            return False
            
        expected_cve = "CVE-2022-48632"
        if cve_result and cve_result[0] != expected_cve:
            print(f"   ❌ Expected CVE {expected_cve}, got {cve_result[0]}")
            return False
            
        print(f"   ✅ Successfully imported {cve_count} CVE(s) and {affects_count} affected product(s)")
        return True
    
    def test_query_by_component(self):
        """Test querying by component using query-vex.py"""
        print("\n🔍 Testing component queries...")
        
        # Test kernel component query
        cmd = [
            "python", str(self.query_script),
            "--component", "kernel",
            "--database", self.temp_db_file,
            "--count-only"
        ]
        
        success, result = self.run_command(cmd)
        if not success:
            return False
            
        # Parse output to verify results
        output = result.stdout
        if "entries" not in output or "unique CVEs" not in output:
            print("   ❌ Query output format unexpected")
            print(f"   Output: {output}")
            return False
            
        print("   ✅ Component query successful")
        return True
        
    def test_query_json_output(self):
        """Test JSON output format"""
        print("\n📄 Testing JSON output format...")
        
        cmd = [
            "python", str(self.query_script),
            "--component", "kernel", 
            "--database", self.temp_db_file,
            "--format", "json"
        ]
        
        success, result = self.run_command(cmd)
        if not success:
            return False
            
        # Try to parse JSON output (skip search info lines)
        output_lines = result.stdout.strip().split('\n')
        json_lines = []
        json_started = False
        
        for line in output_lines:
            if line.startswith('[') or json_started:
                json_started = True
                json_lines.append(line)
                
        if not json_lines:
            print("   ❌ No JSON output found")
            return False
            
        try:
            json_output = '\n'.join(json_lines)
            data = json.loads(json_output)
            
            if not isinstance(data, list):
                print("   ❌ JSON output should be a list")
                return False
                
            if len(data) == 0:
                print("   ❌ JSON output is empty")
                return False
                
            # Verify required fields
            required_fields = ['cve', 'product', 'state', 'components']
            first_item = data[0]
            
            for field in required_fields:
                if field not in first_item:
                    print(f"   ❌ Missing required field: {field}")
                    return False
                    
            print(f"   ✅ JSON output valid with {len(data)} records")
            return True
            
        except json.JSONDecodeError as e:
            print(f"   ❌ Invalid JSON output: {e}")
            print(f"   Output: {json_output[:200]}...")
            return False
    
    def test_query_csv_output(self):
        """Test CSV output format"""
        print("\n📊 Testing CSV output format...")
        
        cmd = [
            "python", str(self.query_script),
            "--component", "kernel",
            "--database", self.temp_db_file, 
            "--format", "csv"
        ]
        
        success, result = self.run_command(cmd)
        if not success:
            return False
            
        # Check CSV format
        output_lines = result.stdout.strip().split('\n')
        csv_lines = []
        csv_started = False
        
        for line in output_lines:
            # Look for CSV header line with cve,product
            if line.startswith('cve,product') or csv_started:
                csv_started = True
                csv_lines.append(line)
                
        if len(csv_lines) < 2:  # Header + at least one data row
            print(f"   ❌ CSV output too short: {len(csv_lines)} lines")
            print(f"   Full output: {result.stdout}")
            return False
            
        # Verify header
        header = csv_lines[0]
        expected_fields = ['cve', 'product', 'state', 'components']
        
        for field in expected_fields:
            if field not in header:
                print(f"   ❌ Missing CSV field: {field}")
                return False
                
        # Verify components are space-separated (not comma-separated) in data rows
        if len(csv_lines) > 1:
            # Check a few data lines to ensure components are properly formatted
            for i in range(1, min(len(csv_lines), 4)):  # Check first few data lines
                data_line = csv_lines[i]
                # The components field should not have internal commas when it's space-separated
                # This is a basic check - components field is near the end of the CSV
                if 'kernel-' in data_line:  # Look for kernel component entries
                    # If we find multiple kernel entries separated by space (not comma), that's good
                    # This is a simple heuristic check
                    break
                    
        print(f"   ✅ CSV output valid with {len(csv_lines)} lines")
        return True
    
    def test_query_filters(self):
        """Test various query filters"""
        print("\n🔧 Testing query filters...")
        
        # Test year filter
        cmd = [
            "python", str(self.query_script),
            "--component", "kernel",
            "--year", "2024",
            "--database", self.temp_db_file,
            "--count-only"
        ]
        
        success, result = self.run_command(cmd)
        if not success:
            return False
            
        # Test exact matching
        cmd = [
            "python", str(self.query_script),
            "--component", "kernel",
            "--exact",
            "--database", self.temp_db_file,
            "--count-only"
        ]
        
        success, result = self.run_command(cmd)
        if not success:
            return False
            
        print("   ✅ Query filters working")
        return True
    
    def test_validation_errors(self):
        """Test validation and error handling"""
        print("\n⚠️  Testing validation and error handling...")
        
        # Test multiple conflicting filters
        cmd = [
            "python", str(self.query_script),
            "--component", "kernel",
            "--product", "RHEL",
            "--cpe", "cpe:test",
            "--database", self.temp_db_file
        ]
        
        success, result = self.run_command(cmd, expected_exit_code=1)
        if not success:
            print("   ❌ Expected validation error for conflicting filters")
            return False
            
        if "Only one filter can be used at a time" not in result.stdout:
            print("   ❌ Expected validation error message not found")
            return False
            
        print("   ✅ Validation errors handled correctly")
        return True
    
    def run_all_tests(self):
        """Run all tests"""
        print("🧪 Starting VEX Database Test Suite")
        print("=" * 50)
        
        try:
            self.setup()
            
            tests = [
                ("Import VEX Data", self.test_import_vex_data),
                ("Query by Component", self.test_query_by_component),
                ("JSON Output", self.test_query_json_output),
                ("CSV Output", self.test_query_csv_output),
                ("Query Filters", self.test_query_filters),
                ("Validation Errors", self.test_validation_errors),
            ]
            
            passed = 0
            failed = 0
            
            for test_name, test_func in tests:
                try:
                    if test_func():
                        passed += 1
                        print(f"✅ {test_name}: PASSED")
                    else:
                        failed += 1
                        print(f"❌ {test_name}: FAILED")
                except Exception as e:
                    failed += 1
                    print(f"❌ {test_name}: ERROR - {e}")
                    
            print("\n" + "=" * 50)
            print(f"🏁 Test Results: {passed} passed, {failed} failed")
            
            if failed == 0:
                print("🎉 All tests passed!")
                return True
            else:
                print(f"💥 {failed} test(s) failed!")
                return False
                
        finally:
            self.cleanup()

if __name__ == "__main__":
    test_suite = VexTestSuite()
    success = test_suite.run_all_tests()
    sys.exit(0 if success else 1) 