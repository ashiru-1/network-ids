#!/usr/bin/env python3
"""
Test the complete IDS system and generate dashboard data
"""

import sys
import os
import subprocess

def run_ids_and_generate_data():
    """Run the IDS system and generate dashboard data"""
    print("="*60)
    print("TESTING COMPLETE IDS SYSTEM")
    print("="*60)
    
    try:
        # Run the comprehensive test
        print("Running comprehensive IDS test...")
        result = subprocess.run([
            sys.executable, 'complete_ids.py', 'comprehensive'
        ], capture_output=True, text=True, cwd='scripts')
        
        if result.returncode == 0:
            print("✓ IDS test completed successfully!")
            print("\nOutput:")
            print(result.stdout)
            
            # Check if dashboard data was generated
            dashboard_file = os.path.join('scripts', 'dashboard_data.json')
            if os.path.exists(dashboard_file):
                print("✓ Dashboard data generated successfully!")
                
                # Copy dashboard data to main directory for web access
                import shutil
                shutil.copy(dashboard_file, 'dashboard_data.json')
                print("✓ Dashboard data copied for web access")
                
            else:
                print("⚠ Dashboard data file not found")
                
        else:
            print("✗ IDS test failed!")
            print("Error:", result.stderr)
            
    except Exception as e:
        print(f"✗ Error running IDS test: {e}")
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)
    print("\nTo view the dashboard:")
    print("1. Open dashboard.html in your web browser")
    print("2. The dashboard will load data from dashboard_data.json")
    print("3. Use the refresh button to reload data")

if __name__ == "__main__":
    run_ids_and_generate_data()
