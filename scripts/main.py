#!/usr/bin/env python3
"""
Main entry point for the Network IDS
"""

import argparse
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from network_ids import NetworkIDS
from config import *

def main():
    parser = argparse.ArgumentParser(description="Network Intrusion Detection System")
    parser.add_argument("--mode", choices=["simulation", "pcap", "csv"], 
                       default="simulation", help="Analysis mode")
    parser.add_argument("--input", help="Input file (for pcap/csv modes)")
    parser.add_argument("--packets", type=int, default=DEFAULT_SIMULATION_PACKETS,
                       help="Number of packets for simulation mode")
    parser.add_argument("--signatures", default=SIGNATURE_FILE,
                       help="Signature file path")
    parser.add_argument("--alerts", default=ALERT_FILE,
                       help="Alert file path")
    parser.add_argument("--report", action="store_true",
                       help="Generate detailed report")
    parser.add_argument("--quiet", action="store_true",
                       help="Suppress verbose output")
    
    args = parser.parse_args()
    
    # Initialize IDS
    try:
        ids = NetworkIDS(args.signatures, args.alerts)
    except Exception as e:
        print(f"Error initializing IDS: {e}")
        sys.exit(1)
    
    # Run analysis based on mode
    alerts = []
    
    try:
        if args.mode == "simulation":
            if not args.quiet:
                print(f"Running simulation with {args.packets} packets...")
            alerts = ids.run_simulation(args.packets)
            
        elif args.mode == "pcap":
            if not args.input:
                print("Error: --input required for pcap mode")
                sys.exit(1)
            if not os.path.exists(args.input):
                print(f"Error: File {args.input} not found")
                sys.exit(1)
            alerts = ids.analyze_pcap_file(args.input)
            
        elif args.mode == "csv":
            if not args.input:
                print("Error: --input required for csv mode")
                sys.exit(1)
            if not os.path.exists(args.input):
                print(f"Error: File {args.input} not found")
                sys.exit(1)
            alerts = ids.analyze_csv_file(args.input)
    
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)
    
    # Print results
    if not args.quiet:
        print(f"\nAnalysis complete!")
        print(f"Alerts generated: {len(alerts)}")
        
        if args.report:
            ids.generate_report()
        else:
            ids.print_system_status()
            ids.alert_manager.print_alert_summary()
    
    print(f"\nResults saved to:")
    print(f"  Alerts: {args.alerts}")
    print(f"  Evaluation: {EVALUATION_FILE}")

if __name__ == "__main__":
    main()
