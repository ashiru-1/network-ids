#!/usr/bin/env python3
"""
Demo script showcasing Network IDS capabilities
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from network_ids import NetworkIDS
import time

def run_demo():
    print("="*60)
    print("NETWORK IDS DEMONSTRATION")
    print("="*60)
    
    # Initialize IDS
    print("\n1. Initializing Network IDS...")
    ids = NetworkIDS()
    
    # Show loaded signatures
    print("\n2. Loaded Attack Signatures:")
    for sig in ids.signature_manager.list_signatures():
        print(f"   - {sig.signature_id}: {sig.name} ({sig.severity})")
    
    # Add custom signature
    print("\n3. Adding Custom Signature...")
    ids.add_custom_signature(
        signature_id="DEMO-001",
        name="Demo Malware Communication",
        protocol="TCP",
        destination_port=8080,
        payload_pattern=r".*MALWARE_BEACON.*",
        severity="Critical",
        description="Demo signature for malware communication"
    )
    
    # Run small simulation
    print("\n4. Running Detection Simulation (100 packets)...")
    alerts = ids.run_simulation(100)
    
    # Show some alerts
    print(f"\n5. Detection Results: {len(alerts)} alerts generated")
    if alerts:
        print("\nSample Alerts:")
        for alert in alerts[:3]:  # Show first 3 alerts
            print(f"   - {alert.signature_name}: {alert.src_ip} -> {alert.dst_ip} ({alert.severity})")
    
    # Show metrics
    print("\n6. Performance Metrics:")
    metrics = ids.evaluator.calculate_metrics()
    print(f"   - Accuracy: {metrics.get('accuracy', 0):.2%}")
    print(f"   - Precision: {metrics.get('precision', 0):.2%}")
    print(f"   - Recall: {metrics.get('recall', 0):.2%}")
    print(f"   - F1 Score: {metrics.get('f1_score', 0):.3f}")
    
    # Test with specific malicious payload
    print("\n7. Testing Specific Attack Detection...")
    test_packet = {
        'packet_id': 999,
        'src_ip': '192.168.1.100',
        'dst_ip': '192.168.1.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'payload': "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
        'is_malicious': True
    }
    
    test_alerts = ids.detect_intrusions(test_packet)
    if test_alerts:
        print(f"   ✓ Detected: {test_alerts[0].signature_name}")
    else:
        print("   ✗ No detection")
    
    print("\n8. Final System Status:")
    ids.print_system_status()
    
    print("\n" + "="*60)
    print("DEMONSTRATION COMPLETE")
    print("="*60)
    print("\nFiles generated:")
    print("- signatures.json (attack signatures)")
    print("- alerts.json (detection alerts)")
    print("- evaluation_results.json (performance metrics)")

if __name__ == "__main__":
    run_demo()
