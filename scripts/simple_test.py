#!/usr/bin/env python3
"""
Simple test script for Network IDS - standalone version
"""

import json
import re
import random
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# Simple signature class
@dataclass
class SimpleSignature:
    signature_id: str
    name: str
    protocol: str
    destination_port: Optional[int]
    payload_pattern: str
    severity: str
    
    def matches_traffic(self, packet_data: Dict[str, Any]) -> bool:
        """Check if this signature matches the given packet data"""
        try:
            # Check protocol
            if self.protocol.upper() != packet_data.get('protocol', '').upper():
                return False
            
            # Check destination port
            if self.destination_port and packet_data.get('dst_port') != self.destination_port:
                return False
            
            # Check payload pattern
            payload = packet_data.get('payload', '')
            if self.payload_pattern and payload:
                pattern = re.compile(self.payload_pattern, re.IGNORECASE)
                return bool(pattern.search(payload))
            
            return True
            
        except Exception as e:
            print(f"Error matching signature {self.signature_id}: {e}")
            return False

# Simple IDS class
class SimpleIDS:
    def __init__(self):
        self.signatures = []
        self.alerts = []
        self.create_default_signatures()
    
    def create_default_signatures(self):
        """Create default attack signatures"""
        self.signatures = [
            SimpleSignature("SQLI-001", "SQL Injection", "TCP", 80, r".*(SELECT|UNION|INSERT|DROP).*", "High"),
            SimpleSignature("XSS-001", "Cross-Site Scripting", "TCP", 80, r".*<script.*>.*</script>.*", "Medium"),
            SimpleSignature("BRUTE-001", "SSH Brute Force", "TCP", 22, r".*", "High"),
            SimpleSignature("MALWARE-001", "Malware Communication", "TCP", 443, r".*(cmd\.exe|powershell).*", "Critical")
        ]
        print(f"Loaded {len(self.signatures)} signatures")
    
    def detect_intrusions(self, packet_data: Dict[str, Any]) -> List[str]:
        """Detect intrusions in a packet"""
        alerts = []
        
        for signature in self.signatures:
            if signature.matches_traffic(packet_data):
                alert = f"ALERT: {signature.name} detected from {packet_data.get('src_ip', 'Unknown')} (Severity: {signature.severity})"
                alerts.append(alert)
                self.alerts.append({
                    'signature': signature.name,
                    'severity': signature.severity,
                    'src_ip': packet_data.get('src_ip'),
                    'dst_ip': packet_data.get('dst_ip'),
                    'timestamp': datetime.now().isoformat()
                })
        
        return alerts
    
    def generate_sample_traffic(self, num_packets: int = 100) -> List[Dict[str, Any]]:
        """Generate sample network traffic"""
        sample_ips = ['192.168.1.10', '192.168.1.20', '10.0.0.5', '172.16.0.100']
        protocols = ['TCP', 'UDP']
        ports = [80, 443, 22, 21, 25]
        
        malicious_payloads = [
            "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
            "<script>alert('XSS')</script>",
            "cmd.exe /c whoami",
            "powershell -enc encoded_command"
        ]
        
        benign_payloads = [
            "GET / HTTP/1.1\r\nHost: example.com",
            "POST /login HTTP/1.1",
            "HTTP/1.1 200 OK",
            "SSH-2.0-OpenSSH_7.4"
        ]
        
        packets = []
        for i in range(num_packets):
            is_malicious = random.random() < 0.2  # 20% malicious
            
            packet = {
                'packet_id': i,
                'src_ip': random.choice(sample_ips),
                'dst_ip': random.choice(sample_ips),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice(ports),
                'protocol': random.choice(protocols),
                'payload': random.choice(malicious_payloads if is_malicious else benign_payloads),
                'timestamp': datetime.now().isoformat(),
                'is_malicious': is_malicious
            }
            packets.append(packet)
        
        return packets
    
    def run_detection(self, packets: List[Dict[str, Any]]):
        """Run detection on a list of packets"""
        print(f"Processing {len(packets)} packets...")
        
        total_alerts = 0
        for packet in packets:
            alerts = self.detect_intrusions(packet)
            total_alerts += len(alerts)
            
            # Print first few alerts
            if alerts and total_alerts <= 5:
                for alert in alerts:
                    print(alert)
        
        print(f"\nDetection complete!")
        print(f"Total packets processed: {len(packets)}")
        print(f"Total alerts generated: {total_alerts}")
        
        # Calculate basic metrics
        malicious_packets = sum(1 for p in packets if p.get('is_malicious', False))
        detected_packets = len(self.alerts)
        
        print(f"Malicious packets in dataset: {malicious_packets}")
        print(f"Packets that triggered alerts: {detected_packets}")
        
        if malicious_packets > 0:
            detection_rate = detected_packets / malicious_packets
            print(f"Detection rate: {detection_rate:.2%}")
    
    def print_alert_summary(self):
        """Print summary of alerts"""
        if not self.alerts:
            print("No alerts generated.")
            return
        
        print(f"\n=== ALERT SUMMARY ===")
        print(f"Total alerts: {len(self.alerts)}")
        
        # Count by severity
        severity_counts = {}
        for alert in self.alerts:
            severity = alert['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("Alerts by severity:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")
        
        # Show recent alerts
        print(f"\nRecent alerts:")
        for alert in self.alerts[-3:]:
            print(f"  {alert['signature']} from {alert['src_ip']} ({alert['severity']})")

def main():
    print("="*50)
    print("SIMPLE NETWORK IDS TEST")
    print("="*50)
    
    # Initialize IDS
    ids = SimpleIDS()
    
    # Generate sample traffic
    print("\nGenerating sample network traffic...")
    packets = ids.generate_sample_traffic(50)
    
    # Run detection
    print("\nRunning intrusion detection...")
    ids.run_detection(packets)
    
    # Print summary
    ids.print_alert_summary()
    
    print("\n" + "="*50)
    print("TEST COMPLETE")
    print("="*50)

if __name__ == "__main__":
    main()
