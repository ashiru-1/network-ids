#!/usr/bin/env python3
"""
Complete Network Intrusion Detection System - All-in-one version
No external module dependencies between files
"""

import json
import re
import random
import time
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

# ============================================================================
# SIGNATURE MANAGEMENT
# ============================================================================

@dataclass
class Signature:
    signature_id: str
    name: str
    protocol: str
    destination_port: Optional[int]
    source_port: Optional[int]
    payload_pattern: str
    severity: str
    description: str = ""
    
    def matches_traffic(self, packet_data: Dict[str, Any]) -> bool:
        """Check if this signature matches the given packet data"""
        try:
            # Check protocol
            if self.protocol.upper() != packet_data.get('protocol', '').upper():
                return False
            
            # Check destination port
            if self.destination_port and packet_data.get('dst_port') != self.destination_port:
                return False
            
            # Check source port
            if self.source_port and packet_data.get('src_port') != self.source_port:
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

class SignatureManager:
    def __init__(self, signature_file: str = "signatures.json"):
        self.signature_file = signature_file
        self.signatures: Dict[str, Signature] = {}
        self.load_signatures()
    
    def load_signatures(self):
        """Load signatures from file"""
        try:
            with open(self.signature_file, 'r') as f:
                data = json.load(f)
            
            for sig_data in data.get('signatures', []):
                signature = Signature(**sig_data)
                self.signatures[signature.signature_id] = signature
            
            print(f"Loaded {len(self.signatures)} signatures")
            
        except FileNotFoundError:
            print(f"Signature file {self.signature_file} not found. Creating default signatures.")
            self.create_default_signatures()
        except Exception as e:
            print(f"Error loading signatures: {e}")
            self.create_default_signatures()
    
    def create_default_signatures(self):
        """Create default attack signatures"""
        default_signatures = [
            {
                "signature_id": "SQLI-001",
                "name": "SQL Injection Attempt",
                "protocol": "TCP",
                "destination_port": 80,
                "source_port": None,
                "payload_pattern": r".*(SELECT|UNION|INSERT|DROP|DELETE).*",
                "severity": "High",
                "description": "Detects SQL injection attempts in HTTP traffic"
            },
            {
                "signature_id": "XSS-001",
                "name": "Cross-Site Scripting Attempt",
                "protocol": "TCP",
                "destination_port": 80,
                "source_port": None,
                "payload_pattern": r".*<script.*>.*</script>.*",
                "severity": "Medium",
                "description": "Detects XSS attempts in HTTP traffic"
            },
            {
                "signature_id": "BRUTE-001",
                "name": "SSH Brute Force",
                "protocol": "TCP",
                "destination_port": 22,
                "source_port": None,
                "payload_pattern": r".*",
                "severity": "High",
                "description": "Detects potential SSH brute force attacks"
            },
            {
                "signature_id": "SCAN-001",
                "name": "Port Scan Detection",
                "protocol": "TCP",
                "destination_port": None,
                "source_port": None,
                "payload_pattern": r"",
                "severity": "Medium",
                "description": "Detects port scanning activities"
            },
            {
                "signature_id": "MALWARE-001",
                "name": "Malware Communication",
                "protocol": "TCP",
                "destination_port": 443,
                "source_port": None,
                "payload_pattern": r".*(cmd\.exe|powershell|/bin/sh).*",
                "severity": "Critical",
                "description": "Detects potential malware command execution"
            }
        ]
        
        for sig_data in default_signatures:
            signature = Signature(**sig_data)
            self.signatures[signature.signature_id] = signature
        
        self.save_signatures()
    
    def save_signatures(self):
        """Save signatures to file"""
        try:
            signatures_data = {
                "signatures": [
                    {
                        "signature_id": sig.signature_id,
                        "name": sig.name,
                        "protocol": sig.protocol,
                        "destination_port": sig.destination_port,
                        "source_port": sig.source_port,
                        "payload_pattern": sig.payload_pattern,
                        "severity": sig.severity,
                        "description": sig.description
                    }
                    for sig in self.signatures.values()
                ]
            }
            
            with open(self.signature_file, 'w') as f:
                json.dump(signatures_data, f, indent=2)
            
            print(f"Saved {len(self.signatures)} signatures to {self.signature_file}")
            
        except Exception as e:
            print(f"Error saving signatures: {e}")
    
    def add_signature(self, signature: Signature):
        """Add a new signature"""
        self.signatures[signature.signature_id] = signature
        self.save_signatures()
    
    def list_signatures(self) -> List[Signature]:
        """Get all signatures"""
        return list(self.signatures.values())

# ============================================================================
# TRAFFIC ANALYSIS
# ============================================================================

class TrafficAnalyzer:
    def __init__(self):
        self.packet_features = []
    
    def analyze_csv(self, csv_file: str) -> List[Dict[str, Any]]:
        """Analyze network traffic data from CSV file"""
        print(f"Analyzing CSV file: {csv_file}")
        
        try:
            df = pd.read_csv(csv_file)
            print(f"Found {len(df)} records")
            
            packet_features = []
            for index, row in df.iterrows():
                features = {
                    'packet_id': index,
                    'timestamp': row.get('timestamp', datetime.now().isoformat()),
                    'src_ip': row.get('src_ip', ''),
                    'dst_ip': row.get('dst_ip', ''),
                    'src_port': row.get('src_port', 0),
                    'dst_port': row.get('dst_port', 0),
                    'protocol': row.get('protocol', ''),
                    'payload': row.get('payload', ''),
                    'packet_size': row.get('packet_size', 0)
                }
                packet_features.append(features)
            
            print(f"Processed {len(packet_features)} records")
            return packet_features
            
        except Exception as e:
            print(f"Error analyzing CSV file: {e}")
            return []
    
    def generate_sample_data(self, num_packets: int = 1000) -> List[Dict[str, Any]]:
        """Generate sample network traffic data for testing"""
        print(f"Generating {num_packets} sample packets...")
        
        sample_ips = ['192.168.1.10', '192.168.1.20', '10.0.0.5', '172.16.0.100', '8.8.8.8']
        protocols = ['TCP', 'UDP', 'ICMP']
        common_ports = [80, 443, 22, 21, 25, 53, 3389]
        
        # Malicious payloads for testing
        malicious_payloads = [
            "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
            "<script>alert('XSS')</script>",
            "cmd.exe /c whoami",
            "powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0",
            "/bin/sh -c 'cat /etc/passwd'",
            "' OR '1'='1",
            "<iframe src='javascript:alert(1)'></iframe>"
        ]
        
        benign_payloads = [
            "GET / HTTP/1.1\r\nHost: example.com",
            "POST /login HTTP/1.1\r\nContent-Type: application/json",
            "HTTP/1.1 200 OK\r\nContent-Type: text/html",
            "SSH-2.0-OpenSSH_7.4",
            "220 FTP server ready"
        ]
        
        packet_features = []
        
        for i in range(num_packets):
            # 15% chance of malicious traffic
            is_malicious = random.random() < 0.15
            
            features = {
                'packet_id': i,
                'timestamp': datetime.now().isoformat(),
                'src_ip': random.choice(sample_ips),
                'dst_ip': random.choice(sample_ips),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice(common_ports),
                'protocol': random.choice(protocols),
                'payload': random.choice(malicious_payloads if is_malicious else benign_payloads),
                'packet_size': random.randint(64, 1500),
                'is_malicious': is_malicious  # Ground truth for evaluation
            }
            
            packet_features.append(features)
        
        malicious_count = sum(1 for p in packet_features if p.get('is_malicious', False))
        print(f"Generated {num_packets} sample packets ({malicious_count} malicious)")
        return packet_features

# ============================================================================
# ALERT MANAGEMENT
# ============================================================================

@dataclass
class Alert:
    alert_id: str
    signature_id: str
    signature_name: str
    severity: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    timestamp: str
    description: str = ""
    payload_snippet: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class AlertManager:
    def __init__(self, alert_file: str = "alerts.json"):
        self.alert_file = alert_file
        self.alerts: List[Alert] = []
        self.alert_counter = 0
    
    def create_alert(self, signature_id: str, signature_name: str, severity: str,
                    packet_data: Dict[str, Any]) -> Alert:
        """Create a new alert"""
        self.alert_counter += 1
        
        alert = Alert(
            alert_id=f"ALERT-{self.alert_counter:06d}",
            signature_id=signature_id,
            signature_name=signature_name,
            severity=severity,
            src_ip=packet_data.get('src_ip', 'Unknown'),
            dst_ip=packet_data.get('dst_ip', 'Unknown'),
            src_port=packet_data.get('src_port', 0),
            dst_port=packet_data.get('dst_port', 0),
            protocol=packet_data.get('protocol', 'Unknown'),
            timestamp=packet_data.get('timestamp', datetime.now().isoformat()),
            payload_snippet=packet_data.get('payload', '')[:100]  # First 100 chars
        )
        
        self.alerts.append(alert)
        return alert
    
    def save_alerts(self):
        """Save alerts to file"""
        try:
            alerts_data = {
                "alerts": [alert.to_dict() for alert in self.alerts],
                "total_alerts": len(self.alerts),
                "last_updated": datetime.now().isoformat()
            }
            
            with open(self.alert_file, 'w') as f:
                json.dump(alerts_data, f, indent=2)
            
        except Exception as e:
            print(f"Error saving alerts: {e}")
    
    def print_alert_summary(self):
        """Print a summary of all alerts"""
        if not self.alerts:
            print("No alerts generated.")
            return
        
        print(f"\n=== ALERT SUMMARY ===")
        print(f"Total Alerts: {len(self.alerts)}")
        
        # Count by severity
        severity_counts = {}
        for alert in self.alerts:
            severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
        
        print("\nAlerts by Severity:")
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity}: {count}")
        
        # Top source IPs
        src_ip_counts = {}
        for alert in self.alerts:
            src_ip_counts[alert.src_ip] = src_ip_counts.get(alert.src_ip, 0) + 1
        
        print("\nTop Source IPs:")
        for ip, count in sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count} alerts")
    
    def print_detailed_alerts(self, limit: int = 10):
        """Print detailed information for recent alerts"""
        recent_alerts = self.alerts[-limit:] if len(self.alerts) > limit else self.alerts
        
        print(f"\n=== DETAILED ALERTS (Last {len(recent_alerts)}) ===")
        for alert in recent_alerts:
            print(f"\nAlert ID: {alert.alert_id}")
            print(f"Signature: {alert.signature_name} ({alert.signature_id})")
            print(f"Severity: {alert.severity}")
            print(f"Source: {alert.src_ip}:{alert.src_port}")
            print(f"Destination: {alert.dst_ip}:{alert.dst_port}")
            print(f"Protocol: {alert.protocol}")
            print(f"Timestamp: {alert.timestamp}")
            if alert.payload_snippet:
                print(f"Payload: {alert.payload_snippet}...")
            print("-" * 50)

# ============================================================================
# EVALUATION METRICS
# ============================================================================

class EvaluationMetrics:
    def __init__(self):
        self.reset_metrics()
    
    def reset_metrics(self):
        """Reset all metrics"""
        self.true_positives = 0
        self.true_negatives = 0
        self.false_positives = 0
        self.false_negatives = 0
        self.total_packets = 0
        self.detection_results = []
    
    def add_detection_result(self, packet_data: Dict[str, Any], detected: bool, 
                           signature_matched: str = None):
        """Add a detection result for evaluation"""
        is_actually_malicious = packet_data.get('is_malicious', False)
        
        result = {
            'packet_id': packet_data.get('packet_id', 0),
            'timestamp': packet_data.get('timestamp', datetime.now().isoformat()),
            'src_ip': packet_data.get('src_ip', ''),
            'dst_ip': packet_data.get('dst_ip', ''),
            'protocol': packet_data.get('protocol', ''),
            'actually_malicious': is_actually_malicious,
            'detected_as_malicious': detected,
            'signature_matched': signature_matched,
            'payload_snippet': packet_data.get('payload', '')[:50]
        }
        
        self.detection_results.append(result)
        self.total_packets += 1
        
        # Update confusion matrix
        if is_actually_malicious and detected:
            self.true_positives += 1
        elif not is_actually_malicious and not detected:
            self.true_negatives += 1
        elif not is_actually_malicious and detected:
            self.false_positives += 1
        elif is_actually_malicious and not detected:
            self.false_negatives += 1
    
    def calculate_metrics(self) -> Dict[str, float]:
        """Calculate all evaluation metrics"""
        metrics = {}
        
        # Basic counts
        metrics['total_packets'] = self.total_packets
        metrics['true_positives'] = self.true_positives
        metrics['true_negatives'] = self.true_negatives
        metrics['false_positives'] = self.false_positives
        metrics['false_negatives'] = self.false_negatives
        
        # Avoid division by zero
        if self.total_packets == 0:
            return metrics
        
        # Accuracy
        metrics['accuracy'] = (self.true_positives + self.true_negatives) / self.total_packets
        
        # Precision
        if (self.true_positives + self.false_positives) > 0:
            metrics['precision'] = self.true_positives / (self.true_positives + self.false_positives)
        else:
            metrics['precision'] = 0.0
        
        # Recall (Sensitivity)
        if (self.true_positives + self.false_negatives) > 0:
            metrics['recall'] = self.true_positives / (self.true_positives + self.false_negatives)
        else:
            metrics['recall'] = 0.0
        
        # F1 Score
        if (metrics['precision'] + metrics['recall']) > 0:
            metrics['f1_score'] = 2 * (metrics['precision'] * metrics['recall']) / (metrics['precision'] + metrics['recall'])
        else:
            metrics['f1_score'] = 0.0
        
        # False Positive Rate
        if (self.false_positives + self.true_negatives) > 0:
            metrics['false_positive_rate'] = self.false_positives / (self.false_positives + self.true_negatives)
        else:
            metrics['false_positive_rate'] = 0.0
        
        return metrics
    
    def print_confusion_matrix(self):
        """Print confusion matrix"""
        print("\n=== CONFUSION MATRIX ===")
        print("                 Predicted")
        print("                Pos    Neg")
        print(f"Actual Pos    {self.true_positives:4d}   {self.false_negatives:4d}")
        print(f"       Neg    {self.false_positives:4d}   {self.true_negatives:4d}")
    
    def print_metrics_report(self):
        """Print comprehensive metrics report"""
        metrics = self.calculate_metrics()
        
        print("\n=== EVALUATION METRICS REPORT ===")
        print(f"Total Packets Analyzed: {metrics['total_packets']}")
        print(f"True Positives:  {metrics['true_positives']}")
        print(f"True Negatives:  {metrics['true_negatives']}")
        print(f"False Positives: {metrics['false_positives']}")
        print(f"False Negatives: {metrics['false_negatives']}")
        
        self.print_confusion_matrix()
        
        print(f"\n=== PERFORMANCE METRICS ===")
        print(f"Accuracy:              {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        print(f"Precision:             {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
        print(f"Recall (Sensitivity):  {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
        print(f"F1 Score:              {metrics['f1_score']:.4f}")
        print(f"False Positive Rate:   {metrics['false_positive_rate']:.4f} ({metrics['false_positive_rate']*100:.2f}%)")
    
    def save_results(self, filename: str = "evaluation_results.json"):
        """Save evaluation results to file"""
        results = {
            'metrics': self.calculate_metrics(),
            'detection_results': self.detection_results,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Evaluation results saved to {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")

# ============================================================================
# MAIN NETWORK IDS CLASS
# ============================================================================

class NetworkIDS:
    def __init__(self, signature_file: str = "signatures.json", 
                 alert_file: str = "alerts.json"):
        """Initialize the Network IDS"""
        print("Initializing Network IDS...")
        
        self.signature_manager = SignatureManager(signature_file)
        self.traffic_analyzer = TrafficAnalyzer()
        self.alert_manager = AlertManager(alert_file)
        self.evaluator = EvaluationMetrics()
        
        self.total_packets_processed = 0
        self.total_alerts_generated = 0
        self.start_time = None
        
        print("Network IDS initialized successfully!")
    
    def detect_intrusions(self, packet_data: Dict[str, Any]) -> List[Alert]:
        """Detect intrusions in a single packet"""
        alerts = []
        detected = False
        matched_signature = None
        
        # Check packet against all signatures
        for signature in self.signature_manager.list_signatures():
            if signature.matches_traffic(packet_data):
                # Create alert
                alert = self.alert_manager.create_alert(
                    signature.signature_id,
                    signature.name,
                    signature.severity,
                    packet_data
                )
                alerts.append(alert)
                detected = True
                matched_signature = signature.signature_id
                
                print(f"ALERT: {signature.name} detected from {packet_data.get('src_ip', 'Unknown')}")
        
        # Record detection result for evaluation
        self.evaluator.add_detection_result(packet_data, detected, matched_signature)
        
        return alerts
    
    def process_traffic_batch(self, traffic_data: List[Dict[str, Any]]) -> List[Alert]:
        """Process a batch of network traffic data"""
        print(f"Processing {len(traffic_data)} packets...")
        
        all_alerts = []
        self.start_time = time.time()
        
        for i, packet_data in enumerate(traffic_data):
            alerts = self.detect_intrusions(packet_data)
            all_alerts.extend(alerts)
            self.total_packets_processed += 1
            
            # Progress indicator
            if (i + 1) % 100 == 0:
                print(f"Processed {i + 1}/{len(traffic_data)} packets...")
        
        self.total_alerts_generated += len(all_alerts)
        
        processing_time = time.time() - self.start_time
        print(f"Processing complete: {len(all_alerts)} alerts generated in {processing_time:.2f} seconds")
        
        return all_alerts
    
    def run_simulation(self, num_packets: int = 1000) -> List[Alert]:
        """Run IDS simulation with generated traffic data"""
        print(f"Running IDS simulation with {num_packets} packets...")
        
        # Generate sample traffic data
        traffic_data = self.traffic_analyzer.generate_sample_data(num_packets)
        
        # Process traffic for intrusions
        return self.process_traffic_batch(traffic_data)
    
    def add_custom_signature(self, signature_id: str, name: str, protocol: str,
                           destination_port: Optional[int], payload_pattern: str,
                           severity: str, description: str = ""):
        """Add a custom signature to the IDS"""
        signature = Signature(
            signature_id=signature_id,
            name=name,
            protocol=protocol,
            destination_port=destination_port,
            source_port=None,
            payload_pattern=payload_pattern,
            severity=severity,
            description=description
        )
        
        self.signature_manager.add_signature(signature)
        print(f"Added custom signature: {signature_id} - {name}")
    
    def print_system_status(self):
        """Print current system status"""
        print("\n=== NETWORK IDS STATUS ===")
        print(f"Signatures Loaded: {len(self.signature_manager.list_signatures())}")
        print(f"Total Packets Processed: {self.total_packets_processed}")
        print(f"Total Alerts Generated: {self.total_alerts_generated}")
        
        if self.start_time:
            processing_time = time.time() - self.start_time
            if processing_time > 0:
                pps = self.total_packets_processed / processing_time
                print(f"Processing Rate: {pps:.2f} packets/second")
        
        print(f"Alert Manager: {len(self.alert_manager.alerts)} total alerts")
    
    def generate_report(self):
        """Generate comprehensive IDS report"""
        print("\n" + "="*60)
        print("NETWORK IDS COMPREHENSIVE REPORT")
        print("="*60)
        print(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # System status
        self.print_system_status()
        
        # Alert summary
        self.alert_manager.print_alert_summary()
        
        # Detailed alerts
        self.alert_manager.print_detailed_alerts(5)
        
        # Evaluation metrics
        self.evaluator.print_metrics_report()
        
        # Save results
        self.alert_manager.save_alerts()
        self.evaluator.save_results()
        
        print("\n" + "="*60)
        print("REPORT COMPLETE")
        print("="*60)
    
    def export_dashboard_data(self):
        """Export data for web dashboard"""
        dashboard_data = {
            'system_status': {
                'signatures_loaded': len(self.signature_manager.list_signatures()),
                'packets_processed': self.total_packets_processed,
                'alerts_generated': self.total_alerts_generated,
                'processing_rate': 0
            },
            'alerts': [alert.to_dict() for alert in self.alert_manager.alerts],
            'metrics': self.evaluator.calculate_metrics(),
            'signatures': [
                {
                    'signature_id': sig.signature_id,
                    'name': sig.name,
                    'severity': sig.severity,
                    'protocol': sig.protocol,
                    'description': sig.description
                }
                for sig in self.signature_manager.list_signatures()
            ],
            'timestamp': datetime.now().isoformat()
        }
        
        # Calculate processing rate
        if self.start_time:
            processing_time = time.time() - self.start_time
            if processing_time > 0:
                dashboard_data['system_status']['processing_rate'] = self.total_packets_processed / processing_time
        
        # Save dashboard data
        try:
            with open('dashboard_data.json', 'w') as f:
                json.dump(dashboard_data, f, indent=2)
            print("Dashboard data exported to dashboard_data.json")
        except Exception as e:
            print(f"Error exporting dashboard data: {e}")
        
        return dashboard_data

# ============================================================================
# MAIN EXECUTION AND DEMO
# ============================================================================

def run_comprehensive_test():
    """Run comprehensive test of all functionality"""
    print("="*60)
    print("COMPREHENSIVE NETWORK IDS TEST")
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
        signature_id="TEST-001",
        name="Test Malware Communication",
        protocol="TCP",
        destination_port=8080,
        payload_pattern=r".*MALWARE_BEACON.*",
        severity="Critical",
        description="Test signature for malware communication"
    )
    
    # Test specific attack detection
    print("\n4. Testing Specific Attack Detection...")
    test_packets = [
        {
            'packet_id': 1,
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'payload': "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
            'is_malicious': True
        },
        {
            'packet_id': 2,
            'src_ip': '192.168.1.101',
            'dst_ip': '192.168.1.1',
            'src_port': 54321,
            'dst_port': 80,
            'protocol': 'TCP',
            'payload': "<script>alert('XSS Attack')</script>",
            'is_malicious': True
        },
        {
            'packet_id': 3,
            'src_ip': '192.168.1.102',
            'dst_ip': '192.168.1.1',
            'src_port': 33333,
            'dst_port': 80,
            'protocol': 'TCP',
            'payload': "GET / HTTP/1.1\r\nHost: example.com",
            'is_malicious': False
        }
    ]
    
    for packet in test_packets:
        alerts = ids.detect_intrusions(packet)
        if alerts:
            print(f"   ✓ Packet {packet['packet_id']}: Detected {len(alerts)} alert(s)")
            for alert in alerts:
                print(f"     - {alert.signature_name}")
        else:
            print(f"   - Packet {packet['packet_id']}: No alerts")
    
    # Run simulation
    print("\n5. Running Detection Simulation (300 packets)...")
    alerts = ids.run_simulation(300)
    
    # Show results
    print(f"\n6. Detection Results: {len(alerts)} alerts generated")
    if alerts:
        print("\nSample Alerts:")
        for alert in alerts[:5]:  # Show first 5 alerts
            print(f"   - {alert.signature_name}: {alert.src_ip} -> {alert.dst_ip} ({alert.severity})")
    
    # Show metrics
    print("\n7. Performance Metrics:")
    metrics = ids.evaluator.calculate_metrics()
    print(f"   - Accuracy: {metrics.get('accuracy', 0):.2%}")
    print(f"   - Precision: {metrics.get('precision', 0):.2%}")
    print(f"   - Recall: {metrics.get('recall', 0):.2%}")
    print(f"   - F1 Score: {metrics.get('f1_score', 0):.3f}")
    print(f"   - False Positive Rate: {metrics.get('false_positive_rate', 0):.2%}")
    
    # Generate full report
    print("\n8. Generating Full Report...")
    ids.generate_report()
    
    # Export dashboard data
    print("\n9. Exporting Dashboard Data...")
    dashboard_data = ids.export_dashboard_data()
    
    print("\n" + "="*60)
    print("COMPREHENSIVE TEST COMPLETE")
    print("="*60)
    print("\nFiles generated:")
    print("- signatures.json (attack signatures)")
    print("- alerts.json (detection alerts)")
    print("- evaluation_results.json (performance metrics)")
    print("- dashboard_data.json (web dashboard data)")
    
    return dashboard_data

def run_quick_test():
    """Run a quick test of core functionality"""
    print("="*50)
    print("QUICK IDS TEST")
    print("="*50)
    
    # Initialize IDS
    ids = NetworkIDS()
    
    # Run small simulation
    print("\nRunning quick simulation (50 packets)...")
    alerts = ids.run_simulation(50)
    
    # Print results
    print(f"\nQuick test complete!")
    print(f"Alerts generated: {len(alerts)}")
    
    # Show metrics
    metrics = ids.evaluator.calculate_metrics()
    print(f"Accuracy: {metrics.get('accuracy', 0):.2%}")
    print(f"Precision: {metrics.get('precision', 0):.2%}")
    print(f"Recall: {metrics.get('recall', 0):.2%}")
    
    # Export data for dashboard
    ids.export_dashboard_data()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "comprehensive":
        run_comprehensive_test()
    elif len(sys.argv) > 1 and sys.argv[1] == "quick":
        run_quick_test()
    else:
        print("Network IDS - Usage:")
        print("python complete_ids.py comprehensive  # Run comprehensive test")
        print("python complete_ids.py quick         # Run quick test")
        print("python complete_ids.py               # Show this help")
        
        # Run comprehensive test by default
        print("\nRunning comprehensive test by default...\n")
        run_comprehensive_test()
