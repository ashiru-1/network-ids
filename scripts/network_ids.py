import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from signature_manager import SignatureManager, Signature
from traffic_analyzer import TrafficAnalyzer
from alert_manager import AlertManager, Alert
from evaluation_metrics import EvaluationMetrics
from typing import List, Dict, Any, Optional
import time
from datetime import datetime

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
    
    def analyze_pcap_file(self, pcap_file: str) -> List[Alert]:
        """Analyze a PCAP file for intrusions"""
        print(f"Analyzing PCAP file: {pcap_file}")
        
        # Extract features from PCAP
        traffic_data = self.traffic_analyzer.analyze_pcap(pcap_file)
        
        if not traffic_data:
            print("No traffic data extracted from PCAP file")
            return []
        
        # Process traffic for intrusions
        return self.process_traffic_batch(traffic_data)
    
    def analyze_csv_file(self, csv_file: str) -> List[Alert]:
        """Analyze a CSV file for intrusions"""
        print(f"Analyzing CSV file: {csv_file}")
        
        # Extract features from CSV
        traffic_data = self.traffic_analyzer.analyze_csv(csv_file)
        
        if not traffic_data:
            print("No traffic data extracted from CSV file")
            return []
        
        # Process traffic for intrusions
        return self.process_traffic_batch(traffic_data)
    
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
        
        # Error analysis
        self.evaluator.print_error_analysis(3)
        
        # Save results
        self.alert_manager.save_alerts()
        self.evaluator.save_results()
        
        print("\n" + "="*60)
        print("REPORT COMPLETE")
        print("="*60)

# Main execution
if __name__ == "__main__":
    # Initialize IDS
    ids = NetworkIDS()
    
    # Add a custom signature for demonstration
    ids.add_custom_signature(
        signature_id="CUSTOM-001",
        name="Suspicious PowerShell Activity",
        protocol="TCP",
        destination_port=443,
        payload_pattern=r".*powershell.*-enc.*",
        severity="High",
        description="Detects encoded PowerShell commands"
    )
    
    # Run simulation
    print("\nStarting IDS simulation...")
    alerts = ids.run_simulation(500)
    
    # Generate comprehensive report
    ids.generate_report()
    
    print(f"\nSimulation complete! Generated {len(alerts)} alerts.")
    print("Check 'alerts.json' and 'evaluation_results.json' for detailed results.")
