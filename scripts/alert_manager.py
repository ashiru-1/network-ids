import json
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass, asdict

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
        self.load_alerts()
    
    def load_alerts(self):
        """Load existing alerts from file"""
        try:
            with open(self.alert_file, 'r') as f:
                data = json.load(f)
                for alert_data in data.get('alerts', []):
                    alert = Alert(**alert_data)
                    self.alerts.append(alert)
                self.alert_counter = len(self.alerts)
            print(f"Loaded {len(self.alerts)} existing alerts")
        except FileNotFoundError:
            print("No existing alerts file found. Starting fresh.")
        except Exception as e:
            print(f"Error loading alerts: {e}")
    
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
    
    def get_alerts_by_severity(self, severity: str) -> List[Alert]:
        """Get alerts filtered by severity"""
        return [alert for alert in self.alerts if alert.severity.lower() == severity.lower()]
    
    def get_alerts_by_ip(self, ip: str) -> List[Alert]:
        """Get alerts filtered by source or destination IP"""
        return [alert for alert in self.alerts if alert.src_ip == ip or alert.dst_ip == ip]
    
    def get_recent_alerts(self, hours: int = 24) -> List[Alert]:
        """Get alerts from the last N hours"""
        from datetime import datetime, timedelta
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_alerts = []
        
        for alert in self.alerts:
            try:
                alert_time = datetime.fromisoformat(alert.timestamp.replace('Z', '+00:00'))
                if alert_time >= cutoff_time:
                    recent_alerts.append(alert)
            except:
                continue
        
        return recent_alerts
    
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
        
        # Recent alerts
        recent = self.get_recent_alerts(1)  # Last hour
        print(f"\nRecent Alerts (last hour): {len(recent)}")
        
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

# Test the alert manager
if __name__ == "__main__":
    am = AlertManager()
    
    # Create sample alert
    sample_packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '192.168.1.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'payload': 'SELECT * FROM users WHERE id=1',
        'timestamp': datetime.now().isoformat()
    }
    
    alert = am.create_alert("SQLI-001", "SQL Injection Attempt", "High", sample_packet)
    print(f"Created alert: {alert.alert_id}")
    
    am.print_alert_summary()
