import json
import yaml
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

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
                if self.signature_file.endswith('.yaml') or self.signature_file.endswith('.yml'):
                    data = yaml.safe_load(f)
                else:
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
    
    def remove_signature(self, signature_id: str):
        """Remove a signature"""
        if signature_id in self.signatures:
            del self.signatures[signature_id]
            self.save_signatures()
            return True
        return False
    
    def get_signature(self, signature_id: str) -> Optional[Signature]:
        """Get a specific signature"""
        return self.signatures.get(signature_id)
    
    def list_signatures(self) -> List[Signature]:
        """Get all signatures"""
        return list(self.signatures.values())

# Test the signature manager
if __name__ == "__main__":
    sm = SignatureManager()
    print("Available signatures:")
    for sig in sm.list_signatures():
        print(f"- {sig.signature_id}: {sig.name} ({sig.severity})")
