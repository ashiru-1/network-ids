import pandas as pd
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
import re
from typing import Dict, List, Any, Optional
from datetime import datetime

class TrafficAnalyzer:
    def __init__(self):
        self.packet_features = []
    
    def extract_packet_features(self, packet) -> Optional[Dict[str, Any]]:
        """Extract relevant features from a network packet"""
        try:
            features = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'protocol': None,
                'payload': '',
                'packet_size': len(packet)
            }
            
            # Extract IP layer information
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                features['src_ip'] = ip_layer.src
                features['dst_ip'] = ip_layer.dst
                features['protocol'] = ip_layer.proto
                
                # Convert protocol number to name
                if ip_layer.proto == 6:
                    features['protocol'] = 'TCP'
                elif ip_layer.proto == 17:
                    features['protocol'] = 'UDP'
                elif ip_layer.proto == 1:
                    features['protocol'] = 'ICMP'
            
            # Extract TCP layer information
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                features['src_port'] = tcp_layer.sport
                features['dst_port'] = tcp_layer.dport
                
                # Extract payload
                if hasattr(tcp_layer, 'payload') and tcp_layer.payload:
                    try:
                        features['payload'] = str(tcp_layer.payload)
                    except:
                        features['payload'] = ''
            
            # Extract UDP layer information
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                features['src_port'] = udp_layer.sport
                features['dst_port'] = udp_layer.dport
                
                # Extract payload
                if hasattr(udp_layer, 'payload') and udp_layer.payload:
                    try:
                        features['payload'] = str(udp_layer.payload)
                    except:
                        features['payload'] = ''
            
            # Extract HTTP information if present
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                if hasattr(http_layer, 'Host'):
                    features['http_host'] = http_layer.Host.decode() if isinstance(http_layer.Host, bytes) else http_layer.Host
                if hasattr(http_layer, 'Path'):
                    features['http_path'] = http_layer.Path.decode() if isinstance(http_layer.Path, bytes) else http_layer.Path
                if hasattr(http_layer, 'Method'):
                    features['http_method'] = http_layer.Method.decode() if isinstance(http_layer.Method, bytes) else http_layer.Method
            
            return features
            
        except Exception as e:
            print(f"Error extracting packet features: {e}")
            return None
    
    def analyze_pcap(self, pcap_file: str) -> List[Dict[str, Any]]:
        """Analyze a PCAP file and extract features from all packets"""
        print(f"Analyzing PCAP file: {pcap_file}")
        packet_features = []
        
        try:
            packets = rdpcap(pcap_file)
            print(f"Found {len(packets)} packets")
            
            for i, packet in enumerate(packets):
                features = self.extract_packet_features(packet)
                if features:
                    features['packet_id'] = i
                    packet_features.append(features)
                
                if (i + 1) % 1000 == 0:
                    print(f"Processed {i + 1} packets...")
            
            print(f"Extracted features from {len(packet_features)} packets")
            return packet_features
            
        except Exception as e:
            print(f"Error analyzing PCAP file: {e}")
            return []
    
    def analyze_csv(self, csv_file: str) -> List[Dict[str, Any]]:
        """Analyze network traffic data from CSV file"""
        print(f"Analyzing CSV file: {csv_file}")
        
        try:
            df = pd.read_csv(csv_file)
            print(f"Found {len(df)} records")
            
            # Convert DataFrame to list of dictionaries
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
        import random
        
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
            # 10% chance of malicious traffic
            is_malicious = random.random() < 0.1
            
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
        
        print(f"Generated {num_packets} sample packets ({sum(1 for p in packet_features if p.get('is_malicious', False))} malicious)")
        return packet_features

# Test the traffic analyzer
if __name__ == "__main__":
    analyzer = TrafficAnalyzer()
    
    # Generate sample data for testing
    sample_data = analyzer.generate_sample_data(100)
    
    print("\nSample packet features:")
    for packet in sample_data[:5]:
        print(f"Packet {packet['packet_id']}: {packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']} ({packet['protocol']})")
        if packet['payload']:
            print(f"  Payload: {packet['payload'][:50]}...")
