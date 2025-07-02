from typing import List, Dict, Any, Tuple
import json
from datetime import datetime

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
        
        # False Negative Rate
        if (self.false_negatives + self.true_positives) > 0:
            metrics['false_negative_rate'] = self.false_negatives / (self.false_negatives + self.true_positives)
        else:
            metrics['false_negative_rate'] = 0.0
        
        # Specificity
        if (self.true_negatives + self.false_positives) > 0:
            metrics['specificity'] = self.true_negatives / (self.true_negatives + self.false_positives)
        else:
            metrics['specificity'] = 0.0
        
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
        print(f"Specificity:           {metrics['specificity']:.4f} ({metrics['specificity']*100:.2f}%)")
        print(f"False Positive Rate:   {metrics['false_positive_rate']:.4f} ({metrics['false_positive_rate']*100:.2f}%)")
        print(f"False Negative Rate:   {metrics['false_negative_rate']:.4f} ({metrics['false_negative_rate']*100:.2f}%)")
    
    def get_detection_errors(self) -> Tuple[List[Dict], List[Dict]]:
        """Get false positives and false negatives for analysis"""
        false_positives = [
            result for result in self.detection_results
            if not result['actually_malicious'] and result['detected_as_malicious']
        ]
        
        false_negatives = [
            result for result in self.detection_results
            if result['actually_malicious'] and not result['detected_as_malicious']
        ]
        
        return false_positives, false_negatives
    
    def print_error_analysis(self, limit: int = 5):
        """Print analysis of detection errors"""
        false_positives, false_negatives = self.get_detection_errors()
        
        print(f"\n=== ERROR ANALYSIS ===")
        print(f"False Positives: {len(false_positives)}")
        print(f"False Negatives: {len(false_negatives)}")
        
        if false_positives:
            print(f"\nTop {min(limit, len(false_positives))} False Positives:")
            for i, fp in enumerate(false_positives[:limit]):
                print(f"{i+1}. Packet {fp['packet_id']}: {fp['src_ip']} -> {fp['dst_ip']}")
                print(f"   Signature: {fp['signature_matched']}")
                print(f"   Payload: {fp['payload_snippet']}...")
        
        if false_negatives:
            print(f"\nTop {min(limit, len(false_negatives))} False Negatives:")
            for i, fn in enumerate(false_negatives[:limit]):
                print(f"{i+1}. Packet {fn['packet_id']}: {fn['src_ip']} -> {fn['dst_ip']}")
                print(f"   Payload: {fn['payload_snippet']}...")
    
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

# Test the evaluation metrics
if __name__ == "__main__":
    evaluator = EvaluationMetrics()
    
    # Simulate some detection results
    test_packets = [
        {'packet_id': 1, 'is_malicious': True, 'payload': 'SELECT * FROM users'},
        {'packet_id': 2, 'is_malicious': False, 'payload': 'GET / HTTP/1.1'},
        {'packet_id': 3, 'is_malicious': True, 'payload': '<script>alert(1)</script>'},
        {'packet_id': 4, 'is_malicious': False, 'payload': 'POST /login HTTP/1.1'},
    ]
    
    # Simulate detection results (some correct, some incorrect)
    evaluator.add_detection_result(test_packets[0], True, "SQLI-001")  # TP
    evaluator.add_detection_result(test_packets[1], False, None)       # TN
    evaluator.add_detection_result(test_packets[2], False, None)       # FN
    evaluator.add_detection_result(test_packets[3], True, "XSS-001")   # FP
    
    evaluator.print_metrics_report()
    evaluator.print_error_analysis()
