"""
CryptoHunter Model Evaluation

This script evaluates the trained GNN model on test datasets and
generates comprehensive accuracy reports.

Features:
- Per-class accuracy metrics
- Confusion matrix visualization
- Confidence distribution analysis
- Cross-architecture evaluation

Usage:
    python evaluate_model.py --model ../models/model.pt --test ./test_data
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

import numpy as np

try:
    import torch
    import torch.nn.functional as F
    from torch_geometric.data import Data, DataLoader
    from torch_geometric.nn import GINConv, global_add_pool
    from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


# Crypto class mapping
CRYPTO_CLASSES = {
    0: "Non-Crypto",
    1: "AES/Block Cipher",
    2: "Hash Function",
    3: "Stream Cipher",
    4: "Public Key",
    5: "Auth/MAC",
    6: "KDF",
    7: "PRNG",
    8: "XOR Cipher",
    9: "Post-Quantum"
}

# Opcode mapping
OPCODE_MAP = {
    "MOV": 0, "ADD": 1, "SUB": 2, "XOR": 3, "LDR": 4,
    "STR": 5, "CMP": 6, "JMP": 7, "CALL": 8, "RET": 9,
    "AND": 10, "ORR": 11, "LSL": 12, "LSR": 13, "NOP": 14,
    "POP": 15, "PUSH": 16
}


class SOTA_GIN(torch.nn.Module):
    """Graph Isomorphism Network for crypto classification."""
    
    def __init__(self, input_dim=20, hidden_dim=128, num_classes=10):
        super(SOTA_GIN, self).__init__()
        
        def make_mlp(in_dim, out_dim):
            return torch.nn.Sequential(
                torch.nn.Linear(in_dim, out_dim),
                torch.nn.BatchNorm1d(out_dim),
                torch.nn.ReLU(),
                torch.nn.Linear(out_dim, out_dim)
            )
        
        self.conv1 = GINConv(make_mlp(input_dim, hidden_dim))
        self.conv2 = GINConv(make_mlp(hidden_dim, hidden_dim))
        self.conv3 = GINConv(make_mlp(hidden_dim, hidden_dim))
        self.conv4 = GINConv(make_mlp(hidden_dim, hidden_dim))
        self.lin1 = torch.nn.Linear(hidden_dim, hidden_dim)
        self.lin2 = torch.nn.Linear(hidden_dim, num_classes)
    
    def forward(self, x, edge_index, batch):
        x = F.relu(self.conv1(x, edge_index))
        x = F.relu(self.conv2(x, edge_index))
        x = F.relu(self.conv3(x, edge_index))
        x = F.relu(self.conv4(x, edge_index))
        x = global_add_pool(x, batch)
        x = F.relu(self.lin1(x))
        x = self.lin2(x)
        return x


def sample_to_data(sample):
    """Convert sample to PyTorch Geometric Data object."""
    graph = sample.get("graph", {})
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    label = sample.get("label", 0)
    
    if not nodes:
        return None
    
    node_features = []
    node_id_map = {}
    
    for idx, node in enumerate(nodes):
        node_id_map[node.get("id", idx)] = idx
        vec = [0.0] * 20
        
        for op in node.get("ops", []):
            k = op.upper()
            if k in OPCODE_MAP:
                vec[OPCODE_MAP[k]] += 1
        
        vec[17] = 0.5
        vec[18] = float(node.get("fk", 0))
        vec[19] = float(node.get("fu", 0))
        
        node_features.append(vec)
    
    x = torch.tensor(node_features, dtype=torch.float)
    
    if edges:
        remapped = []
        for edge in edges:
            if len(edge) >= 2:
                src, dst = edge[0], edge[1]
                if src in node_id_map and dst in node_id_map:
                    remapped.append([node_id_map[src], node_id_map[dst]])
        
        if remapped:
            edge_index = torch.tensor(remapped, dtype=torch.long).t().contiguous()
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long)
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)
    
    y = torch.tensor([label], dtype=torch.long)
    
    return Data(x=x, edge_index=edge_index, y=y)


def evaluate_model(model, data_list, device):
    """Run evaluation on a dataset."""
    model.eval()
    
    all_preds = []
    all_labels = []
    all_confidences = []
    
    with torch.no_grad():
        for data in data_list:
            data = data.to(device)
            
            # Add batch dimension for single sample
            if not hasattr(data, 'batch') or data.batch is None:
                data.batch = torch.zeros(data.x.size(0), dtype=torch.long, device=device)
            
            out = model(data.x, data.edge_index, data.batch)
            probs = F.softmax(out, dim=-1)
            pred = out.argmax(dim=1).item()
            conf = probs.max().item()
            
            all_preds.append(pred)
            all_labels.append(data.y.item())
            all_confidences.append(conf)
    
    return all_preds, all_labels, all_confidences


def main():
    if not TORCH_AVAILABLE:
        print("PyTorch not available. Please install required packages.")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description="Evaluate trained model")
    parser.add_argument("--model", "-m", required=True,
                       help="Path to trained model (.pt file)")
    parser.add_argument("--test", "-t", required=True,
                       help="Path to test dataset (JSON file or directory)")
    parser.add_argument("--output", "-o", default="./evaluation_report.json",
                       help="Output path for evaluation report")
    
    args = parser.parse_args()
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")
    
    # Load model
    print(f"Loading model from: {args.model}")
    model = SOTA_GIN(input_dim=20, hidden_dim=128, num_classes=10)
    model.load_state_dict(torch.load(args.model, map_location=device))
    model = model.to(device)
    model.eval()
    
    # Load test data
    test_path = Path(args.test)
    if test_path.is_file():
        with open(test_path, 'r') as f:
            samples = json.load(f)
    else:
        samples = []
        for json_file in test_path.glob("*.json"):
            with open(json_file, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    samples.extend(data)
                else:
                    samples.append(data)
    
    print(f"Test samples: {len(samples)}")
    
    # Convert to Data objects
    data_list = []
    for sample in samples:
        data = sample_to_data(sample)
        if data is not None:
            data_list.append(data)
    
    print(f"Valid graphs: {len(data_list)}")
    
    if not data_list:
        print("No valid test data found.")
        sys.exit(1)
    
    # Run evaluation
    preds, labels, confidences = evaluate_model(model, data_list, device)
    
    # Calculate metrics
    accuracy = accuracy_score(labels, preds)
    
    print("\n" + "="*60)
    print("Evaluation Results")
    print("="*60)
    print(f"Overall Accuracy: {accuracy:.4f} ({accuracy*100:.1f}%)")
    
    # Classification report
    print("\nClassification Report:")
    report = classification_report(labels, preds,
                                  target_names=[CRYPTO_CLASSES[i] for i in range(10)],
                                  zero_division=0,
                                  output_dict=True)
    print(classification_report(labels, preds,
                               target_names=[CRYPTO_CLASSES[i] for i in range(10)],
                               zero_division=0))
    
    # Confidence analysis
    avg_confidence = np.mean(confidences)
    high_conf = sum(1 for c in confidences if c >= 0.8) / len(confidences)
    
    print(f"\nConfidence Analysis:")
    print(f"  Average confidence: {avg_confidence:.3f}")
    print(f"  High confidence (>80%): {high_conf*100:.1f}%")
    
    # Confusion matrix
    cm = confusion_matrix(labels, preds)
    print(f"\nConfusion Matrix:")
    print(cm)
    
    # Save report
    report_data = {
        "evaluated_at": datetime.now().isoformat(),
        "model_path": args.model,
        "test_path": str(args.test),
        "total_samples": len(data_list),
        "overall_accuracy": accuracy,
        "average_confidence": avg_confidence,
        "high_confidence_ratio": high_conf,
        "classification_report": report,
        "confusion_matrix": cm.tolist()
    }
    
    output_path = Path(args.output)
    with open(output_path, "w") as f:
        json.dump(report_data, f, indent=2)
    
    print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()
