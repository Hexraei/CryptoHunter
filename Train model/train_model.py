"""
CryptoHunter GNN Model Training

This script trains the Graph Neural Network (GNN) model for cryptographic
primitive detection in binary firmware.

Model Architecture:
- Graph Isomorphism Network (GIN) with 4 convolutional layers
- 128 hidden dimensions
- 10-class classification (Non-crypto + 9 crypto types)

Training Process:
1. Load prepared dataset (JSON format)
2. Convert to PyTorch Geometric Data objects
3. Train with Adam optimizer
4. Evaluate on test set
5. Save model to models/model.pt

Usage:
    python train_model.py --dataset ./training_data/training_dataset.json --epochs 100
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

import numpy as np

# PyTorch and PyTorch Geometric imports
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.data import Data, DataLoader
    from torch_geometric.nn import GINConv, global_add_pool
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    TORCH_AVAILABLE = True
except ImportError as e:
    print(f"Error: Required packages not installed: {e}")
    print("Please install: pip install torch torch-geometric scikit-learn")
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

# Opcode mapping for feature extraction
OPCODE_MAP = {
    "MOV": 0, "ADD": 1, "SUB": 2, "XOR": 3, "LDR": 4,
    "STR": 5, "CMP": 6, "JMP": 7, "CALL": 8, "RET": 9,
    "AND": 10, "ORR": 11, "LSL": 12, "LSR": 13, "NOP": 14,
    "POP": 15, "PUSH": 16
}


class SOTA_GIN(nn.Module):
    """
    State-of-the-art Graph Isomorphism Network for crypto classification.
    
    Architecture:
    - 4 GIN convolutional layers with batch normalization
    - Global add pooling for graph-level representation
    - 2 fully connected layers for classification
    """
    
    def __init__(self, input_dim=20, hidden_dim=128, num_classes=10):
        super(SOTA_GIN, self).__init__()
        
        def make_mlp(in_dim, out_dim):
            return nn.Sequential(
                nn.Linear(in_dim, out_dim),
                nn.BatchNorm1d(out_dim),
                nn.ReLU(),
                nn.Linear(out_dim, out_dim)
            )
        
        self.conv1 = GINConv(make_mlp(input_dim, hidden_dim))
        self.conv2 = GINConv(make_mlp(hidden_dim, hidden_dim))
        self.conv3 = GINConv(make_mlp(hidden_dim, hidden_dim))
        self.conv4 = GINConv(make_mlp(hidden_dim, hidden_dim))
        self.lin1 = nn.Linear(hidden_dim, hidden_dim)
        self.lin2 = nn.Linear(hidden_dim, num_classes)
        self.dropout = nn.Dropout(0.2)
    
    def forward(self, x, edge_index, batch):
        x = F.relu(self.conv1(x, edge_index))
        x = self.dropout(x)
        x = F.relu(self.conv2(x, edge_index))
        x = self.dropout(x)
        x = F.relu(self.conv3(x, edge_index))
        x = self.dropout(x)
        x = F.relu(self.conv4(x, edge_index))
        x = global_add_pool(x, batch)
        x = F.relu(self.lin1(x))
        x = self.dropout(x)
        x = self.lin2(x)
        return x


def sample_to_data(sample):
    """Convert a training sample to PyTorch Geometric Data object."""
    graph = sample.get("graph", {})
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    label = sample.get("label", 0)
    
    if not nodes:
        return None
    
    # Extract node features (20-dimensional)
    node_features = []
    node_id_map = {}
    
    for idx, node in enumerate(nodes):
        node_id_map[node.get("id", idx)] = idx
        vec = [0.0] * 20
        
        # Opcode features
        for op in node.get("ops", []):
            k = op.upper()
            if k in OPCODE_MAP:
                vec[OPCODE_MAP[k]] += 1
        
        # Additional features
        vec[17] = 0.5  # Centrality placeholder
        vec[18] = float(node.get("fk", 0))  # Crypto constant flag
        vec[19] = float(node.get("fu", 0))  # Unrolled loop flag
        
        node_features.append(vec)
    
    x = torch.tensor(node_features, dtype=torch.float)
    
    # Build edge index
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


def load_dataset(dataset_path):
    """Load and prepare training dataset."""
    print(f"Loading dataset from: {dataset_path}")
    
    with open(dataset_path, 'r') as f:
        samples = json.load(f)
    
    print(f"Total samples: {len(samples)}")
    
    # Convert to Data objects
    data_list = []
    for sample in samples:
        data = sample_to_data(sample)
        if data is not None:
            data_list.append(data)
    
    print(f"Valid graphs: {len(data_list)}")
    return data_list


def train_epoch(model, loader, optimizer, device):
    """Train for one epoch."""
    model.train()
    total_loss = 0
    
    for batch in loader:
        batch = batch.to(device)
        optimizer.zero_grad()
        out = model(batch.x, batch.edge_index, batch.batch)
        loss = F.cross_entropy(out, batch.y)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * batch.num_graphs
    
    return total_loss / len(loader.dataset)


def evaluate(model, loader, device):
    """Evaluate model on a dataset."""
    model.eval()
    correct = 0
    all_preds = []
    all_labels = []
    
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device)
            out = model(batch.x, batch.edge_index, batch.batch)
            pred = out.argmax(dim=1)
            correct += (pred == batch.y).sum().item()
            all_preds.extend(pred.cpu().numpy())
            all_labels.extend(batch.y.cpu().numpy())
    
    accuracy = correct / len(loader.dataset)
    return accuracy, all_preds, all_labels


def main():
    if not TORCH_AVAILABLE:
        print("PyTorch not available. Please install required packages.")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description="Train GNN model for crypto detection")
    parser.add_argument("--dataset", "-d", required=True,
                       help="Path to training dataset JSON")
    parser.add_argument("--output", "-o", default="../models/model.pt",
                       help="Output path for trained model")
    parser.add_argument("--epochs", "-e", type=int, default=100,
                       help="Number of training epochs")
    parser.add_argument("--batch-size", "-b", type=int, default=32,
                       help="Batch size for training")
    parser.add_argument("--lr", type=float, default=0.001,
                       help="Learning rate")
    parser.add_argument("--hidden", type=int, default=128,
                       help="Hidden dimension size")
    
    args = parser.parse_args()
    
    # Setup device
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")
    
    # Load dataset
    data_list = load_dataset(args.dataset)
    
    if len(data_list) < 10:
        print("Error: Not enough samples for training")
        sys.exit(1)
    
    # Split dataset
    train_data, test_data = train_test_split(data_list, test_size=0.2, random_state=42)
    train_data, val_data = train_test_split(train_data, test_size=0.15, random_state=42)
    
    print(f"Train: {len(train_data)}, Val: {len(val_data)}, Test: {len(test_data)}")
    
    # Create data loaders
    train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=args.batch_size)
    test_loader = DataLoader(test_data, batch_size=args.batch_size)
    
    # Initialize model
    model = SOTA_GIN(input_dim=20, hidden_dim=args.hidden, num_classes=10)
    model = model.to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    
    print(f"\nTraining for {args.epochs} epochs...")
    print("-" * 60)
    
    best_val_acc = 0
    best_model_state = None
    patience = 10
    patience_counter = 0
    
    for epoch in range(1, args.epochs + 1):
        train_loss = train_epoch(model, train_loader, optimizer, device)
        train_acc, _, _ = evaluate(model, train_loader, device)
        val_acc, _, _ = evaluate(model, val_loader, device)
        
        # Early stopping
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            best_model_state = model.state_dict().copy()
            patience_counter = 0
        else:
            patience_counter += 1
        
        if epoch % 10 == 0 or epoch == 1:
            print(f"Epoch {epoch:3d}: Loss={train_loss:.4f}, Train={train_acc:.4f}, Val={val_acc:.4f}")
        
        if patience_counter >= patience:
            print(f"\nEarly stopping at epoch {epoch}")
            break
    
    # Load best model
    if best_model_state:
        model.load_state_dict(best_model_state)
    
    # Final evaluation
    test_acc, preds, labels = evaluate(model, test_loader, device)
    
    print("\n" + "="*60)
    print("Training Complete!")
    print("="*60)
    print(f"Best Validation Accuracy: {best_val_acc:.4f}")
    print(f"Test Accuracy: {test_acc:.4f}")
    
    # Classification report
    print("\nClassification Report:")
    print(classification_report(labels, preds, 
                               target_names=[CRYPTO_CLASSES[i] for i in range(10)],
                               zero_division=0))
    
    # Save model
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), output_path)
    print(f"\nModel saved to: {output_path}")
    
    # Save training metadata
    metadata = {
        "trained_at": datetime.now().isoformat(),
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "learning_rate": args.lr,
        "hidden_dim": args.hidden,
        "train_samples": len(train_data),
        "val_samples": len(val_data),
        "test_samples": len(test_data),
        "best_val_accuracy": best_val_acc,
        "test_accuracy": test_acc
    }
    
    metadata_path = output_path.with_suffix(".json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to: {metadata_path}")


if __name__ == "__main__":
    main()
