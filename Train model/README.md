# How to Train the CryptoHunter Model

This guide explains how to train the GNN (Graph Neural Network) model used by CryptoHunter to detect cryptographic primitives in binary firmware.

## Overview

The training pipeline consists of four main steps:

1. **Download Datasets** - Fetch crypto library source code from GitHub
2. **Prepare Datasets** - Compile, extract CFGs, and label functions
3. **Train Model** - Train the GNN on prepared data
4. **Evaluate Model** - Test accuracy on held-out data

## Prerequisites

### Required Software

- Python 3.9+
- Ghidra 11.0+ (for CFG extraction)
- Git (for cloning repositories)
- Cross-compilers (optional, for multi-arch training):
  - `arm-linux-gnueabi-gcc`
  - `mips-linux-gnu-gcc`
  - `riscv64-linux-gnu-gcc`

### Required Python Packages

```bash
pip install torch torch-geometric scikit-learn numpy xgboost
```

### Environment Variables

Set the Ghidra path:

```bash
# Windows
set GHIDRA_PATH=D:\ghidra_11.4.2_PUBLIC

# Linux/Mac
export GHIDRA_PATH=/opt/ghidra
```

## Step 1: Download Datasets

Download crypto library source code from GitHub:

```bash
cd "Train model"

# Download all libraries
python download_datasets.py --output ./datasets

# Or select specific libraries
python download_datasets.py --output ./datasets --libraries openssl,mbedtls

# List available libraries
python download_datasets.py --list
```

### Supported Libraries

| Library | Description |
|---------|-------------|
| openssl | OpenSSL crypto library (TLS, ciphers, hashes) |
| mbedtls | Lightweight embedded TLS library |
| wolfssl | Embedded SSL/TLS for IoT |
| libsodium | Modern crypto library (NaCl-based) |

## Step 2: Prepare Datasets

Process downloaded libraries and create training data:

```bash
# Process real binaries (requires Ghidra)
python prepare_datasets.py --input ./datasets --output ./training_data

# Generate synthetic data (no Ghidra needed)
python prepare_datasets.py --output ./training_data --synthetic 1000
```

This script will:
- Find all binary files (.o, .so, .elf)
- Run Ghidra to extract control flow graphs
- Label functions based on symbol names
- Save as JSON dataset

### Adding Your Own Datasets

To add custom binaries:

1. Place binaries in `./datasets/my_library/`
2. Run the preparation script
3. Manually label functions in the output JSON if needed

### Labeling Format

Each sample should have:
```json
{
    "name": "aes_encrypt",
    "label": 1,
    "label_name": "AES/Block Cipher",
    "graph": {
        "nodes": [...],
        "edges": [...]
    }
}
```

Class labels:
- 0: Non-Crypto
- 1: AES/Block Cipher
- 2: Hash Function
- 3: Stream Cipher
- 4: Public Key
- 5: Auth/MAC
- 6: KDF
- 7: PRNG
- 8: XOR Cipher
- 9: Post-Quantum

## Step 3: Train the Model

Train the GNN model:

```bash
# Basic training
python train_model.py --dataset ./training_data/training_dataset.json

# With custom parameters
python train_model.py \
    --dataset ./training_data/training_dataset.json \
    --output ../models/model.pt \
    --epochs 100 \
    --batch-size 32 \
    --lr 0.001 \
    --hidden 128
```

### Training Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| --epochs | 100 | Number of training epochs |
| --batch-size | 32 | Batch size |
| --lr | 0.001 | Learning rate |
| --hidden | 128 | Hidden layer dimension |

### Expected Output

```
Training for 100 epochs...
------------------------------------------------------------
Epoch   1: Loss=2.3041, Train=0.1234, Val=0.1156
Epoch  10: Loss=0.8234, Train=0.6543, Val=0.6234
...
Epoch  95: Loss=0.1234, Train=0.9423, Val=0.9156

Training Complete!
============================================================
Best Validation Accuracy: 0.9412
Test Accuracy: 0.9378
```

## Step 4: Evaluate the Model

Test model accuracy on new data:

```bash
python evaluate_model.py \
    --model ../models/model.pt \
    --test ./test_data/test_dataset.json \
    --output ./evaluation_report.json
```

### Evaluation Metrics

The script generates:
- Overall accuracy
- Per-class precision, recall, F1-score
- Confusion matrix
- Confidence distribution

## Expanding Training Data

### Adding New Crypto Libraries

1. Download the library source:
   ```bash
   git clone https://github.com/library/name ./datasets/name
   ```

2. Compile for target architectures:
   ```bash
   # ARM
   arm-linux-gnueabi-gcc -c *.c -O2
   
   # x86-64
   gcc -c *.c -O2
   ```

3. Run preparation:
   ```bash
   python prepare_datasets.py --input ./datasets --output ./training_data
   ```

### Cross-Architecture Training

For better generalization, include samples from multiple architectures:

- ARM32, ARM64 (embedded devices)
- x86, x86-64 (desktop/server)
- MIPS (routers, IoT)
- RISC-V (emerging)

### Handling Imbalanced Classes

If some crypto classes have few samples:

1. Use synthetic data generation
2. Apply class weighting during training
3. Use data augmentation (graph transformations)

## Troubleshooting

### Ghidra Errors

```
Error: Ghidra not found
```
Solution: Set `GHIDRA_PATH` environment variable.

### Out of Memory

```
RuntimeError: CUDA out of memory
```
Solution: Reduce batch size or use CPU training.

### Low Accuracy

If accuracy is below 80%:
- Increase training data
- Check label quality
- Try more training epochs
- Adjust learning rate

## File Structure

```
Train model/
├── download_datasets.py   # Step 1: Download from GitHub
├── prepare_datasets.py    # Step 2: Process and label
├── train_model.py         # Step 3: Train GNN
├── evaluate_model.py      # Step 4: Evaluate
├── README.md              # This file
├── datasets/              # Downloaded libraries
├── training_data/         # Prepared training data
└── models/                # Trained models
```

## Next Steps

After training:

1. Copy `model.pt` to `../models/model.pt`
2. Test with the main application
3. Run on real firmware samples
4. Fine-tune based on results
