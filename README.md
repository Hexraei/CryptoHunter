# CryptoHunter

**AI/ML-Powered Cryptographic Primitive Detection in Binary Firmware**

---

## Table of Contents

1. [Problem Statement and Our Approach](#problem-statement-and-our-approach)
2. [Why This Solution Works](#why-this-solution-works)
3. [System Architecture](#system-architecture)
4. [File Structure and Descriptions](#file-structure-and-descriptions)
5. [The Complete Pipeline](#the-complete-pipeline)
6. [Training Process Overview](#training-process-overview)
7. [Installation and Running](#installation-and-running)
8. [End Results and Output](#end-results-and-output)
9. [Pros and Cons](#pros-and-cons)
10. [API Reference](#api-reference)

---

## Problem Statement and Our Approach

### The Challenge

Modern firmware contains embedded cryptographic implementations that are critical for security analysis. Identifying these implementations manually is:

- **Time-consuming**: A single firmware image may contain thousands of functions
- **Architecture-dependent**: Firmware runs on diverse CPUs (ARM, MIPS, x86, RISC-V)
- **Obfuscation-prone**: Optimizing compilers transform code, making pattern matching unreliable
- **Scale-prohibitive**: Security researchers cannot manually analyze every firmware update

Traditional signature-based tools (like FindCrypt) fail when:
- Code is compiled with different optimization levels (-O0 to -O3)
- Different compilers produce different instruction sequences
- Stripped binaries remove symbol information
- Custom or modified crypto implementations are used

### Our Solution

CryptoHunter uses **Graph Neural Networks (GNN)** to detect cryptographic primitives by analyzing the **structural topology** of function control flow graphs, not the raw instruction bytes. This approach is:

1. **Architecture-agnostic**: Ghidra lifts all binaries to P-Code intermediate representation
2. **Optimization-resistant**: CFG structure is preserved across optimization levels
3. **Compiler-independent**: Graph topology remains consistent across GCC/Clang
4. **Scalable**: Automated pipeline processes firmware without human intervention

---

## Why This Solution Works

### The Key Insight

Cryptographic algorithms have **distinctive control flow patterns**:

- **Block ciphers (AES, DES)**: Dense loops with XOR operations and S-box lookups
- **Hash functions (SHA, MD5)**: Sequential rounds with rotation and mixing
- **Public key (RSA, ECDSA)**: Large integer arithmetic in nested loops
- **Key derivation (PBKDF2)**: Iterative hash chains

These patterns manifest as **graph structures** that remain consistent even when:
- The binary is compiled for different architectures
- Different optimization levels are applied
- Symbol names are stripped

### Technical Approach

```
Source Code -> Compiler -> Binary -> Ghidra P-Code -> CFG Graph -> GNN -> Classification
     |                                    |                          |
     |          (varies)                  |      (consistent)        |
     +------------------------------------+                          |
                                                                     v
                                                            Crypto Identified
```

By training on 50,000+ samples across 6 architectures and 4 optimization levels, the GNN learns to recognize crypto "fingerprints" that transcend low-level implementation details.

---

## System Architecture

```
+------------------------------------------------------------------+
|                        CryptoHunter Stack                         |
+------------------------------------------------------------------+
|                                                                    |
|   [Frontend] -----> [FastAPI Server] -----> [RabbitMQ]            |
|       |                    |                     |                 |
|       v                    v                     v                 |
|   WebSocket           PostgreSQL           [Celery Workers]       |
|   (Progress)          (Results)                  |                 |
|                                                  v                 |
|                                    +---------------------------+   |
|                                    |     Analysis Pipeline     |   |
|                                    +---------------------------+   |
|                                    | Step 0: binwalk/unblob    |   |
|                                    | Step 1: Ghidra P-Code     |   |
|                                    | Step 2: XGBoost Filter    |   |
|                                    | Step 3: GNN Inference     |   |
|                                    | Step 4: Angr Verify       |   |
|                                    | Step 5: Aggregation       |   |
|                                    +---------------------------+   |
|                                                                    |
+------------------------------------------------------------------+
```

---

## File Structure and Descriptions

```
CryptoHunter/
|
+-- Dockerfile              # Container with Ghidra, binwalk, unblob, angr
+-- docker-compose.yml      # Full stack: API, workers, PostgreSQL, Redis, RabbitMQ
+-- requirements.txt        # Python dependencies
+-- README.md               # This documentation
+-- LICENSE                 # MIT License
+-- .gitignore              # Git exclusions
|
+-- docs/
|   +-- API.md              # REST API documentation
|
+-- models/
|   +-- crypto_gnn_model.pt     # Original trained GNN model
|   +-- sota_crypto_model.pt    # State-of-the-art model (higher accuracy)
|
+-- src/
|   +-- standalone.py           # Main FastAPI server with all endpoints
|   +-- run_full_analysis.py    # Orchestrates the complete Ghidra pipeline
|   +-- extract_firmware.py     # binwalk/unblob firmware extraction
|   +-- xgboost_filter.py       # Fast pre-filter using XGBoost
|   +-- infer_crypto.py         # GNN inference engine
|   +-- symbolic_verify.py      # Angr-based symbolic verification
|   +-- check_z80.py            # Z80 architecture detection
|   +-- check_avr.py            # AVR/Arduino architecture detection
|   +-- check_architectures.py  # Unified architecture detection
|   |
|   +-- utils/
|   |   +-- export_report.py    # JSON, CSV, Excel, PDF export
|   |
|   +-- workers/
|       +-- celery_app.py       # Celery configuration
|       +-- tasks.py            # Background analysis tasks
|       +-- __init__.py
|
+-- uploads/                # Uploaded firmware files
+-- results/                # Analysis results (JSON)
```

### How Each File Fits the Pipeline

| Step | File | Role in Pipeline |
|------|------|------------------|
| 0 | `extract_firmware.py` | Extracts filesystems from firmware using binwalk/unblob |
| 1 | `run_full_analysis.py` | Runs Ghidra headless to extract P-Code and CFGs |
| 2 | `xgboost_filter.py` | Pre-filters functions using lightweight ML model |
| 3 | `infer_crypto.py` | Runs GNN inference on candidate functions |
| 4 | `symbolic_verify.py` | Verifies crypto with Angr symbolic execution |
| 5 | `standalone.py` | Aggregates results, serves API, exports reports |

---

## The Complete Pipeline

### Phase A: Offline Training (Pre-deployment)

```
1. Source Code Collection
   - OpenSSL, MbedTLS, WolfSSL, LibSodium source code

2. Cross-Compilation Matrix
   - 6 Architectures: x86, x64, ARMv7, ARM64, MIPS, RISC-V
   - 4 Compilers: GCC, Clang with -O0, -O2, -O3, -Os
   - Result: ~50,000 labeled binary samples

3. Graph Extraction
   - Ghidra lifts binaries to P-Code
   - NetworkX extracts Control Flow Graphs
   - Labels assigned from debug symbols

4. GNN Training
   - PyTorch Geometric trains Graph Isomorphism Network
   - 10-class classification (Non-crypto + 9 crypto types)
   - Output: sota_crypto_model.pt
```

### Phase B: Live Analysis (Runtime)

```
User uploads firmware.bin
            |
            v
   +------------------+
   | Step 0: Extract  |  binwalk/unblob recursively extracts filesystems
   +------------------+
            |
            v
   +------------------+
   | Step 1: Lift     |  Ghidra converts binaries to P-Code IR
   +------------------+
            |
            v
   +------------------+
   | Step 2: Filter   |  XGBoost filters to ~100 suspicious functions
   +------------------+
            |
            v
   +------------------+
   | Step 3: Classify |  GNN classifies each function (0.0-1.0 confidence)
   +------------------+
            |
            v
   +------------------+
   | Step 4: Verify   |  Angr symbolically verifies high-confidence (>0.85)
   +------------------+
            |
            v
   +------------------+
   | Step 5: Report   |  Aggregate to JSON, detect protocols, export
   +------------------+
            |
            v
   JSON/CSV/Excel/PDF Report
```

---

## Training Process Overview

### Dataset Generation

1. **Crypto Libraries**: OpenSSL 3.0, MbedTLS 3.x, WolfSSL 5.x, LibSodium
2. **Compilation**:
   ```bash
   # Example: Cross-compile OpenSSL for ARM
   ./Configure linux-armv4 --cross-compile-prefix=arm-linux-gnueabi-
   make CC="arm-linux-gnueabi-gcc -O2"
   ```
3. **Result**: 50,000+ unique binary objects with known crypto functions

### Graph Extraction

For each compiled binary:
1. Load into Ghidra headless analyzer
2. Auto-detect architecture
3. Extract P-Code for each function
4. Build CFG with NetworkX (nodes = basic blocks, edges = jumps)
5. Label using symbol table before stripping

### Model Architecture

```
Input: Function CFG (nodes with P-Code features, edges)
   |
   v
GIN Layer 1 (128 hidden) -> ReLU -> Dropout(0.2)
   |
   v
GIN Layer 2 (128 hidden) -> ReLU -> Dropout(0.2)
   |
   v
GIN Layer 3 (128 hidden) -> ReLU
   |
   v
Global Mean Pooling
   |
   v
Linear(128 -> 64) -> ReLU
   |
   v
Linear(64 -> 10) -> Softmax
   |
   v
Output: 10-class probabilities
```

### Training Parameters

- Optimizer: Adam (lr=0.001)
- Batch size: 32 graphs
- Epochs: 100 with early stopping
- Train/Val/Test split: 70/15/15
- Achieved accuracy: 94.2% on test set

---

## Installation and Running

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/CryptoHunter.git
cd CryptoHunter

# Build and start all services
docker-compose up --build

# Access points:
# - Web UI:      http://localhost:8000
# - API Docs:    http://localhost:8000/docs
# - RabbitMQ:    http://localhost:15672 (guest/guest)
# - Flower:      http://localhost:5555
```

### Option 2: Local Installation

```bash
# Prerequisites
# - Python 3.11+
# - Ghidra 11.0+ (set GHIDRA_PATH environment variable)
# - binwalk (optional, for firmware extraction)

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Set Ghidra path
export GHIDRA_PATH=/opt/ghidra  # Linux/Mac
set GHIDRA_PATH=D:\ghidra       # Windows

# Run the server
python src/standalone.py
```

### Usage

```bash
# Upload and analyze via CLI
curl -X POST -F "file=@firmware.bin" http://localhost:8000/api/analyze

# Get results
curl http://localhost:8000/api/results/{job_id}

# Export as CSV
curl http://localhost:8000/api/export/{job_id}/csv -o report.csv
```

---

## End Results and Output

### JSON Output Structure

```json
{
  "job_id": "abc12345",
  "filename": "firmware.bin",
  "status": "completed",
  "classifications": [
    {
      "name": "aes_encrypt",
      "class_id": 1,
      "class_name": "AES/Block Cipher",
      "confidence": 0.94,
      "indicator": "GNN classification"
    }
  ],
  "protocols": [
    {
      "name": "TLS_HANDSHAKE",
      "description": "TLS/SSL Protocol detected",
      "confidence": 0.85
    }
  ],
  "summary": {
    "crypto_detected": true,
    "crypto_count": 12,
    "architecture": "uImage/MIPS",
    "security_level": "medium"
  }
}
```

### Crypto Classes Detected

| Class | Name | Examples |
|-------|------|----------|
| 0 | Non-Crypto | Regular functions |
| 1 | Block Cipher | AES, DES, Blowfish, Camellia |
| 2 | Hash Function | SHA-256, SHA-512, MD5, BLAKE2 |
| 3 | Stream Cipher | ChaCha20, RC4, Salsa20 |
| 4 | Public Key | RSA, ECDSA, Ed25519, DH |
| 5 | MAC/Auth | HMAC, Poly1305, GCM |
| 6 | KDF | PBKDF2, scrypt, Argon2 |
| 7 | PRNG | CTR-DRBG, Fortuna |
| 8 | XOR/Custom | Obfuscation, custom crypto |
| 9 | Post-Quantum | Kyber, Dilithium |

---

## Pros and Cons

### Advantages

| Advantage | Explanation |
|-----------|-------------|
| **Architecture-agnostic** | P-Code normalization handles x86, ARM, MIPS, RISC-V identically |
| **Optimization-resistant** | CFG topology persists across -O0 to -O3 |
| **High accuracy** | 94% accuracy on diverse test set |
| **Scalable** | Celery workers parallelize analysis |
| **Protocol detection** | Identifies TLS, SSH, IPSec from crypto combinations |
| **Explainable** | Shows which functions triggered detection |
| **Export options** | JSON, CSV, Excel, PDF reports |

### Limitations

| Limitation | Explanation |
|------------|-------------|
| **Ghidra dependency** | Requires Ghidra installation (large, Java-based) |
| **Analysis time** | Full pipeline takes 1-5 minutes per binary |
| **Custom crypto** | Novel implementations may not match training data |
| **Encrypted firmware** | Cannot analyze encrypted sections without keys |
| **Memory usage** | Large firmwares require significant RAM |
| **False positives** | Some complex non-crypto may trigger detection |

### Mitigation Strategies

- **Custom crypto**: Add to training set and retrain
- **Encrypted firmware**: Use `firmware_intelligence` for entropy analysis
- **False positives**: Angr verification step reduces false positives
- **Performance**: XGBoost filter reduces GNN calls by 90%

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/analyze` | POST | Upload and analyze firmware |
| `/api/status/{job_id}` | GET | Get analysis status |
| `/api/results/{job_id}` | GET | Get analysis results |
| `/api/export/{job_id}/json` | GET | Export as JSON |
| `/api/export/{job_id}/csv` | GET | Export as CSV |
| `/api/export/{job_id}/excel` | GET | Export as Excel |
| `/api/export/{job_id}/pdf` | GET | Export as PDF/HTML |
| `/ws/progress/{job_id}` | WebSocket | Real-time progress |

See [docs/API.md](docs/API.md) for detailed API documentation.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

## Team

**Team IRIZ** - Smart India Hackathon 2024

## Acknowledgments

- NSA Ghidra Team for the reverse engineering framework
- PyTorch Geometric for GNN components
- ReFirmLabs for binwalk
