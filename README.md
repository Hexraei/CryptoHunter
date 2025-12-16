# CryptoHunter

**AI/ML-Powered Cryptographic Primitive Detection in Binary Firmware**

## Quick Start

### Docker (Recommended)

```bash
git clone https://github.com/your-org/CryptoHunter.git
cd CryptoHunter
docker-compose up --build

# Access:
# - Web UI: http://localhost:8000
# - API Docs: http://localhost:8000/docs
```

### Local Installation

```bash
python -m venv venv
.\venv\Scripts\activate        # Windows
source venv/bin/activate       # Linux/Mac

pip install -r requirements.txt

# Set Ghidra path
set GHIDRA_PATH=D:\ghidra      # Windows
export GHIDRA_PATH=/opt/ghidra # Linux/Mac

python src/standalone.py
```

## How It Works

CryptoHunter uses **Graph Neural Networks (GNN)** to detect cryptographic functions by analyzing control flow graph (CFG) structure. The approach is:

1. **Architecture-agnostic** - Works on ARM, x86, MIPS, RISC-V
2. **Optimization-resistant** - CFG topology preserved across -O0 to -O3
3. **Compiler-independent** - Consistent across GCC/Clang

### Pipeline

```
Firmware → binwalk/unblob → Ghidra P-Code → XGBoost Filter → GNN → Angr Verify → Report
```

## Project Structure

```
CryptoHunter/
├── src/
│   ├── standalone.py          # FastAPI server
│   ├── run_full_analysis.py   # Analysis pipeline
│   ├── infer_crypto.py        # GNN inference
│   ├── xgboost_filter.py      # Fast pre-filter
│   └── symbolic_verify.py     # Angr verification
├── models/
│   ├── model.pt               # Trained GNN model
│   └── xgboost_filter.json    # XGBoost filter model
├── frontend/                   # Web UI
├── Train model/               # Training scripts
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze` | POST | Upload and analyze firmware |
| `/api/results/{job_id}` | GET | Get analysis results |
| `/api/export/{job_id}/json` | GET | Export as JSON |
| `/api/health` | GET | Health check |

## Detected Crypto Classes

| Class | Description |
|-------|-------------|
| 1 | Block Cipher (AES, DES) |
| 2 | Hash Function (SHA, MD5) |
| 3 | Stream Cipher (ChaCha, RC4) |
| 4 | Public Key (RSA, ECDSA) |
| 5 | Auth/MAC (HMAC, GCM) |
| 6 | KDF (PBKDF2, scrypt) |
| 7 | PRNG (DRBG) |
| 8 | XOR/Custom |
| 9 | Post-Quantum (Kyber) |

## Training Your Own Model

See `Train model/README.md` for instructions on:
- Downloading datasets from GitHub
- Preparing training data
- Training the GNN model
- Evaluating accuracy

## License

MIT License - See [LICENSE](LICENSE)

## Team

**Team IRIZ** - Smart India Hackathon 2024
