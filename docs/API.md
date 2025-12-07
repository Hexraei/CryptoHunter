# CryptoHunter API Documentation

## Base URL

```
http://localhost:8000
```

## Endpoints

### Health Check

```http
GET /api/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-12-07T12:00:00.000Z"
}
```

---

### Analyze Binary

```http
POST /api/analyze
Content-Type: multipart/form-data
```

**Request:**
- `file`: Binary file to analyze (form-data)

**Response:**
```json
{
  "job_id": "abc12345",
  "status": "completed",
  "filename": "firmware.bin",
  "size": 1048576,
  "sha256": "...",
  "timestamp": "2024-12-07T12:00:00.000Z",
  "classifications": [
    {
      "name": "aes_encrypt",
      "class_id": 1,
      "class_name": "AES/Block Cipher",
      "confidence": 0.95,
      "indicator": "AES S-Box pattern found"
    }
  ],
  "protocols": [
    {
      "name": "TLS_HANDSHAKE",
      "description": "TLS/SSL Protocol detected",
      "confidence": 0.85
    }
  ],
  "firmware_intelligence": {
    "file_size": 1048576,
    "encryption_detected": false,
    "encryption_status": "unencrypted",
    "security_level": "low",
    "entropy_analysis": {
      "average": 5.2,
      "max": 7.1,
      "variance": 1.9
    },
    "findings": [],
    "recommendations": []
  },
  "summary": {
    "crypto_detected": true,
    "crypto_count": 5,
    "architecture": "uImage/MIPS",
    "encryption_status": "unencrypted",
    "security_level": "low"
  }
}
```

---

### Get Results

```http
GET /api/results/{job_id}
```

**Response:** Same as analyze response

---

### Get Status

```http
GET /api/status/{job_id}
```

**Response:**
```json
{
  "job_id": "abc12345",
  "status": "completed",
  "progress": 100
}
```

---

### Export Report (JSON)

```http
GET /api/export/{job_id}/json
```

**Response:** Downloads JSON file

---

## Crypto Classes

| ID | Name | Description |
|----|------|-------------|
| 0 | Non-Crypto | No cryptographic operations |
| 1 | Block Cipher | AES, DES, Blowfish, etc. |
| 2 | Hash Function | SHA, MD5, BLAKE2, etc. |
| 3 | Stream Cipher | ChaCha20, RC4, etc. |
| 4 | Public Key | RSA, ECDSA, Ed25519, etc. |
| 5 | MAC/Auth | HMAC, Poly1305, etc. |
| 6 | KDF | PBKDF2, scrypt, Argon2 |
| 7 | PRNG | Random number generators |
| 8 | XOR/Obfuscation | Custom obfuscation |
| 9 | Post-Quantum | Kyber, Dilithium |

---

## Architecture Detection

The system detects:
- **ELF architectures:** x86, x86_64, ARM, ARM64, MIPS, RISC-V, PowerPC
- **Firmware containers:** uImage (with architecture parsing)
- **Embedded formats:** Z80, AVR (Intel HEX)
- **Compressed formats:** SquashFS, LZMA, JFFS2
