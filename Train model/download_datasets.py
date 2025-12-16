"""
CryptoHunter Dataset Downloader

This script downloads and prepares datasets from GitHub repositories
containing crypto library binaries for training the GNN model.

Supported Libraries:
- OpenSSL (various versions)
- mbedTLS
- WolfSSL
- LibSodium

Usage:
    python download_datasets.py --output ./datasets --libraries openssl,mbedtls
"""

import os
import sys
import json
import shutil
import zipfile
import tarfile
import argparse
import subprocess
from pathlib import Path
from urllib.request import urlretrieve


# Dataset sources (GitHub repositories and release assets)
DATASET_SOURCES = {
    "openssl": {
        "description": "OpenSSL crypto library",
        "repo": "https://github.com/openssl/openssl",
        "releases": [
            "https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.0.zip",
        ],
        "compile_targets": ["linux-x86_64", "linux-armv4", "linux-aarch64", "linux-mips32"],
    },
    "mbedtls": {
        "description": "mbedTLS embedded crypto library",
        "repo": "https://github.com/Mbed-TLS/mbedtls",
        "releases": [
            "https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.5.0.zip",
        ],
        "compile_targets": ["arm-none-eabi", "x86_64-linux-gnu", "mips-linux-gnu"],
    },
    "wolfssl": {
        "description": "WolfSSL embedded crypto library",
        "repo": "https://github.com/wolfSSL/wolfssl",
        "releases": [
            "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.6.3-stable.zip",
        ],
        "compile_targets": ["arm-none-eabi", "x86_64-linux-gnu"],
    },
    "libsodium": {
        "description": "LibSodium modern crypto library",
        "repo": "https://github.com/jedisct1/libsodium",
        "releases": [
            "https://github.com/jedisct1/libsodium/archive/refs/tags/1.0.19-RELEASE.zip",
        ],
        "compile_targets": ["x86_64", "arm", "aarch64"],
    },
}


def download_file(url, output_path):
    """Download a file from URL with progress."""
    print(f"  Downloading: {os.path.basename(output_path)}...")
    try:
        urlretrieve(url, output_path)
        return True
    except Exception as e:
        print(f"  Error downloading {url}: {e}")
        return False


def extract_archive(archive_path, output_dir):
    """Extract ZIP or TAR archive."""
    print(f"  Extracting: {os.path.basename(archive_path)}...")
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as z:
                z.extractall(output_dir)
        elif archive_path.endswith(('.tar.gz', '.tgz')):
            with tarfile.open(archive_path, 'r:gz') as t:
                t.extractall(output_dir)
        return True
    except Exception as e:
        print(f"  Error extracting {archive_path}: {e}")
        return False


def clone_repository(repo_url, output_dir, depth=1):
    """Clone a Git repository."""
    print(f"  Cloning: {repo_url}...")
    try:
        cmd = ["git", "clone", "--depth", str(depth), repo_url, output_dir]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.returncode == 0
    except Exception as e:
        print(f"  Error cloning {repo_url}: {e}")
        return False


def download_library(lib_name, lib_config, output_dir):
    """Download a single library from configured sources."""
    lib_dir = output_dir / lib_name
    lib_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\nDownloading {lib_name} ({lib_config['description']})...")
    
    # Download releases
    for release_url in lib_config.get("releases", []):
        filename = os.path.basename(release_url)
        archive_path = lib_dir / filename
        
        if download_file(release_url, str(archive_path)):
            extract_archive(str(archive_path), str(lib_dir))
            archive_path.unlink()  # Remove archive after extraction
    
    # Clone repository if no releases
    if not lib_config.get("releases"):
        clone_repository(lib_config["repo"], str(lib_dir / "source"), depth=1)
    
    return True


def find_binaries(directory):
    """Find all binary files in a directory."""
    binaries = []
    binary_extensions = {'.o', '.so', '.a', '.elf', '.bin', '.ko', '.out'}
    
    for root, dirs, files in os.walk(directory):
        for f in files:
            fpath = Path(root) / f
            ext = fpath.suffix.lower()
            
            # Check extension
            if ext in binary_extensions:
                binaries.append(fpath)
                continue
            
            # Check ELF magic
            try:
                with open(fpath, 'rb') as bf:
                    if bf.read(4) == b'\x7fELF':
                        binaries.append(fpath)
            except:
                pass
    
    return binaries


def main():
    parser = argparse.ArgumentParser(description="Download crypto library datasets")
    parser.add_argument("--output", "-o", default="./datasets",
                       help="Output directory for datasets")
    parser.add_argument("--libraries", "-l", default="all",
                       help="Comma-separated list of libraries (or 'all')")
    parser.add_argument("--list", action="store_true",
                       help="List available libraries")
    
    args = parser.parse_args()
    
    if args.list:
        print("Available libraries:")
        for name, config in DATASET_SOURCES.items():
            print(f"  {name}: {config['description']}")
        return
    
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Select libraries
    if args.libraries == "all":
        libraries = list(DATASET_SOURCES.keys())
    else:
        libraries = [l.strip() for l in args.libraries.split(",")]
    
    print(f"CryptoHunter Dataset Downloader")
    print(f"Output directory: {output_dir.absolute()}")
    print(f"Libraries to download: {', '.join(libraries)}")
    
    # Download each library
    for lib_name in libraries:
        if lib_name not in DATASET_SOURCES:
            print(f"Unknown library: {lib_name}")
            continue
        
        download_library(lib_name, DATASET_SOURCES[lib_name], output_dir)
    
    # Summary
    print("\n" + "="*60)
    print("Download Complete!")
    print("="*60)
    
    all_binaries = find_binaries(output_dir)
    print(f"Total binaries found: {len(all_binaries)}")
    
    # Save manifest
    manifest = {
        "output_dir": str(output_dir.absolute()),
        "libraries": libraries,
        "binary_count": len(all_binaries),
        "binaries": [str(b) for b in all_binaries[:100]]  # First 100
    }
    
    with open(output_dir / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    
    print(f"Manifest saved to: {output_dir / 'manifest.json'}")


if __name__ == "__main__":
    main()
