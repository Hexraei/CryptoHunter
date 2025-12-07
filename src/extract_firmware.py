#!/usr/bin/env python3
"""
Firmware Extraction Script using Binwalk (primary) and Unblob (backup)
Extracts filesystems and binaries from firmware images for CryptoHunter analysis.

Usage:
    python extract_firmware.py firmware.bin
    python extract_firmware.py firmware.bin --output ./extracted/ --recursive
    python extract_firmware.py firmware.bin --use-unblob  # Force unblob
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Optional


# =============================================================================
# Configuration
# =============================================================================

BINWALK_CMD = "binwalk"  # Assumes binwalk is in PATH
UNBLOB_CMD = "unblob"    # Backup: unblob (if installed)

# Binary file extensions to extract for analysis
BINARY_EXTENSIONS = {
    '.so', '.o', '.elf', '.bin', '.exe', '.dll',
    '.ko', '.a', '.dylib', '.axf', '.out'
}

# Skip these directories during recursive extraction
SKIP_DIRS = {
    '__pycache__', '.git', 'node_modules', '.svn'
}


# =============================================================================
# Tool Availability Checks
# =============================================================================

def check_binwalk() -> bool:
    """Check if binwalk is installed."""
    try:
        result = subprocess.run(
            [BINWALK_CMD, '--help'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def check_unblob() -> bool:
    """Check if unblob is installed (backup extractor)."""
    try:
        result = subprocess.run(
            [UNBLOB_CMD, '--help'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


# =============================================================================
# Binwalk Wrapper
# =============================================================================


def scan_firmware(firmware_path: str) -> Dict:
    """
    Scan firmware with binwalk to identify contents.
    
    Args:
        firmware_path: Path to firmware file
        
    Returns:
        Dict with scan results
    """
    print(f"\n[*] Scanning: {firmware_path}")
    
    try:
        result = subprocess.run(
            [BINWALK_CMD, '-B', firmware_path],  # -B for signature scan
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        lines = result.stdout.strip().split('\n')
        findings = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('DECIMAL') and not line.startswith('-'):
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    try:
                        offset = int(parts[0])
                        findings.append({
                            'offset_decimal': offset,
                            'offset_hex': parts[1],
                            'description': parts[2]
                        })
                    except ValueError:
                        continue
        
        return {
            'file': firmware_path,
            'findings': findings,
            'count': len(findings)
        }
        
    except Exception as e:
        print(f"[!] Scan error: {e}")
        return {'file': firmware_path, 'error': str(e), 'findings': []}


def extract_firmware(firmware_path: str, output_dir: str, recursive: bool = True, 
                     depth: int = 8) -> Dict:
    """
    Extract firmware contents using binwalk.
    
    Args:
        firmware_path: Path to firmware file
        output_dir: Output directory for extracted files
        recursive: Enable recursive extraction (default: True)
        depth: Maximum recursion depth (default: 8)
        
    Returns:
        Dict with extraction results
    """
    print(f"\n[*] Extracting: {firmware_path}")
    print(f"    Output: {output_dir}")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Build binwalk command
    cmd = [BINWALK_CMD, '-e']  # -e for extract
    
    if recursive:
        cmd.extend(['-M', '-d', str(depth)])  # -M recursive, -d depth
    
    cmd.extend(['-C', output_dir])  # -C output directory
    cmd.append(firmware_path)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=600  # 10 minute timeout
        )
        
        # Find extracted files
        extracted = []
        extract_path = Path(output_dir)
        
        for root, dirs, files in os.walk(extract_path):
            # Skip unwanted directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            
            for f in files:
                full_path = Path(root) / f
                extracted.append(str(full_path))
        
        return {
            'file': firmware_path,
            'output_dir': output_dir,
            'extracted_count': len(extracted),
            'extracted_files': extracted,
            'recursive': recursive,
            'success': True
        }
        
    except subprocess.TimeoutExpired:
        print("[!] Extraction timed out")
        return {'file': firmware_path, 'error': 'timeout', 'success': False}
    except Exception as e:
        print(f"[!] Extraction error: {e}")
        return {'file': firmware_path, 'error': str(e), 'success': False}


def extract_to_raw(firmware_path: str, offset: int, size: int, output_path: str) -> bool:
    """
    Extract raw bytes from firmware at specific offset.
    
    Args:
        firmware_path: Source firmware file
        offset: Start offset in bytes
        size: Number of bytes to extract
        output_path: Output file path
        
    Returns:
        True if successful
    """
    try:
        cmd = [
            BINWALK_CMD, '-D', f'raw:{offset}:{size}',
            '-C', os.path.dirname(output_path),
            firmware_path
        ]
        subprocess.run(cmd, capture_output=True)
        return os.path.exists(output_path)
    except Exception as e:
        print(f"[!] Raw extraction error: {e}")
        return False


def find_binaries(extracted_dir: str) -> List[str]:
    """
    Find analyzable binary files in extracted directory.
    
    Args:
        extracted_dir: Path to extracted files
        
    Returns:
        List of binary file paths
    """
    binaries = []
    
    for root, dirs, files in os.walk(extracted_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        
        for f in files:
            ext = Path(f).suffix.lower()
            full_path = Path(root) / f
            
            if ext in BINARY_EXTENSIONS:
                binaries.append(str(full_path))
            elif ext == '' or ext not in {'.txt', '.md', '.json', '.xml', '.html', '.css', '.js'}:
                # Check if it's an ELF or other binary without extension
                if full_path.stat().st_size > 0:
                    try:
                        with open(full_path, 'rb') as bf:
                            magic = bf.read(4)
                            # ELF magic: \x7fELF
                            if magic == b'\x7fELF':
                                binaries.append(str(full_path))
                            # PE magic: MZ
                            elif magic[:2] == b'MZ':
                                binaries.append(str(full_path))
                    except:
                        pass
    
    return binaries


def entropy_scan(firmware_path: str) -> Dict:
    """
    Perform entropy analysis to detect encrypted/compressed regions.
    
    Args:
        firmware_path: Path to firmware file
        
    Returns:
        Dict with entropy results
    """
    print(f"\n[*] Entropy scan: {firmware_path}")
    
    try:
        result = subprocess.run(
            [BINWALK_CMD, '-E', firmware_path],  # -E for entropy
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        # Check for high entropy regions (possible encryption)
        high_entropy_regions = []
        lines = result.stdout.strip().split('\n')
        
        for line in lines:
            if 'Rising entropy edge' in line or 'Falling entropy edge' in line:
                high_entropy_regions.append(line.strip())
        
        return {
            'file': firmware_path,
            'high_entropy_regions': high_entropy_regions,
            'possible_encrypted': len(high_entropy_regions) > 0
        }
        
    except Exception as e:
        return {'file': firmware_path, 'error': str(e)}


# =============================================================================
# Unblob Wrapper (Backup)
# =============================================================================

def extract_with_unblob(firmware_path: str, output_dir: str, depth: int = 5) -> Dict:
    """
    Extract firmware using unblob (backup when binwalk fails).
    
    Args:
        firmware_path: Path to firmware file
        output_dir: Output directory for extracted files
        depth: Maximum recursion depth
        
    Returns:
        Dict with extraction results
    """
    print(f"\n[*] Extracting with unblob (backup): {firmware_path}")
    print(f"    Output: {output_dir}")
    
    if not check_unblob():
        print("[!] unblob not available")
        return {'file': firmware_path, 'success': False, 'error': 'unblob not installed'}
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Build unblob command
    cmd = [
        UNBLOB_CMD,
        '--extract-dir', output_dir,
        '--depth', str(depth),
        firmware_path
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=600  # 10 minute timeout
        )
        
        # Find extracted files
        extracted = []
        extract_path = Path(output_dir)
        
        for root, dirs, files in os.walk(extract_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                full_path = Path(root) / f
                extracted.append(str(full_path))
        
        print(f"[+] Unblob extracted {len(extracted)} files")
        
        return {
            'file': firmware_path,
            'output_dir': output_dir,
            'extracted_count': len(extracted),
            'extracted_files': extracted,
            'tool': 'unblob',
            'success': len(extracted) > 0
        }
        
    except subprocess.TimeoutExpired:
        print("[!] Unblob extraction timed out")
        return {'file': firmware_path, 'error': 'timeout', 'success': False}
    except Exception as e:
        print(f"[!] Unblob extraction error: {e}")
        return {'file': firmware_path, 'error': str(e), 'success': False}


def smart_extract(firmware_path: str, output_dir: str, recursive: bool = True,
                  depth: int = 8, force_unblob: bool = False) -> Dict:
    """
    Smart extraction: try binwalk first, fallback to unblob if needed.
    
    Args:
        firmware_path: Path to firmware file
        output_dir: Output directory
        recursive: Enable recursive extraction
        depth: Maximum recursion depth
        force_unblob: Force using unblob instead of binwalk
        
    Returns:
        Extraction results dict
    """
    binwalk_available = check_binwalk()
    unblob_available = check_unblob()
    
    print(f"\n[*] Tools available: binwalk={binwalk_available}, unblob={unblob_available}")
    
    # Force unblob if requested
    if force_unblob:
        if unblob_available:
            return extract_with_unblob(firmware_path, output_dir, depth)
        else:
            print("[!] unblob requested but not installed, trying binwalk")
    
    # Try binwalk first
    if binwalk_available:
        result = extract_firmware(firmware_path, output_dir, recursive, depth)
        
        # Check if binwalk extracted useful files
        if result.get('success'):
            binaries = find_binaries(output_dir)
            if len(binaries) > 0:
                result['binaries'] = binaries
                result['tool'] = 'binwalk'
                return result
            else:
                print("[!] Binwalk extracted no binaries, trying unblob...")
        else:
            print("[!] Binwalk extraction failed, trying unblob...")
        
        # Fallback to unblob
        if unblob_available:
            unblob_output = output_dir + "_unblob"
            unblob_result = extract_with_unblob(firmware_path, unblob_output, depth)
            if unblob_result.get('success'):
                binaries = find_binaries(unblob_output)
                unblob_result['binaries'] = binaries
                return unblob_result
    
    # Try unblob as primary if binwalk not available
    elif unblob_available:
        return extract_with_unblob(firmware_path, output_dir, depth)
    
    # Neither available
    print("[!] ERROR: Neither binwalk nor unblob is installed")
    print("    Install binwalk: pip install binwalk")
    print("    Install unblob: pip install unblob")
    return {'error': 'no extraction tools available', 'success': False}


# =============================================================================
# Main Pipeline
# =============================================================================

def analyze_firmware(firmware_path: str, output_dir: str = None, 
                     recursive: bool = True) -> Dict:
    """
    Complete firmware extraction and analysis pipeline.
    
    Args:
        firmware_path: Path to firmware file
        output_dir: Output directory (default: firmware_extracted/<name>)
        recursive: Enable recursive extraction
        
    Returns:
        Complete analysis results
    """
    if not check_binwalk():
        print("[!] ERROR: binwalk not found. Please install with:")
        print("    pip install binwalk")
        print("    or: apt install binwalk")
        return {'error': 'binwalk not installed'}
    
    firmware_path = os.path.abspath(firmware_path)
    
    if not os.path.exists(firmware_path):
        print(f"[!] File not found: {firmware_path}")
        return {'error': 'file not found'}
    
    # Set output directory
    if output_dir is None:
        base_name = Path(firmware_path).stem
        output_dir = os.path.join(os.path.dirname(firmware_path), 
                                  'firmware_extracted', base_name)
    
    print("=" * 60)
    print("  BINWALK FIRMWARE EXTRACTION")
    print("=" * 60)
    print(f"  Input: {firmware_path}")
    print(f"  Output: {output_dir}")
    
    # Step 1: Scan
    scan_result = scan_firmware(firmware_path)
    print(f"\n[+] Found {scan_result['count']} signatures")
    
    for finding in scan_result['findings'][:10]:
        print(f"    0x{finding['offset_decimal']:08X}: {finding['description'][:60]}")
    
    # Step 2: Entropy analysis
    entropy_result = entropy_scan(firmware_path)
    if entropy_result.get('possible_encrypted'):
        print(f"\n[!] High entropy regions detected (possible encryption)")
    
    # Step 3: Extract
    extract_result = extract_firmware(firmware_path, output_dir, recursive)
    print(f"\n[+] Extracted {extract_result['extracted_count']} files")
    
    # Step 4: Find binaries
    if extract_result['success']:
        binaries = find_binaries(output_dir)
        print(f"\n[+] Found {len(binaries)} analyzable binaries")
        for b in binaries[:10]:
            print(f"    • {os.path.basename(b)}")
    else:
        binaries = []
    
    # Compile results
    results = {
        'firmware': firmware_path,
        'output_dir': output_dir,
        'scan': scan_result,
        'entropy': entropy_result,
        'extraction': extract_result,
        'binaries': binaries,
        'binary_count': len(binaries)
    }
    
    # Save results
    results_path = os.path.join(output_dir, 'extraction_results.json')
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\\n[+] Results saved: {results_path}")
    
    print("\\n" + "=" * 60)
    print("  EXTRACTION COMPLETE")
    print("=" * 60)
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description='Extract firmware contents using binwalk (with unblob backup)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python extract_firmware.py firmware.bin
  python extract_firmware.py router.bin --output ./extracted/
  python extract_firmware.py firmware.bin --use-unblob  # Force unblob

Extraction Strategy:
  1. Try binwalk first (faster, good for most firmware)
  2. If binwalk fails or extracts no binaries, fallback to unblob
  3. Use --use-unblob to skip binwalk and use unblob directly

Requirements:
  Primary:   pip install binwalk
  Backup:    pip install unblob (optional)
        """
    )
    
    parser.add_argument('firmware', help='Path to firmware file')
    parser.add_argument('-o', '--output', help='Output directory for extracted files')
    parser.add_argument('--no-recursive', action='store_true',
                       help='Disable recursive extraction')
    parser.add_argument('-d', '--depth', type=int, default=8,
                       help='Maximum recursion depth (default: 8)')
    parser.add_argument('--scan-only', action='store_true',
                       help='Only scan, do not extract')
    parser.add_argument('--use-unblob', action='store_true',
                       help='Force using unblob instead of binwalk')
    parser.add_argument('-j', '--json', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.firmware):
        print(f"Error: File not found: {args.firmware}")
        sys.exit(1)
    
    if args.scan_only:
        result = scan_firmware(args.firmware)
        print(json.dumps(result, indent=2))
    elif args.use_unblob:
        output_dir = args.output or f"extracted_{Path(args.firmware).stem}"
        result = smart_extract(args.firmware, output_dir, force_unblob=True)
    else:
        recursive = not args.no_recursive
        result = analyze_firmware(args.firmware, args.output, recursive)
        
    if args.json and result:
        with open(args.json, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\\nResults saved to: {args.json}")


if __name__ == '__main__':
    main()

