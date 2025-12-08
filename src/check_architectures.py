#!/usr/bin/env python3
"""
Unified Architecture Detection Script for CryptoHunter Framework
Detects Z80, AVR, Xtensa (ESP32/ESP8266), and other architectures in binary files.

This script combines detection for multiple embedded architectures:
- Z80 (8-bit, Zilog)
- AVR (8-bit, Atmel/Microchip/Arduino)
- Xtensa (32-bit, ESP32/ESP8266/Cadence)

GitHub References:
Z80:
  - Vector35/Z80: https://github.com/Vector35/Z80
  - z80dismblr: https://github.com/nicschumann/z80dismblr
  - lvitals/z80dasm: https://github.com/lvitals/z80dasm
  
AVR:
  - vsergeev/vavrdisasm: https://github.com/vsergeev/vavrdisasm
  - imrehorvath/avrdis: https://github.com/imrehorvath/avrdis
  - twinearthsoftware/AVRDisassembler: https://github.com/twinearthsoftware/AVRDisassembler

Xtensa (ESP32/ESP8266):
  - Espressif ESP-IDF: https://github.com/espressif/esp-idf
  - Ghidra Xtensa: https://github.com/yath/ghidra-xtensa
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import our detection modules
from check_z80 import detect_z80, Z80Detector
from check_avr import detect_avr, AVRDetector
from check_xtensa import detect_xtensa, XtensaDetector


class UnifiedArchDetector:
    """Unified architecture detector supporting multiple architectures."""
    
    SUPPORTED_ARCHITECTURES = ['z80', 'avr', 'xtensa']
    
    def __init__(self):
        self.results = []
        
    def detect_file(self, filepath: str) -> Dict:
        """
        Detect architecture of a single binary file.
        Tries all supported architectures and returns the best match.
        
        Args:
            filepath: Path to binary file
            
        Returns:
            Detection result dictionary
        """
        results = {}
        
        # Run Z80 detection
        z80_result = detect_z80(filepath)
        if z80_result.get('confidence', 0) > 0:
            results['z80'] = z80_result
            
        # Run AVR detection
        avr_result = detect_avr(filepath)
        if avr_result.get('confidence', 0) > 0:
            results['avr'] = avr_result
            
        # Run Xtensa/ESP32 detection
        xtensa_result = detect_xtensa(filepath)
        if xtensa_result.get('confidence', 0) > 0:
            results['xtensa'] = xtensa_result
            
        # Find best match
        best_arch = None
        best_confidence = 0.0
        
        for arch, result in results.items():
            conf = result.get('confidence', 0)
            if conf > best_confidence:
                best_confidence = conf
                best_arch = arch
                
        if best_arch and best_confidence >= 0.5:
            best_result = results[best_arch]
            return {
                'filepath': filepath,
                'detected': True,
                'architecture': best_arch.upper(),
                'confidence': best_confidence,
                'details': best_result,
                'all_results': results,
            }
        else:
            return {
                'filepath': filepath,
                'detected': False,
                'architecture': 'unknown',
                'confidence': best_confidence,
                'all_results': results,
            }
    
    def detect_directory(self, 
                         directory: str, 
                         extensions: List[str] = None,
                         architecture: str = None,
                         workers: int = 4) -> List[Dict]:
        """
        Scan a directory for binaries of specified architecture(s).
        
        Args:
            directory: Directory to scan
            extensions: File extensions to check
            architecture: Specific architecture to detect (or None for all)
            workers: Number of parallel workers
            
        Returns:
            List of detection results
        """
        path = Path(directory)
        if not path.exists():
            return []
            
        files = []
        for file in path.rglob('*'):
            if file.is_file():
                if extensions:
                    if file.suffix.lower() in extensions:
                        files.append(str(file))
                else:
                    files.append(str(file))
                    
        results = []
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.detect_file, f): f for f in files}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result.get('detected'):
                        # Filter by architecture if specified
                        if architecture is None or result['architecture'].lower() == architecture.lower():
                            results.append(result)
                except Exception as e:
                    filepath = futures[future]
                    print(f"Error processing {filepath}: {e}")
                    
        return results


def print_summary(results: List[Dict]):
    """Print a summary of detection results."""
    if not results:
        print("\nNo embedded architecture binaries detected.")
        return
        
    print(f"\n{'='*60}")
    print(f"ARCHITECTURE DETECTION SUMMARY")
    print(f"{'='*60}")
    
    # Group by architecture
    arch_groups = {}
    for r in results:
        arch = r.get('architecture', 'unknown')
        if arch not in arch_groups:
            arch_groups[arch] = []
        arch_groups[arch].append(r)
        
    for arch, group in arch_groups.items():
        print(f"\n{arch} Architecture ({len(group)} files):")
        print(f"{'-'*40}")
        for r in group[:10]:  # Show first 10
            confidence = r.get('confidence', 0)
            filepath = Path(r.get('filepath', '')).name
            print(f"  {filepath}: {confidence:.1%}")
        if len(group) > 10:
            print(f"  ... and {len(group) - 10} more")
            
    print(f"\n{'='*60}")
    print(f"Total: {len(results)} embedded architecture binaries detected")
    

def main():
    parser = argparse.ArgumentParser(
        description='Detect Z80 and AVR architecture binaries',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python check_architectures.py firmware.bin
  python check_architectures.py --arch avr ./binaries/
  python check_architectures.py -r -j results.json ./firmware/
  
GitHub References:
  Z80:
    - Vector35/Z80: https://github.com/Vector35/Z80
    - z80dismblr: https://github.com/nicschumann/z80dismblr
    - lvitals/z80dasm: https://github.com/lvitals/z80dasm
    
  AVR:
    - vsergeev/vavrdisasm: https://github.com/vsergeev/vavrdisasm
    - imrehorvath/avrdis: https://github.com/imrehorvath/avrdis
    - twinearthsoftware/AVRDisassembler: https://github.com/twinearthsoftware/AVRDisassembler
        """
    )
    
    parser.add_argument('target', help='File or directory to analyze')
    parser.add_argument('-a', '--arch', choices=['z80', 'avr', 'all'], 
                        default='all', help='Architecture to detect (default: all)')
    parser.add_argument('-e', '--extensions', nargs='+',
                        help='File extensions to check (e.g., .bin .hex)')
    parser.add_argument('-j', '--json', metavar='FILE',
                        help='Output results to JSON file')
    parser.add_argument('-r', '--recursive', action='store_true',
                        help='Recursively scan directories')
    parser.add_argument('-w', '--workers', type=int, default=4,
                        help='Number of parallel workers (default: 4)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    
    args = parser.parse_args()
    
    detector = UnifiedArchDetector()
    
    target = args.target
    arch = None if args.arch == 'all' else args.arch
    
    if os.path.isfile(target):
        # Single file
        result = detector.detect_file(target)
        
        if args.verbose:
            print(json.dumps(result, indent=2))
        else:
            if result.get('detected'):
                print(f"Architecture: {result['architecture']}")
                print(f"Confidence: {result['confidence']:.1%}")
                details = result.get('details', {})
                indicators = details.get('indicators', [])
                if indicators:
                    print("Indicators:")
                    for ind in indicators:
                        print(f"  - {ind}")
            else:
                print("No Z80 or AVR architecture detected")
                if result.get('all_results'):
                    best_conf = max(r.get('confidence', 0) 
                                    for r in result['all_results'].values())
                    if best_conf > 0:
                        print(f"Best match confidence: {best_conf:.1%}")
                        
        results = [result]
        
    elif os.path.isdir(target):
        # Directory scan
        print(f"Scanning directory: {target}")
        
        extensions = None
        if args.extensions:
            extensions = [e if e.startswith('.') else f'.{e}' for e in args.extensions]
            
        results = detector.detect_directory(
            target,
            extensions=extensions,
            architecture=arch,
            workers=args.workers
        )
        
        print_summary(results)
        
    else:
        print(f"Error: {target} not found")
        sys.exit(1)
        
    # Save to JSON if requested
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {args.json}")


if __name__ == '__main__':
    main()
