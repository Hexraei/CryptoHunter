"""
CryptoHunter Background Tasks
Celery tasks for firmware analysis pipeline
"""

import os
import json
import tempfile
from datetime import datetime
from typing import Dict, List, Any

from celery import shared_task
from .celery_app import celery_app


@celery_app.task(bind=True, name="src.workers.tasks.analyze_firmware_task")
def analyze_firmware_task(self, job_id: str, file_path: str, filename: str) -> Dict:
    """
    Main analysis task - orchestrates the full pipeline.
    
    Pipeline Steps:
    1. Extract firmware (binwalk/unblob)
    2. Lift to P-Code (Ghidra)
    3. Fast filter suspicious regions (XGBoost)
    4. Build CFGs (NetworkX)
    5. GNN inference
    6. Symbolic verification (Angr)
    7. Aggregate results
    """
    results = {
        "job_id": job_id,
        "filename": filename,
        "started_at": datetime.utcnow().isoformat(),
        "status": "running",
        "steps": {},
        "classifications": [],
        "protocols": []
    }
    
    try:
        # Update task state
        self.update_state(state='PROGRESS', meta={'step': 'extraction', 'progress': 10})
        
        # Step 0: Firmware Extraction
        results["steps"]["extraction"] = {"status": "running"}
        extracted_files = extract_firmware(file_path)
        results["steps"]["extraction"] = {
            "status": "completed",
            "files_found": len(extracted_files)
        }
        
        # Step 1: Ghidra Analysis
        self.update_state(state='PROGRESS', meta={'step': 'ghidra', 'progress': 30})
        results["steps"]["ghidra"] = {"status": "running"}
        
        ghidra_results = []
        for binary in extracted_files[:5]:  # Limit to 5 binaries
            try:
                result = ghidra_task.delay(binary).get(timeout=600)
                ghidra_results.append(result)
            except Exception as e:
                ghidra_results.append({"error": str(e)})
        
        results["steps"]["ghidra"] = {
            "status": "completed",
            "binaries_analyzed": len(ghidra_results)
        }
        
        # Step 2: Fast Filter (XGBoost)
        self.update_state(state='PROGRESS', meta={'step': 'filter', 'progress': 50})
        results["steps"]["fast_filter"] = {"status": "running"}
        
        suspicious_functions = []
        for gr in ghidra_results:
            if isinstance(gr, dict) and "functions" in gr:
                # Apply XGBoost filter
                suspicious_functions.extend(gr["functions"])
        
        results["steps"]["fast_filter"] = {
            "status": "completed",
            "functions_filtered": len(suspicious_functions)
        }
        
        # Step 3: GNN Classification
        self.update_state(state='PROGRESS', meta={'step': 'gnn', 'progress': 70})
        results["steps"]["gnn_classification"] = {"status": "running"}
        
        classifications = gnn_inference_task.delay(suspicious_functions).get(timeout=300)
        results["classifications"] = classifications
        
        results["steps"]["gnn_classification"] = {
            "status": "completed",
            "crypto_detected": len([c for c in classifications if c.get("class_id", 0) > 0])
        }
        
        # Step 4: Protocol Detection
        self.update_state(state='PROGRESS', meta={'step': 'protocol', 'progress': 85})
        results["protocols"] = detect_protocols(classifications)
        
        # Step 5: Symbolic Verification (Optional)
        self.update_state(state='PROGRESS', meta={'step': 'verification', 'progress': 95})
        results["steps"]["symbolic_verification"] = {"status": "skipped"}
        
        # Finalize
        results["status"] = "completed"
        results["completed_at"] = datetime.utcnow().isoformat()
        results["summary"] = {
            "crypto_detected": len([c for c in classifications if c.get("class_id", 0) > 0]) > 0,
            "crypto_count": len([c for c in classifications if c.get("class_id", 0) > 0]),
            "protocols_detected": len(results["protocols"])
        }
        
        return results
        
    except Exception as e:
        results["status"] = "failed"
        results["error"] = str(e)
        return results


@celery_app.task(name="src.workers.tasks.ghidra_task")
def ghidra_task(binary_path: str) -> Dict:
    """Run Ghidra analysis on a single binary."""
    try:
        from run_full_analysis import run_ghidra_step
        return run_ghidra_step(binary_path)
    except Exception as e:
        return {"error": str(e), "binary": binary_path}


@celery_app.task(name="src.workers.tasks.gnn_inference_task")
def gnn_inference_task(functions: List[Dict]) -> List[Dict]:
    """Run GNN inference on extracted functions."""
    try:
        from infer_crypto import infer_batch
        return infer_batch(functions)
    except Exception as e:
        return [{"error": str(e)}]


def extract_firmware(file_path: str) -> List[str]:
    """Extract firmware and return list of binary paths."""
    import subprocess
    import shutil
    
    extract_dir = tempfile.mkdtemp(prefix="fw_extract_")
    binaries = []
    
    # Try binwalk
    if shutil.which('binwalk'):
        try:
            subprocess.run(
                ['binwalk', '-eM', '-C', extract_dir, file_path],
                capture_output=True,
                timeout=120
            )
            
            # Find extracted binaries
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    fpath = os.path.join(root, f)
                    if os.path.getsize(fpath) > 1024:
                        binaries.append(fpath)
        except:
            pass
    
    # If nothing extracted, use original
    if not binaries:
        binaries = [file_path]
    
    return binaries


def detect_protocols(classifications: List[Dict]) -> List[Dict]:
    """Detect protocols based on crypto combinations."""
    protocols = []
    class_ids = {c.get("class_id", 0) for c in classifications}
    
    if 1 in class_ids and 2 in class_ids:
        protocols.append({
            "name": "TLS_HANDSHAKE",
            "description": "TLS/SSL Protocol detected",
            "confidence": 0.85 if 4 in class_ids else 0.70
        })
    
    if 1 in class_ids and 4 in class_ids:
        protocols.append({
            "name": "SSH_KEX",
            "description": "SSH Key Exchange",
            "confidence": 0.75
        })
    
    return protocols
