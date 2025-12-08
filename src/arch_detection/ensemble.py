"""
Ensemble detector - combines all detection methods with weighted voting.
"""
from typing import List, Dict, Optional
from collections import defaultdict
from .base import BaseDetector, ArchDetectionResult


class EnsembleDetector:
    """
    Combine multiple architecture detectors with weighted voting.
    
    Each detector has a weight, and votes are weighted by confidence × weight.
    The architecture with the highest total vote wins.
    """
    
    def __init__(self, detectors: List[BaseDetector] = None):
        """
        Initialize ensemble with detectors.
        
        Args:
            detectors: List of detector instances. If None, uses default set.
        """
        if detectors is not None:
            self.detectors = detectors
        else:
            self.detectors = self._create_default_detectors()
    
    def _create_default_detectors(self) -> List[BaseDetector]:
        """Create default set of detectors (Capstone + Header + Prologue only)."""
        detectors = []
        
        # Header detector - highest weight (authoritative when present)
        try:
            from .header_detector import HeaderDetector
            detector = HeaderDetector()
            detector.weight = 3.0  # Very high - ELF/PE headers are definitive
            detectors.append(detector)
        except ImportError:
            pass
        
        # Capstone detector - high weight (reliable disassembly analysis)
        try:
            from .capstone_detector import CapstoneDetector
            detector = CapstoneDetector()
            detector.weight = 2.0  # High - strict disassembly is reliable
            detectors.append(detector)
        except ImportError:
            pass
        
        # Prologue detector - medium weight (supporting evidence)
        try:
            from .prologue_detector import PrologueDetector
            detector = PrologueDetector()
            detector.weight = 1.0  # Medium - function patterns are helpful
            detectors.append(detector)
        except ImportError:
            pass
        
        # Note: ML n-gram detector removed - Capstone is more reliable
        
        return detectors
    
    def add_detector(self, detector: BaseDetector):
        """Add a detector to the ensemble."""
        self.detectors.append(detector)
    
    def detect(self, data: bytes) -> ArchDetectionResult:
        """
        Run all detectors and combine results with weighted voting.
        
        Args:
            data: Binary data to analyze
            
        Returns:
            Best architecture detection result
        """
        votes: Dict[str, float] = defaultdict(float)
        all_results: List[ArchDetectionResult] = []
        method_results: Dict[str, List[ArchDetectionResult]] = defaultdict(list)
        
        # Run each detector
        for detector in self.detectors:
            if not detector.is_available():
                continue
            
            try:
                results = detector.detect(data)
                for r in results:
                    # Weighted vote: confidence × detector weight
                    votes[r.architecture] += r.confidence * detector.weight
                    all_results.append(r)
                    method_results[detector.name].append(r)
            except Exception as e:
                # Log error but continue with other detectors
                continue
        
        # Handle case where no detectors produced results
        if not votes:
            return ArchDetectionResult(
                architecture="Unknown",
                confidence=0.0,
                offset=0,
                bits=32,
                endian="LE",
                method="ensemble",
                details={
                    "error": "No detectors produced results",
                    "detectors_tried": len(self.detectors)
                }
            )
        
        # Find winner (architecture with highest vote)
        winner = max(votes, key=votes.get)
        
        # Get best result for winner to extract offset/bits/endian
        winner_results = [r for r in all_results if r.architecture == winner]
        best_result = max(winner_results, key=lambda x: x.confidence)
        
        # Count how many methods agreed
        methods_agreed = len(set(r.method for r in winner_results))
        detectors_that_voted = len(method_results)  # Only count detectors that returned results
        
        # Calculate confidence based on ONLY detectors that actually contributed
        # Not all available detectors (some may return nothing for raw binaries)
        active_weight = 0.0
        for detector in self.detectors:
            if detector.name in method_results:
                active_weight += detector.weight
        
        if active_weight > 0:
            # Base confidence from weighted voting
            base_confidence = votes[winner] / active_weight
            
            # Boost confidence when multiple independent methods agree
            if methods_agreed >= 2:
                agreement_boost = 0.15 * (methods_agreed - 1)  # +15% per additional method
                base_confidence = min(base_confidence + agreement_boost, 1.0)
            
            # Boost if the best result has very high confidence
            if best_result.confidence >= 0.7:
                base_confidence = max(base_confidence, best_result.confidence)
            
            ensemble_confidence = min(base_confidence, 1.0)
        else:
            ensemble_confidence = 0.0
        
        return ArchDetectionResult(
            architecture=winner,
            confidence=ensemble_confidence,
            offset=best_result.offset,
            bits=best_result.bits,
            endian=best_result.endian,
            method="ensemble",
            details={
                "votes": dict(votes),
                "methods_agreed": methods_agreed,
                "total_methods": len([d for d in self.detectors if d.is_available()]),
                "winning_detector": best_result.method,
                "method_breakdown": {
                    name: [r.to_dict() for r in results[:2]]  # Top 2 per method
                    for name, results in method_results.items()
                }
            }
        )
    
    def detect_all(self, data: bytes) -> List[ArchDetectionResult]:
        """
        Run all detectors and return all results (not just winner).
        
        Useful for debugging or when you want to see all possibilities.
        """
        all_results = []
        
        for detector in self.detectors:
            if not detector.is_available():
                continue
            
            try:
                results = detector.detect(data)
                all_results.extend(results)
            except Exception:
                continue
        
        # Sort by confidence
        all_results.sort(key=lambda x: x.confidence, reverse=True)
        return all_results
    
    def get_detector_status(self) -> Dict[str, bool]:
        """Get availability status of all detectors."""
        return {d.name: d.is_available() for d in self.detectors}


# Convenience function
def detect_architecture(data: bytes) -> ArchDetectionResult:
    """Detect architecture using ensemble of all available methods."""
    detector = EnsembleDetector()
    return detector.detect(data)


def detect_architecture_file(path: str) -> ArchDetectionResult:
    """Detect architecture of a file."""
    with open(path, "rb") as f:
        data = f.read()
    return detect_architecture(data)
