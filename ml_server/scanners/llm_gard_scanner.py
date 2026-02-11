"""
LLM Guard Scanner - Real-time prompt and output protection

This module wraps the llm-guard library for ML-powered security scanning.
There is NO fallback or mock mode — if llm-guard is not installed or fails
to initialize, the sidecar will crash immediately so the issue is visible.
"""

from typing import Any, Dict, Optional

from llm_guard import scan_output as llm_guard_scan_output

# ── Hard imports — crash immediately if llm-guard is not installed ────────
from llm_guard import scan_prompt as llm_guard_scan
from llm_guard.input_scanners import (
    Anonymize,
    Gibberish,
    InvisibleText,
    PromptInjection,
    Secrets,
    Toxicity,
)
from llm_guard.output_scanners import (
    Bias,
    Deanonymize,
    MaliciousURLs,
    Sensitive,
)
from llm_guard.output_scanners import (
    Toxicity as OutputToxicity,
)
from llm_guard.vault import Vault
from loguru import logger


class LLMGuardScanner:
    """
    Wrapper for LLM Guard library.
    Provides prompt injection detection, toxicity filtering, and PII protection.

    This class requires llm-guard to be installed. There is no fallback mode.
    If initialization fails, the exception propagates and the sidecar will not start.
    """

    def __init__(self, device: str = "cpu"):
        self._device = device
        logger.info(f"Initializing LLM Guard Scanner on device: {device}")

        self._initialize_scanners()

        logger.info("✅ LLM Guard Scanner initialized with REAL ML models")

    def _initialize_scanners(self):
        """Initialize LLM Guard scanners. Raises on failure — no fallback."""

        # Create vault for PII anonymization/deanonymization
        self._vault = Vault()

        # GPU vs CPU: use ONNX for CPU (faster), PyTorch for GPU
        use_gpu = self._device.startswith("cuda")
        use_onnx = not use_gpu

        # Input scanners (for prompts)
        self._input_scanners = {
            "injection": PromptInjection(use_onnx=use_onnx),
            "toxicity": Toxicity(use_onnx=use_onnx),
            "pii": Anonymize(vault=self._vault),
            "secrets": Secrets(),
            "gibberish": Gibberish(use_onnx=use_onnx),
            "invisible": InvisibleText(),
        }

        # Output scanners (for LLM responses)
        self._output_scanners = {
            "sensitive": Sensitive(use_onnx=use_onnx),
            "toxicity": OutputToxicity(use_onnx=use_onnx),
            "malicious_urls": MaliciousURLs(),
            "bias": Bias(use_onnx=use_onnx),
            "deanonymize": Deanonymize(vault=self._vault),
        }

        if use_gpu:
            logger.info(f"LLM Guard scanners initialized with GPU ({self._device})")
        else:
            logger.info("LLM Guard scanners initialized with CPU (ONNX optimized)")

    def scan_prompt(
        self,
        prompt: str,
        check_injection: bool = True,
        check_toxicity: bool = True,
        check_pii: bool = True,
        sanitize: bool = False,
    ) -> Dict[str, Any]:
        """
        Scan a prompt for threats using real LLM Guard ML models.

        Args:
            prompt: The prompt to scan
            check_injection: Check for prompt injection attacks
            check_toxicity: Check for toxic content
            check_pii: Check for PII/sensitive data
            sanitize: If True, return sanitized version of prompt

        Returns:
            Dict with 'safe', 'sanitized_prompt', 'risk_score', 'threats'
        """
        threats = []
        risk_score = 0.0

        # Select scanners based on options
        scanners_to_use = []

        if check_injection:
            scanners_to_use.append(self._input_scanners["injection"])
            scanners_to_use.append(self._input_scanners["invisible"])

        if check_toxicity:
            scanners_to_use.append(self._input_scanners["toxicity"])

        if check_pii:
            scanners_to_use.append(self._input_scanners["pii"])
            scanners_to_use.append(self._input_scanners["secrets"])

        if not scanners_to_use:
            return {
                "safe": True,
                "sanitized_prompt": prompt if sanitize else "",
                "risk_score": 0.0,
                "threats": [],
            }

        # Run scan through real LLM Guard
        sanitized, results_valid, results_score = llm_guard_scan(
            scanners_to_use, prompt
        )

        # Process results
        # In LLM Guard, is_valid=False means a threat was detected
        for scanner_name, is_valid in results_valid.items():
            score = results_score.get(scanner_name, 0.0)
            if not is_valid:
                threats.append(
                    {
                        "type": scanner_name,
                        "confidence": score,
                        "description": f"Detected potential {scanner_name} issue",
                        "severity": self._get_severity(score),
                    }
                )
                risk_score = max(risk_score, score)

        is_safe = len(threats) == 0

        return {
            "safe": is_safe,
            "sanitized_prompt": sanitized if sanitize else "",
            "risk_score": risk_score,
            "threats": threats,
        }

    def scan_output(
        self, output: str, original_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Scan LLM output for issues using real LLM Guard ML models.

        Args:
            output: The LLM output to scan
            original_prompt: The original prompt (for context)

        Returns:
            Dict with 'safe', 'sanitized_output', 'issues'
        """
        issues = []

        scanners = [
            self._output_scanners["sensitive"],
            self._output_scanners["toxicity"],
            self._output_scanners["malicious_urls"],
        ]

        sanitized, results_valid, results_score = llm_guard_scan_output(
            scanners, original_prompt or "", output
        )

        for scanner_name, valid in results_valid.items():
            if not valid:
                score = results_score.get(scanner_name, 0.0)
                issues.append(
                    {
                        "type": scanner_name,
                        "description": f"Detected potential {scanner_name} issue in output",
                        "severity": self._get_severity(1.0 - score),
                    }
                )

        is_safe = len(issues) == 0

        return {"safe": is_safe, "sanitized_output": sanitized, "issues": issues}

    def _get_severity(self, score: float) -> str:
        """Convert score to severity level"""
        if score >= 0.9:
            return "critical"
        elif score >= 0.7:
            return "high"
        elif score >= 0.4:
            return "medium"
        else:
            return "low"
