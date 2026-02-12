"""
LLM Guard Scanner - Full Scanner Support with Dynamic Configuration (GPU-ONLY)

This module wraps the llm-guard library for ML-powered security scanning.
It supports ALL prompt (input) and output scanners with per-scanner
configuration passed dynamically via gRPC AdvancedScan requests.

There is NO fallback or mock mode — if llm-guard is not installed or fails
to initialize, the sidecar will crash immediately so the issue is visible.

GPU ONLY: This scanner requires an NVIDIA CUDA-capable GPU. It will NOT
run on CPU. If no GPU is detected, initialization fails immediately.

Supported Input (Prompt) Scanners:
  anonymize, ban_code, ban_competitors, ban_substrings, ban_topics,
  code, gibberish, invisible_text, language, prompt_injection,
  regex, secrets, sentiment, token_limit, toxicity

Supported Output Scanners:
  ban_code, ban_competitors, ban_substrings, ban_topics, bias,
  code, deanonymize, json, language, language_same, malicious_urls,
  no_refusal, reading_time, factual_consistency, gibberish, regex,
  relevance, sensitive, sentiment, toxicity, url_reachability
"""

import json
import time
from typing import Any, Dict, List, Optional, Tuple

import torch
from llm_guard import scan_output as llm_guard_scan_output
from llm_guard import scan_prompt as llm_guard_scan_prompt

# ── Input (Prompt) Scanner Imports ────────────────────────────────────────
from llm_guard.input_scanners import (
    Anonymize,
    BanCode,
    BanCompetitors,
    BanSubstrings,
    BanTopics,
    Code,
    Gibberish,
    InvisibleText,
    Language,
    PromptInjection,
    Regex,
    Secrets,
    Sentiment,
    TokenLimit,
    Toxicity,
)
from llm_guard.output_scanners import BanCode as OutputBanCode
from llm_guard.output_scanners import BanCompetitors as OutputBanCompetitors
from llm_guard.output_scanners import BanSubstrings as OutputBanSubstrings
from llm_guard.output_scanners import BanTopics as OutputBanTopics

# ── Output Scanner Imports ────────────────────────────────────────────────
from llm_guard.output_scanners import (
    Bias,
    Deanonymize,
    LanguageSame,
    MaliciousURLs,
    NoRefusal,
    Relevance,
    Sensitive,
    URLReachability,
)
from llm_guard.output_scanners import Code as OutputCode
from llm_guard.output_scanners import Gibberish as OutputGibberish
from llm_guard.output_scanners import Language as OutputLanguage
from llm_guard.output_scanners import Regex as OutputRegex
from llm_guard.output_scanners import Sentiment as OutputSentiment
from llm_guard.output_scanners import Toxicity as OutputToxicity
from llm_guard.vault import Vault
from loguru import logger

# Conditional imports — some scanners may not exist in all llm-guard versions
try:
    from llm_guard.output_scanners import FactualConsistency

    HAS_FACTUAL_CONSISTENCY = True
except ImportError:
    HAS_FACTUAL_CONSISTENCY = False
    logger.warning("FactualConsistency scanner not available in this llm-guard version")

try:
    from llm_guard.output_scanners import JSON as JSONScanner

    HAS_JSON_SCANNER = True
except ImportError:
    HAS_JSON_SCANNER = False
    logger.warning("JSON scanner not available in this llm-guard version")

try:
    from llm_guard.output_scanners import ReadingTime

    HAS_READING_TIME = True
except ImportError:
    HAS_READING_TIME = False
    logger.warning("ReadingTime scanner not available in this llm-guard version")


# ── Constants ─────────────────────────────────────────────────────────────

# All supported input scanner names (snake_case, matches proto keys)
ALL_INPUT_SCANNERS = [
    "anonymize",
    "ban_code",
    "ban_competitors",
    "ban_substrings",
    "ban_topics",
    "code",
    "gibberish",
    "invisible_text",
    "language",
    "prompt_injection",
    "regex",
    "secrets",
    "sentiment",
    "token_limit",
    "toxicity",
]

# All supported output scanner names (snake_case, matches proto keys)
ALL_OUTPUT_SCANNERS = [
    "ban_code",
    "ban_competitors",
    "ban_substrings",
    "ban_topics",
    "bias",
    "code",
    "deanonymize",
    "json",
    "language",
    "language_same",
    "malicious_urls",
    "no_refusal",
    "reading_time",
    "factual_consistency",
    "gibberish",
    "regex",
    "relevance",
    "sensitive",
    "sentiment",
    "toxicity",
    "url_reachability",
]

# Default input scanners when no explicit config is provided
DEFAULT_INPUT_SCANNERS = [
    "prompt_injection",
    "toxicity",
    "anonymize",
    "secrets",
    "gibberish",
    "invisible_text",
]

# Default output scanners when no explicit config is provided
DEFAULT_OUTPUT_SCANNERS = [
    "sensitive",
    "toxicity",
    "malicious_urls",
    "bias",
    "deanonymize",
]


def _parse_settings(settings_json: str) -> dict:
    """Safely parse scanner settings JSON string."""
    if not settings_json or settings_json.strip() == "":
        return {}
    try:
        parsed = json.loads(settings_json)
        if isinstance(parsed, dict):
            return parsed
        return {}
    except (json.JSONDecodeError, TypeError):
        logger.warning(f"Failed to parse scanner settings JSON: {settings_json!r}")
        return {}


class LLMGuardScanner:
    """
    Full-featured wrapper for LLM Guard library — GPU ONLY.

    Supports ALL input and output scanners with dynamic per-scanner
    configuration. Scanners can be configured at init time (defaults)
    or dynamically per-request via AdvancedScan.

    This class requires:
      - llm-guard to be installed
      - An NVIDIA CUDA-capable GPU to be available
    There is no CPU fallback mode.
    """

    def __init__(self, device: str = "cuda"):
        # ── GPU validation — refuse to start without CUDA ────────────
        if not torch.cuda.is_available():
            raise RuntimeError(
                "❌ FATAL: No CUDA-capable GPU detected!\n"
                "This ML sidecar is GPU-ONLY and will NOT run on CPU.\n"
                "Requirements:\n"
                "  • NVIDIA GPU with CUDA support\n"
                "  • NVIDIA drivers installed on the host\n"
                "  • NVIDIA Container Toolkit installed (for Docker)\n"
                "  • Container started with --gpus all (or deploy.resources in compose)\n"
                "Verify with: nvidia-smi"
            )

        if not device.startswith("cuda"):
            raise RuntimeError(
                f"❌ FATAL: Device '{device}' is not a CUDA device.\n"
                "This ML sidecar is GPU-ONLY. Only 'cuda' or 'cuda:N' devices "
                "are accepted. CPU mode has been removed."
            )

        self._device = device
        self._use_onnx = False  # GPU-ONLY: always use PyTorch

        gpu_name = torch.cuda.get_device_name(0)
        gpu_mem = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        logger.info(
            f"🚀 GPU detected: {gpu_name} ({gpu_mem:.1f} GB VRAM) — "
            f"initializing LLM Guard Scanner on device: {device}"
        )

        # Create vault for PII anonymization/deanonymization
        self._vault = Vault()

        # Initialize default scanner instances (used for legacy endpoints)
        self._default_input_scanners = {}
        self._default_output_scanners = {}
        self._initialize_default_scanners()

        logger.info(
            f"✅ LLM Guard Scanner initialized with ALL scanner support on GPU ({gpu_name})"
        )

    # ════════════════════════════════════════════════════════════════
    # Default Scanner Initialization (Legacy Endpoints)
    # ════════════════════════════════════════════════════════════════

    def _initialize_default_scanners(self):
        """Initialize default scanner instances for legacy ScanPrompt/ScanOutput."""
        logger.info("Initializing default input scanners...")

        self._default_input_scanners = {
            "prompt_injection": PromptInjection(use_onnx=self._use_onnx, threshold=0.5),
            "toxicity": Toxicity(use_onnx=self._use_onnx, threshold=0.70),
            "anonymize": Anonymize(vault=self._vault, threshold=0.60),
            "secrets": Secrets(),
            "gibberish": Gibberish(use_onnx=self._use_onnx, threshold=0.70),
            "invisible_text": InvisibleText(),
        }

        logger.info("Initializing default output scanners...")

        self._default_output_scanners = {
            "sensitive": Sensitive(use_onnx=self._use_onnx),
            "toxicity": OutputToxicity(use_onnx=self._use_onnx, threshold=0.70),
            "malicious_urls": MaliciousURLs(),
            "bias": Bias(use_onnx=self._use_onnx, threshold=0.70),
            "deanonymize": Deanonymize(vault=self._vault),
        }

        logger.info(
            f"Default scanners initialized — "
            f"{len(self._default_input_scanners)} input, "
            f"{len(self._default_output_scanners)} output"
        )

    # ════════════════════════════════════════════════════════════════
    # Dynamic Scanner Factory
    # ════════════════════════════════════════════════════════════════

    def _build_input_scanner(self, name: str, threshold: float, settings: dict):
        """
        Build an input scanner instance from its name and settings.
        Returns the scanner instance or None if the scanner can't be built.
        """
        try:
            if name == "anonymize":
                kwargs = {}
                if "entity_types" in settings:
                    kwargs["entity_types"] = settings["entity_types"]
                if "use_faker" in settings:
                    kwargs["use_faker"] = bool(settings["use_faker"])
                if "language" in settings:
                    kwargs["language"] = settings["language"]
                if "preamble" in settings:
                    kwargs["preamble"] = settings["preamble"]
                if "hidden_names" in settings:
                    kwargs["hidden_names"] = settings["hidden_names"]
                if "allowed_names" in settings:
                    kwargs["allowed_names"] = settings["allowed_names"]
                # PII scanner: enforce minimum threshold of 0.60 to reduce
                # false positives on benign text that mentions names/places.
                pii_threshold = max(threshold, 0.60)
                return Anonymize(vault=self._vault, threshold=pii_threshold, **kwargs)

            elif name == "ban_code":
                kwargs = {}
                if "languages" in settings:
                    kwargs["languages"] = settings["languages"]
                if "is_blocked" in settings:
                    kwargs["is_blocked"] = bool(settings["is_blocked"])
                return BanCode(use_onnx=self._use_onnx, threshold=threshold, **kwargs)

            elif name == "ban_competitors":
                competitors = settings.get("competitors", [])
                if not competitors:
                    logger.warning(
                        "BanCompetitors scanner requires 'competitors' list in settings"
                    )
                    return None
                kwargs = {"competitors": competitors, "threshold": threshold}
                if "redact" in settings:
                    kwargs["redact"] = bool(settings["redact"])
                return BanCompetitors(use_onnx=self._use_onnx, **kwargs)

            elif name == "ban_substrings":
                substrings = settings.get("substrings", [])
                if not substrings:
                    logger.warning(
                        "BanSubstrings scanner requires 'substrings' list in settings"
                    )
                    return None
                kwargs = {"substrings": substrings}
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                if "case_sensitive" in settings:
                    kwargs["case_sensitive"] = bool(settings["case_sensitive"])
                if "redact" in settings:
                    kwargs["redact"] = bool(settings["redact"])
                if "contains_all" in settings:
                    kwargs["contains_all"] = bool(settings["contains_all"])
                return BanSubstrings(**kwargs)

            elif name == "ban_topics":
                topics = settings.get("topics", [])
                if not topics:
                    logger.warning(
                        "BanTopics scanner requires 'topics' list in settings"
                    )
                    return None
                return BanTopics(
                    topics=topics,
                    threshold=threshold,
                    use_onnx=self._use_onnx,
                )

            elif name == "code":
                kwargs = {"use_onnx": self._use_onnx, "threshold": threshold}
                if "languages" in settings:
                    kwargs["languages"] = settings["languages"]
                if "is_blocked" in settings:
                    kwargs["is_blocked"] = bool(settings["is_blocked"])
                return Code(**kwargs)

            elif name == "gibberish":
                # Gibberish scanner: enforce minimum threshold of 0.70 to
                # avoid flagging informal but legitimate prompts.
                gib_threshold = max(threshold, 0.70)
                kwargs = {"use_onnx": self._use_onnx, "threshold": gib_threshold}
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                return Gibberish(**kwargs)

            elif name == "invisible_text":
                return InvisibleText()

            elif name == "language":
                valid_languages = settings.get("valid_languages", ["en"])
                kwargs = {
                    "valid_languages": valid_languages,
                    "threshold": threshold,
                    "use_onnx": self._use_onnx,
                }
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                return Language(**kwargs)

            elif name == "prompt_injection":
                kwargs = {"use_onnx": self._use_onnx, "threshold": threshold}
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                return PromptInjection(**kwargs)

            elif name == "regex":
                patterns = settings.get("patterns", [])
                if not patterns:
                    logger.warning("Regex scanner requires 'patterns' list in settings")
                    return None
                kwargs = {"patterns": patterns}
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                if "redact" in settings:
                    kwargs["redact"] = bool(settings["redact"])
                return Regex(**kwargs)

            elif name == "secrets":
                kwargs = {}
                if "redact_mode" in settings:
                    kwargs["redact_mode"] = settings["redact_mode"]
                return Secrets(**kwargs)

            elif name == "sentiment":
                # The Sentiment scanner flags text whose compound sentiment
                # score falls BELOW the threshold.  A threshold of 0.5 means
                # only very positive text passes — causing massive false
                # positives on neutral/factual prompts.
                # Clamp to at most -0.50 so only strongly negative text is
                # flagged. Callers can still pass a more-negative value.
                if threshold > 0:
                    # Caller likely used the generic 0-1 scale; translate to
                    # the sentiment scale (which is -1 … +1).
                    sentiment_threshold = -0.50
                    logger.info(
                        f"Sentiment scanner: overriding threshold {threshold:.2f} → "
                        f"{sentiment_threshold} (generic 0-1 scale not applicable)"
                    )
                else:
                    sentiment_threshold = threshold
                kwargs = {"threshold": sentiment_threshold}
                return Sentiment(**kwargs)

            elif name == "token_limit":
                kwargs = {}
                if "limit" in settings:
                    kwargs["limit"] = int(settings["limit"])
                if "encoding_name" in settings:
                    kwargs["encoding_name"] = settings["encoding_name"]
                return TokenLimit(**kwargs)

            elif name == "toxicity":
                # Toxicity scanner: enforce minimum threshold of 0.70 to
                # reduce false positives on edgy-but-benign content.
                tox_threshold = max(threshold, 0.70)
                kwargs = {"use_onnx": self._use_onnx, "threshold": tox_threshold}
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                return Toxicity(**kwargs)

            else:
                logger.warning(f"Unknown input scanner: {name}")
                return None

        except Exception as e:
            logger.error(f"Failed to build input scanner '{name}': {e}")
            return None

    def _build_output_scanner(self, name: str, threshold: float, settings: dict):
        """
        Build an output scanner instance from its name and settings.
        Returns the scanner instance or None if the scanner can't be built.
        """
        try:
            if name == "ban_code":
                kwargs = {"use_onnx": self._use_onnx, "threshold": threshold}
                if "languages" in settings:
                    kwargs["languages"] = settings["languages"]
                if "is_blocked" in settings:
                    kwargs["is_blocked"] = bool(settings["is_blocked"])
                return OutputBanCode(**kwargs)

            elif name == "ban_competitors":
                competitors = settings.get("competitors", [])
                if not competitors:
                    logger.warning("Output BanCompetitors requires 'competitors' list")
                    return None
                kwargs = {"competitors": competitors, "threshold": threshold}
                if "redact" in settings:
                    kwargs["redact"] = bool(settings["redact"])
                return OutputBanCompetitors(use_onnx=self._use_onnx, **kwargs)

            elif name == "ban_substrings":
                substrings = settings.get("substrings", [])
                if not substrings:
                    logger.warning("Output BanSubstrings requires 'substrings' list")
                    return None
                kwargs = {"substrings": substrings}
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                if "case_sensitive" in settings:
                    kwargs["case_sensitive"] = bool(settings["case_sensitive"])
                if "redact" in settings:
                    kwargs["redact"] = bool(settings["redact"])
                if "contains_all" in settings:
                    kwargs["contains_all"] = bool(settings["contains_all"])
                return OutputBanSubstrings(**kwargs)

            elif name == "ban_topics":
                topics = settings.get("topics", [])
                if not topics:
                    logger.warning("Output BanTopics requires 'topics' list")
                    return None
                return OutputBanTopics(
                    topics=topics,
                    threshold=threshold,
                    use_onnx=self._use_onnx,
                )

            elif name == "bias":
                kwargs = {"use_onnx": self._use_onnx, "threshold": threshold}
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                return Bias(**kwargs)

            elif name == "code":
                kwargs = {"use_onnx": self._use_onnx, "threshold": threshold}
                if "languages" in settings:
                    kwargs["languages"] = settings["languages"]
                if "is_blocked" in settings:
                    kwargs["is_blocked"] = bool(settings["is_blocked"])
                return OutputCode(**kwargs)

            elif name == "deanonymize":
                return Deanonymize(vault=self._vault)

            elif name == "json":
                if not HAS_JSON_SCANNER:
                    logger.warning(
                        "JSON scanner not available in this llm-guard version"
                    )
                    return None
                kwargs = {}
                if "required_elements" in settings:
                    kwargs["required_elements"] = int(settings["required_elements"])
                if "repair" in settings:
                    kwargs["repair"] = bool(settings["repair"])
                return JSONScanner(**kwargs)

            elif name == "language":
                valid_languages = settings.get("valid_languages", ["en"])
                kwargs = {
                    "valid_languages": valid_languages,
                    "threshold": threshold,
                    "use_onnx": self._use_onnx,
                }
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                return OutputLanguage(**kwargs)

            elif name == "language_same":
                kwargs = {"use_onnx": self._use_onnx, "threshold": threshold}
                return LanguageSame(**kwargs)

            elif name == "malicious_urls":
                kwargs = {"use_onnx": self._use_onnx, "threshold": threshold}
                return MaliciousURLs(**kwargs)

            elif name == "no_refusal":
                kwargs = {"use_onnx": self._use_onnx, "threshold": threshold}
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                return NoRefusal(**kwargs)

            elif name == "reading_time":
                if not HAS_READING_TIME:
                    logger.warning("ReadingTime scanner not available")
                    return None
                kwargs = {}
                if "max_seconds" in settings:
                    kwargs["max_seconds"] = int(settings["max_seconds"])
                if "truncate" in settings:
                    kwargs["truncate"] = bool(settings["truncate"])
                return ReadingTime(**kwargs)

            elif name == "factual_consistency":
                if not HAS_FACTUAL_CONSISTENCY:
                    logger.warning("FactualConsistency scanner not available")
                    return None
                kwargs = {"use_onnx": self._use_onnx, "threshold": threshold}
                return FactualConsistency(**kwargs)

            elif name == "gibberish":
                kwargs = {"use_onnx": self._use_onnx, "threshold": threshold}
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                return OutputGibberish(**kwargs)

            elif name == "regex":
                patterns = settings.get("patterns", [])
                if not patterns:
                    logger.warning("Output Regex scanner requires 'patterns' list")
                    return None
                kwargs = {"patterns": patterns}
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                if "redact" in settings:
                    kwargs["redact"] = bool(settings["redact"])
                return OutputRegex(**kwargs)

            elif name == "relevance":
                kwargs = {"use_onnx": self._use_onnx, "threshold": threshold}
                return Relevance(**kwargs)

            elif name == "sensitive":
                kwargs = {"use_onnx": self._use_onnx, "threshold": threshold}
                if "entity_types" in settings:
                    kwargs["entity_types"] = settings["entity_types"]
                if "redact" in settings:
                    kwargs["redact"] = bool(settings["redact"])
                return Sensitive(**kwargs)

            elif name == "sentiment":
                # Same guard as input sentiment — see _build_input_scanner.
                if threshold > 0:
                    sentiment_threshold = -0.50
                    logger.info(
                        f"Output Sentiment scanner: overriding threshold "
                        f"{threshold:.2f} → {sentiment_threshold}"
                    )
                else:
                    sentiment_threshold = threshold
                kwargs = {"threshold": sentiment_threshold}
                return OutputSentiment(**kwargs)

            elif name == "toxicity":
                tox_threshold = max(threshold, 0.70)
                kwargs = {"use_onnx": self._use_onnx, "threshold": tox_threshold}
                if "match_type" in settings:
                    kwargs["match_type"] = settings["match_type"]
                return OutputToxicity(**kwargs)

            elif name == "url_reachability":
                kwargs = {}
                if "success_status_codes" in settings:
                    kwargs["success_status_codes"] = settings["success_status_codes"]
                return URLReachability(**kwargs)

            else:
                logger.warning(f"Unknown output scanner: {name}")
                return None

        except Exception as e:
            logger.error(f"Failed to build output scanner '{name}': {e}")
            return None

    # ════════════════════════════════════════════════════════════════
    # Legacy Scan Methods (backward-compatible with existing proto)
    # ════════════════════════════════════════════════════════════════

    def scan_prompt(
        self,
        prompt: str,
        check_injection: bool = True,
        check_toxicity: bool = True,
        check_pii: bool = True,
        sanitize: bool = False,
    ) -> Dict[str, Any]:
        """
        Legacy scan_prompt — uses default scanners with simple boolean toggles.
        Used by the existing ScanPrompt gRPC endpoint.

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
            if "prompt_injection" in self._default_input_scanners:
                scanners_to_use.append(self._default_input_scanners["prompt_injection"])
            if "invisible_text" in self._default_input_scanners:
                scanners_to_use.append(self._default_input_scanners["invisible_text"])

        if check_toxicity:
            if "toxicity" in self._default_input_scanners:
                scanners_to_use.append(self._default_input_scanners["toxicity"])

        if check_pii:
            if "anonymize" in self._default_input_scanners:
                scanners_to_use.append(self._default_input_scanners["anonymize"])
            if "secrets" in self._default_input_scanners:
                scanners_to_use.append(self._default_input_scanners["secrets"])

        if not scanners_to_use:
            return {
                "safe": True,
                "sanitized_prompt": prompt if sanitize else "",
                "risk_score": 0.0,
                "threats": [],
            }

        # Run scan through LLM Guard (GPU-accelerated)
        sanitized, results_valid, results_score = llm_guard_scan_prompt(
            scanners_to_use, prompt
        )

        # Process results
        for scanner_name, is_valid in results_valid.items():
            score = results_score.get(scanner_name, 0.0)
            if not is_valid:
                # Risk = 1 - score (low scanner score → high risk)
                risk_contribution = round(1.0 - score, 4)
                threats.append(
                    {
                        "type": scanner_name,
                        "confidence": risk_contribution,
                        "description": f"Detected potential {scanner_name} issue",
                        "severity": self._get_severity(risk_contribution),
                    }
                )
                risk_score = max(risk_score, risk_contribution)

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
        Legacy scan_output — uses default output scanners.
        Used by the existing ScanOutput gRPC endpoint.

        Args:
            output: The LLM output to scan
            original_prompt: The original prompt (for context)

        Returns:
            Dict with 'safe', 'sanitized_output', 'issues'
        """
        issues = []

        scanners = []
        for name in ["sensitive", "toxicity", "malicious_urls"]:
            if name in self._default_output_scanners:
                scanners.append(self._default_output_scanners[name])

        if not scanners:
            return {"safe": True, "sanitized_output": output, "issues": []}

        sanitized, results_valid, results_score = llm_guard_scan_output(
            scanners, original_prompt or "", output
        )

        for scanner_name, valid in results_valid.items():
            if not valid:
                score = results_score.get(scanner_name, 0.0)
                risk_contribution = round(1.0 - score, 4)
                issues.append(
                    {
                        "type": scanner_name,
                        "description": f"Detected potential {scanner_name} issue in output",
                        "severity": self._get_severity(risk_contribution),
                    }
                )

        is_safe = len(issues) == 0

        return {"safe": is_safe, "sanitized_output": sanitized, "issues": issues}

    # ════════════════════════════════════════════════════════════════
    # Advanced Scan (Full Customization)
    # ════════════════════════════════════════════════════════════════

    def advanced_scan(
        self,
        prompt: str = "",
        output: str = "",
        scan_mode: int = 0,  # 0=PROMPT_ONLY, 1=OUTPUT_ONLY, 2=BOTH
        input_scanner_configs: Optional[Dict[str, Dict]] = None,
        output_scanner_configs: Optional[Dict[str, Dict]] = None,
        sanitize: bool = False,
        fail_fast: bool = False,
    ) -> Dict[str, Any]:
        """
        Advanced scan with full per-scanner configuration.

        Args:
            prompt: Text to scan as input (for PROMPT_ONLY or BOTH)
            output: Text to scan as output (for OUTPUT_ONLY or BOTH)
            scan_mode: 0=PROMPT_ONLY, 1=OUTPUT_ONLY, 2=BOTH
            input_scanner_configs: Dict of {scanner_name: {enabled, threshold, settings}}
            output_scanner_configs: Dict of {scanner_name: {enabled, threshold, settings}}
            sanitize: Whether to return sanitized text
            fail_fast: Whether to stop after the first failing scanner

        Returns:
            Dict with comprehensive scan results including per-scanner details
        """
        start_time = time.time()

        result = {
            "safe": True,
            "sanitized_prompt": "",
            "sanitized_output": "",
            "risk_score": 0.0,
            "input_results": [],
            "output_results": [],
            "latency_ms": 0,
            "scan_mode": scan_mode,
            "input_scanners_run": 0,
            "output_scanners_run": 0,
        }

        # ── Prompt Scanning ─────────────────────────────────────────
        if scan_mode in (0, 2):  # PROMPT_ONLY or BOTH
            if prompt:
                input_results = self._run_input_scan(
                    prompt, input_scanner_configs, sanitize, fail_fast
                )
                result["input_results"] = input_results["scanner_results"]
                result["input_scanners_run"] = input_results["scanners_run"]

                if not input_results["safe"]:
                    result["safe"] = False

                result["risk_score"] = max(
                    result["risk_score"], input_results["risk_score"]
                )

                if sanitize:
                    result["sanitized_prompt"] = input_results["sanitized_text"]
            else:
                logger.warning("scan_mode includes prompt scanning but prompt is empty")

        # ── Output Scanning ─────────────────────────────────────────
        if scan_mode in (1, 2):  # OUTPUT_ONLY or BOTH
            if output:
                # Use original or sanitized prompt for context
                context_prompt = result.get("sanitized_prompt") or prompt or ""
                output_results = self._run_output_scan(
                    output, context_prompt, output_scanner_configs, sanitize, fail_fast
                )
                result["output_results"] = output_results["scanner_results"]
                result["output_scanners_run"] = output_results["scanners_run"]

                if not output_results["safe"]:
                    result["safe"] = False

                result["risk_score"] = max(
                    result["risk_score"], output_results["risk_score"]
                )

                if sanitize:
                    result["sanitized_output"] = output_results["sanitized_text"]
            else:
                logger.warning("scan_mode includes output scanning but output is empty")

        result["latency_ms"] = int((time.time() - start_time) * 1000)

        return result

    def _run_input_scan(
        self,
        prompt: str,
        scanner_configs: Optional[Dict[str, Dict]],
        sanitize: bool,
        fail_fast: bool,
    ) -> Dict[str, Any]:
        """
        Run input scanners with dynamic configuration.

        scanner_configs format:
        {
            "scanner_name": {
                "enabled": True,
                "threshold": 0.5,
                "settings": { ... scanner-specific ... }
            }
        }
        """
        # Build scanner list
        scanners = []
        scanner_names = []

        if scanner_configs:
            # Use explicit config — only enabled scanners
            for name, config in scanner_configs.items():
                if not config.get("enabled", True):
                    continue

                threshold = config.get("threshold", 0.5)
                settings = config.get("settings", {})

                scanner = self._build_input_scanner(name, threshold, settings)
                if scanner is not None:
                    scanners.append(scanner)
                    scanner_names.append(name)
        else:
            # Use default scanners
            for name in DEFAULT_INPUT_SCANNERS:
                if name in self._default_input_scanners:
                    scanners.append(self._default_input_scanners[name])
                    scanner_names.append(name)

        if not scanners:
            return {
                "safe": True,
                "sanitized_text": prompt if sanitize else "",
                "risk_score": 0.0,
                "scanner_results": [],
                "scanners_run": 0,
            }

        # Run scan
        sanitized, results_valid, results_score = llm_guard_scan_prompt(
            scanners, prompt, fail_fast=fail_fast
        )

        # Process results
        scanner_results = []
        risk_score = 0.0
        is_safe = True

        for scanner_name, is_valid in results_valid.items():
            score = results_score.get(scanner_name, 0.0)
            # In LLM Guard, a LOW score means the scanner considers the
            # text unsafe, so the *risk* is `1 - score`.
            risk_contribution = round(1.0 - score, 4) if not is_valid else 0.0
            scanner_result = {
                "scanner_name": scanner_name,
                "is_valid": is_valid,
                "score": score,
                "description": "",
                "severity": "low",
                "scanner_latency_ms": 0,  # llm-guard doesn't expose per-scanner latency
            }

            if not is_valid:
                is_safe = False
                scanner_result["description"] = (
                    f"Detected potential {scanner_name} issue"
                )
                scanner_result["severity"] = self._get_severity(risk_contribution)
                risk_score = max(risk_score, risk_contribution)

            scanner_results.append(scanner_result)

        return {
            "safe": is_safe,
            "sanitized_text": sanitized if sanitize else "",
            "risk_score": risk_score,
            "scanner_results": scanner_results,
            "scanners_run": len(scanners),
        }

    def _run_output_scan(
        self,
        output: str,
        original_prompt: str,
        scanner_configs: Optional[Dict[str, Dict]],
        sanitize: bool,
        fail_fast: bool,
    ) -> Dict[str, Any]:
        """
        Run output scanners with dynamic configuration.

        scanner_configs format same as _run_input_scan.
        """
        # Build scanner list
        scanners = []
        scanner_names = []

        if scanner_configs:
            # Use explicit config — only enabled scanners
            for name, config in scanner_configs.items():
                if not config.get("enabled", True):
                    continue

                threshold = config.get("threshold", 0.5)
                settings = config.get("settings", {})

                scanner = self._build_output_scanner(name, threshold, settings)
                if scanner is not None:
                    scanners.append(scanner)
                    scanner_names.append(name)
        else:
            # Use default scanners
            for name in DEFAULT_OUTPUT_SCANNERS:
                if name in self._default_output_scanners:
                    scanners.append(self._default_output_scanners[name])
                    scanner_names.append(name)

        if not scanners:
            return {
                "safe": True,
                "sanitized_text": output if sanitize else "",
                "risk_score": 0.0,
                "scanner_results": [],
                "scanners_run": 0,
            }

        # Run scan
        sanitized, results_valid, results_score = llm_guard_scan_output(
            scanners, original_prompt, output, fail_fast=fail_fast
        )

        # Process results
        scanner_results = []
        risk_score = 0.0
        is_safe = True

        for scanner_name, is_valid in results_valid.items():
            score = results_score.get(scanner_name, 0.0)
            # Risk = 1 - score (low scanner score → high risk)
            risk_contribution = round(1.0 - score, 4) if not is_valid else 0.0
            scanner_result = {
                "scanner_name": scanner_name,
                "is_valid": is_valid,
                "score": score,
                "description": "",
                "severity": "low",
                "scanner_latency_ms": 0,
            }

            if not is_valid:
                is_safe = False
                scanner_result["description"] = (
                    f"Detected potential {scanner_name} issue in output"
                )
                scanner_result["severity"] = self._get_severity(risk_contribution)
                risk_score = max(risk_score, risk_contribution)

            scanner_results.append(scanner_result)

        return {
            "safe": is_safe,
            "sanitized_text": sanitized if sanitize else "",
            "risk_score": risk_score,
            "scanner_results": scanner_results,
            "scanners_run": len(scanners),
        }

    # ════════════════════════════════════════════════════════════════
    # Utility Methods
    # ════════════════════════════════════════════════════════════════

    @staticmethod
    def get_available_input_scanners() -> List[str]:
        """Return list of all available input scanner names."""
        return list(ALL_INPUT_SCANNERS)

    @staticmethod
    def get_available_output_scanners() -> List[str]:
        """Return list of all available output scanner names."""
        available = []
        for name in ALL_OUTPUT_SCANNERS:
            if name == "json" and not HAS_JSON_SCANNER:
                continue
            if name == "reading_time" and not HAS_READING_TIME:
                continue
            if name == "factual_consistency" and not HAS_FACTUAL_CONSISTENCY:
                continue
            available.append(name)
        return available

    @staticmethod
    def _get_severity(score: float) -> str:
        """Convert score to severity level."""
        if score >= 0.9:
            return "critical"
        elif score >= 0.7:
            return "high"
        elif score >= 0.4:
            return "medium"
        else:
            return "low"
