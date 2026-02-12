"""
Garak Scanner - LLM Vulnerability Testing
"""

import asyncio
from typing import Any, Callable, Dict, List, Optional

from loguru import logger


class GarakScanner:
    """
    Wrapper for Garak vulnerability scanner
    Provides automated red-teaming and vulnerability testing for LLMs
    """

    # Probe categories and their probes
    PROBE_CATEGORIES = {
        "injection": [
            "promptinject",
            "dan",
            "atkgen",
        ],
        "jailbreak": [
            "gcg",
            "autodan",
            "artprompt",
        ],
        "data_leakage": [
            "leakreplay",
            "lmrc",
        ],
        "toxicity": [
            "realtoxicityprompts",
            "continuation",
        ],
        "encoding": [
            "encoding",
        ],
        "hallucination": [
            "snowball",
            "packagehallucination",
        ],
    }

    # Scan type configurations
    SCAN_TYPES = {
        "quick": {
            "probes": ["promptinject", "dan"],
            "samples": 10,
        },
        "standard": {
            "probes": ["promptinject", "dan", "encoding", "leakreplay"],
            "samples": 50,
        },
        "comprehensive": {
            "probes": None,  # All probes
            "samples": 100,
        },
    }

    def __init__(self):
        logger.info("Initializing Garak Scanner...")
        self._initialized = False

        try:
            # Test if garak is available
            import garak

            self._initialized = True
            logger.info("Garak Scanner initialized successfully")
        except ImportError as e:
            logger.warning(f"Garak not available: {e}")
            logger.warning(
                "Garak scanner disabled - install garak package for vulnerability scanning"
            )

    def is_available(self) -> bool:
        """Check if Garak scanner is available"""
        return self._initialized

    async def run_scan(
        self,
        provider: str,
        model: str,
        api_key: str,
        base_url: str,
        probes: List[str],
        scan_type: str,
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """
        Run a Garak vulnerability scan

        Args:
            provider: LLM provider (openai, huggingface, ollama, etc.)
            model: Model name
            api_key: API key for the provider
            base_url: Custom base URL (optional)
            probes: List of specific probes to run (empty = based on scan_type)
            scan_type: Type of scan (quick, standard, comprehensive)
            progress_callback: Callback for progress updates (progress, completed, total)
            cancel_check: Callback to check if scan should be cancelled

        Returns:
            Dict with scan results and vulnerabilities
        """
        if not self._initialized:
            raise RuntimeError(
                "Garak scanner is not available. Please install the garak package."
            )

        # Determine probes to run
        if not probes:
            scan_config = self.SCAN_TYPES.get(scan_type, self.SCAN_TYPES["standard"])
            probes = scan_config["probes"] or self._get_all_probes()

        total_probes = len(probes)
        vulnerabilities = []

        try:
            # Configure garak
            import garak._config as garak_config
            import garak.cli

            # Set up generator configuration
            generator_config = self._get_generator_config(
                provider, model, api_key, base_url
            )

            for i, probe_name in enumerate(probes):
                # Check for cancellation
                if cancel_check and cancel_check():
                    logger.info("Scan cancelled by user")
                    return {
                        "status": "cancelled",
                        "probes_run": i,
                        "vulnerabilities": vulnerabilities,
                    }

                if progress_callback:
                    progress = int((i / total_probes) * 100)
                    progress_callback(progress, i, total_probes)

                try:
                    # Run individual probe
                    probe_results = await self._run_probe(probe_name, generator_config)

                    if probe_results.get("failed"):
                        for vuln in probe_results["vulnerabilities"]:
                            vulnerabilities.append(
                                {
                                    "probe_name": probe_name,
                                    "category": self._get_probe_category(probe_name),
                                    "severity": self._assess_severity(vuln),
                                    "description": vuln.get("description", ""),
                                    "attack_prompt": vuln.get("prompt", ""),
                                    "model_response": vuln.get("response", ""),
                                    "recommendation": self._get_recommendation(
                                        probe_name
                                    ),
                                }
                            )

                except Exception as e:
                    logger.error(f"Error running probe {probe_name}: {e}")

            if progress_callback:
                progress_callback(100, total_probes, total_probes)

            return {
                "status": "completed",
                "probes_run": total_probes,
                "vulnerabilities": vulnerabilities,
            }

        except Exception as e:
            logger.error(f"Garak scan failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "vulnerabilities": vulnerabilities,
            }

    def _get_generator_config(
        self, provider: str, model: str, api_key: str, base_url: str
    ) -> Dict:
        """Get garak generator configuration for the provider"""

        provider_configs = {
            "openai": {
                "generator": "openai",
                "model": model,
                "api_key": api_key,
            },
            "huggingface": {
                "generator": "huggingface",
                "model": model,
                "api_key": api_key,
            },
            "ollama": {
                "generator": "ollama",
                "model": model,
                "base_url": base_url or "http://localhost:11434",
            },
            "anthropic": {
                "generator": "anthropic",
                "model": model,
                "api_key": api_key,
            },
        }

        return provider_configs.get(
            provider,
            {
                "generator": "rest",
                "model": model,
                "api_key": api_key,
                "base_url": base_url,
            },
        )

    async def _run_probe(self, probe_name: str, generator_config: Dict) -> Dict:
        """Run a single garak probe"""
        # TODO: Implement actual garak probe integration
        # This is a placeholder that returns no vulnerabilities
        # Real implementation would use garak's probe API
        try:
            import garak.probes

            # Placeholder - actual garak integration would go here
            # garak.probes would be used to run the specific probe
            logger.debug(f"Running probe: {probe_name}")

            # Return empty result - real implementation pending
            return {
                "failed": False,
                "vulnerabilities": [],
            }
        except Exception as e:
            logger.error(f"Failed to run probe {probe_name}: {e}")
            return {
                "failed": False,
                "vulnerabilities": [],
                "error": str(e),
            }

    def _get_probe_category(self, probe_name: str) -> str:
        """Get category for a probe"""
        for category, probes in self.PROBE_CATEGORIES.items():
            if probe_name in probes:
                return category
        return "other"

    def _assess_severity(self, vuln: Dict) -> str:
        """Assess severity of a vulnerability"""
        # Simple heuristic - could be more sophisticated
        success_rate = vuln.get("success_rate", 0)

        if success_rate >= 0.8:
            return "critical"
        elif success_rate >= 0.5:
            return "high"
        elif success_rate >= 0.2:
            return "medium"
        else:
            return "low"

    def _get_recommendation(self, probe_name: str) -> str:
        """Get recommendation for a vulnerability"""
        recommendations = {
            "promptinject": "Implement input validation and prompt sanitization.",
            "dan": "Add system-level guardrails to prevent jailbreak attempts.",
            "encoding": "Validate and normalize input encoding.",
            "leakreplay": "Implement training data protection measures.",
            "realtoxicityprompts": "Add toxicity filters to model outputs.",
            "packagehallucination": "Verify code recommendations against known packages.",
        }
        return recommendations.get(probe_name, "Review and address the vulnerability.")

    def _get_all_probes(self) -> List[str]:
        """Get all available probes"""
        all_probes = []
        for probes in self.PROBE_CATEGORIES.values():
            all_probes.extend(probes)
        return all_probes
