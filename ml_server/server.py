"""
Orafinite ML Sidecar - gRPC Server
Provides LLM Guard and Garak functionality to the Rust API
"""

import asyncio
import os
import threading
import time
import uuid
from concurrent import futures
from typing import Dict, List, Optional

import grpc

# Import generated protobuf code
import ml_service_pb2
import ml_service_pb2_grpc
from loguru import logger
from scanners.garak_scanner import GarakScanner

# Import scanners
from scanners.llm_guard_scanner import LLMGuardScanner

# Configuration
SCAN_RETENTION_SECONDS = 3600  # Keep completed scans for 1 hour
SCAN_CLEANUP_INTERVAL_SECONDS = 300  # Clean up every 5 minutes
SCAN_STALE_TIMEOUT_SECONDS = 1800  # Consider running scans stale after 30 minutes
MAX_RUNNING_SCANS = 10  # Maximum concurrent scans


class MlServiceServicer(ml_service_pb2_grpc.MlServiceServicer):
    """gRPC service implementation for ML operations"""

    def __init__(self):
        logger.info("Initializing ML Service...")

        # Initialize LLM Guard scanner (loads models into memory)
        # NO FALLBACK — if this fails, the sidecar crashes immediately
        device = os.environ.get("LLM_GUARD_DEVICE", "cpu")
        logger.info(f"Using device: {device}")
        try:
            self.llm_guard = LLMGuardScanner(device=device)
        except Exception as e:
            logger.critical(
                f"❌ FATAL: LLM Guard failed to initialize: {e}\n"
                "The sidecar CANNOT start without real LLM Guard ML models.\n"
                "Make sure 'llm-guard' and its dependencies (torch, transformers) "
                "are installed correctly.\n"
                "Run: pip install llm-guard torch transformers"
            )
            raise SystemExit(1) from e

        # Initialize Garak scanner
        self.garak = GarakScanner()

        # Track running scans with timestamps
        self.running_scans: Dict[str, dict] = {}
        self._scans_lock = threading.Lock()

        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

        logger.info(
            "✅ ML Service initialized successfully — using REAL LLM Guard ML models"
        )

    def _cleanup_loop(self):
        """Background thread to clean up old scans"""
        while True:
            time.sleep(SCAN_CLEANUP_INTERVAL_SECONDS)
            self._cleanup_old_scans()

    def _cleanup_old_scans(self):
        """Remove old scans and mark stale running scans as failed"""
        now = time.time()
        scans_to_remove = []
        stale_scans = []

        with self._scans_lock:
            for scan_id, scan_data in self.running_scans.items():
                status = scan_data["status"]
                created_at = scan_data.get("created_at", 0)
                completed_at = scan_data.get("completed_at")

                # Clean up completed/failed/cancelled scans older than retention period
                if status in ("completed", "failed", "cancelled"):
                    if completed_at and now - completed_at > SCAN_RETENTION_SECONDS:
                        scans_to_remove.append(scan_id)
                # Mark stale running/queued scans as failed (memory leak fix)
                elif status in ("running", "queued"):
                    if now - created_at > SCAN_STALE_TIMEOUT_SECONDS:
                        stale_scans.append(scan_id)

            # Mark stale scans as failed
            for scan_id in stale_scans:
                self.running_scans[scan_id].update(
                    {
                        "status": "failed",
                        "error_message": "Scan timed out (stale)",
                        "completed_at": now,
                    }
                )
                logger.warning(f"Marked stale scan as failed: {scan_id}")

            # Remove old completed scans
            for scan_id in scans_to_remove:
                del self.running_scans[scan_id]
                logger.debug(f"Cleaned up old scan: {scan_id}")

        if stale_scans:
            logger.info(f"Marked {len(stale_scans)} stale scan(s) as failed")
        if scans_to_remove:
            logger.info(f"Cleaned up {len(scans_to_remove)} old scan(s)")

    def _get_active_scan_count(self) -> int:
        """Count scans that are queued or running"""
        with self._scans_lock:
            return sum(
                1
                for s in self.running_scans.values()
                if s["status"] in ("queued", "running")
            )

    def HealthCheck(self, request, context):
        """Health check endpoint — confirms real LLM Guard is loaded"""
        # If we got here, LLM Guard is initialized (sidecar would have
        # crashed on startup otherwise). Report healthy.
        return ml_service_pb2.HealthResponse(healthy=True, version="0.1.0-llmguard")

    def ScanPrompt(self, request, context):
        """Scan a prompt using LLM Guard"""
        start_time = time.time()

        # Validate input
        if not request.prompt:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Prompt cannot be empty")
            return ml_service_pb2.ScanResponse()

        if len(request.prompt) > 32 * 1024:  # 32KB limit
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Prompt exceeds maximum length of 32KB")
            return ml_service_pb2.ScanResponse()

        try:
            result = self.llm_guard.scan_prompt(
                prompt=request.prompt,
                check_injection=request.check_injection,
                check_toxicity=request.check_toxicity,
                check_pii=request.check_pii,
                sanitize=request.sanitize,
            )

            latency_ms = int((time.time() - start_time) * 1000)

            threats = [
                ml_service_pb2.Threat(
                    threat_type=t["type"],
                    confidence=t["confidence"],
                    description=t["description"],
                    severity=t["severity"],
                )
                for t in result.get("threats", [])
            ]

            return ml_service_pb2.ScanResponse(
                safe=result["safe"],
                sanitized_prompt=result.get("sanitized_prompt", ""),
                risk_score=result.get("risk_score", 0.0),
                threats=threats,
                latency_ms=latency_ms,
            )

        except Exception as e:
            logger.error(f"Error scanning prompt: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Scan failed: {str(e)}")
            return ml_service_pb2.ScanResponse()

    def ScanOutput(self, request, context):
        """Scan LLM output using LLM Guard"""
        start_time = time.time()

        # Validate input
        if not request.output:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Output cannot be empty")
            return ml_service_pb2.OutputScanResponse()

        try:
            result = self.llm_guard.scan_output(
                output=request.output, original_prompt=request.original_prompt or None
            )

            latency_ms = int((time.time() - start_time) * 1000)

            issues = [
                ml_service_pb2.OutputIssue(
                    issue_type=i["type"],
                    description=i["description"],
                    severity=i["severity"],
                )
                for i in result.get("issues", [])
            ]

            return ml_service_pb2.OutputScanResponse(
                safe=result["safe"],
                sanitized_output=result.get("sanitized_output", ""),
                issues=issues,
                latency_ms=latency_ms,
            )

        except Exception as e:
            logger.error(f"Error scanning output: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Output scan failed: {str(e)}")
            return ml_service_pb2.OutputScanResponse()

    def StartGarakScan(self, request, context):
        """Start a Garak vulnerability scan"""
        # Validate required fields
        if not request.provider:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Provider is required")
            return ml_service_pb2.GarakResponse()

        if not request.model:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Model is required")
            return ml_service_pb2.GarakResponse()

        # Check Garak availability
        if not self.garak.is_available():
            context.set_code(grpc.StatusCode.UNAVAILABLE)
            context.set_details(
                "Garak scanner is not available. Please install garak package."
            )
            return ml_service_pb2.GarakResponse()

        # Check concurrent scan limit
        if self._get_active_scan_count() >= MAX_RUNNING_SCANS:
            context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
            context.set_details(
                f"Maximum concurrent scans ({MAX_RUNNING_SCANS}) reached. "
                "Please wait for existing scans to complete."
            )
            return ml_service_pb2.GarakResponse()

        try:
            scan_id = str(uuid.uuid4())

            # Store scan info with timestamp
            with self._scans_lock:
                self.running_scans[scan_id] = {
                    "status": "queued",
                    "progress": 0,
                    "probes_completed": 0,
                    "probes_total": 0,
                    "vulnerabilities": [],
                    "created_at": time.time(),
                    "completed_at": None,
                }

            # Start scan in a background thread with its own event loop
            def run_scan_in_thread():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(
                        self._run_garak_scan(
                            scan_id=scan_id,
                            provider=request.provider,
                            model=request.model,
                            api_key=request.api_key,
                            base_url=request.base_url,
                            probes=list(request.probes),
                            scan_type=request.scan_type,
                        )
                    )
                finally:
                    loop.close()

            thread = threading.Thread(target=run_scan_in_thread, daemon=True)
            thread.start()

            return ml_service_pb2.GarakResponse(
                scan_id=scan_id, status="queued", estimated_duration_seconds=300
            )

        except Exception as e:
            logger.error(f"Error starting Garak scan: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Failed to start scan: {str(e)}")
            return ml_service_pb2.GarakResponse()

    def GetGarakStatus(self, request, context):
        """Get status of a running Garak scan"""
        scan_id = request.scan_id

        if not scan_id:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Scan ID is required")
            return ml_service_pb2.GarakStatusResponse()

        with self._scans_lock:
            if scan_id not in self.running_scans:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details(f"Scan {scan_id} not found")
                return ml_service_pb2.GarakStatusResponse()

            scan = self.running_scans[scan_id]

            vulnerabilities = [
                ml_service_pb2.Vulnerability(
                    probe_name=v["probe_name"],
                    category=v["category"],
                    severity=v["severity"],
                    description=v["description"],
                    attack_prompt=v.get("attack_prompt", ""),
                    model_response=v.get("model_response", ""),
                    recommendation=v.get("recommendation", ""),
                )
                for v in scan.get("vulnerabilities", [])
            ]

            return ml_service_pb2.GarakStatusResponse(
                scan_id=scan_id,
                status=scan["status"],
                progress=scan["progress"],
                probes_completed=scan["probes_completed"],
                probes_total=scan["probes_total"],
                vulnerabilities_found=len(vulnerabilities),
                vulnerabilities=vulnerabilities,
                error_message=scan.get("error_message", ""),
            )

    def CancelGarakScan(self, request, context):
        """Cancel a running Garak scan"""
        scan_id = request.scan_id

        if not scan_id:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Scan ID is required")
            return ml_service_pb2.CancelScanResponse(success=False)

        with self._scans_lock:
            if scan_id not in self.running_scans:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details(f"Scan {scan_id} not found")
                return ml_service_pb2.CancelScanResponse(success=False)

            scan = self.running_scans[scan_id]

            if scan["status"] in ("completed", "failed", "cancelled"):
                return ml_service_pb2.CancelScanResponse(
                    success=False, message=f"Scan already {scan['status']}"
                )

            scan["status"] = "cancelled"
            scan["completed_at"] = time.time()

            return ml_service_pb2.CancelScanResponse(
                success=True, message="Scan cancelled"
            )

    async def _run_garak_scan(
        self,
        scan_id: str,
        provider: str,
        model: str,
        api_key: str,
        base_url: str,
        probes: List[str],
        scan_type: str,
    ):
        """Run Garak scan in background"""
        try:
            with self._scans_lock:
                if scan_id in self.running_scans:
                    # Check if cancelled before starting
                    if self.running_scans[scan_id]["status"] == "cancelled":
                        return
                    self.running_scans[scan_id]["status"] = "running"

            result = await self.garak.run_scan(
                provider=provider,
                model=model,
                api_key=api_key,
                base_url=base_url,
                probes=probes,
                scan_type=scan_type,
                progress_callback=lambda p, c, t: self._update_scan_progress(
                    scan_id, p, c, t
                ),
                cancel_check=lambda: self._is_scan_cancelled(scan_id),
            )

            with self._scans_lock:
                if scan_id in self.running_scans:
                    # Don't overwrite if cancelled
                    if self.running_scans[scan_id]["status"] != "cancelled":
                        self.running_scans[scan_id].update(
                            {
                                "status": "completed",
                                "progress": 100,
                                "vulnerabilities": result.get("vulnerabilities", []),
                                "completed_at": time.time(),
                            }
                        )

        except Exception as e:
            logger.error(f"Garak scan {scan_id} failed: {e}")
            with self._scans_lock:
                if scan_id in self.running_scans:
                    self.running_scans[scan_id].update(
                        {
                            "status": "failed",
                            "error_message": str(e),
                            "completed_at": time.time(),
                        }
                    )

    def _is_scan_cancelled(self, scan_id: str) -> bool:
        """Check if a scan has been cancelled"""
        with self._scans_lock:
            if scan_id in self.running_scans:
                return self.running_scans[scan_id]["status"] == "cancelled"
        return True  # Treat missing scans as cancelled

    def _update_scan_progress(
        self, scan_id: str, progress: int, completed: int, total: int
    ):
        """Update scan progress"""
        with self._scans_lock:
            if scan_id in self.running_scans:
                self.running_scans[scan_id].update(
                    {
                        "progress": progress,
                        "probes_completed": completed,
                        "probes_total": total,
                    }
                )


def serve():
    """Start the gRPC server"""
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        options=[
            ("grpc.max_send_message_length", 50 * 1024 * 1024),
            ("grpc.max_receive_message_length", 50 * 1024 * 1024),
            ("grpc.keepalive_time_ms", 30000),
            ("grpc.keepalive_timeout_ms", 10000),
            ("grpc.keepalive_permit_without_calls", 1),
        ],
    )

    ml_service_pb2_grpc.add_MlServiceServicer_to_server(MlServiceServicer(), server)

    port = 50051
    server.add_insecure_port(f"[::]:{port}")
    server.start()

    logger.info(f"ML Sidecar gRPC server started on port {port}")

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        server.stop(grace=5)  # 5 second grace period


if __name__ == "__main__":
    serve()
