"use client";

import { useState, useEffect, useCallback } from "react";
import { useSearchParams } from "next/navigation";
import {
  IconFileAnalytics,
  IconShieldCheck,
  IconChevronDown,
  IconChevronUp,
  IconRefresh,
  IconLoader2,
  IconAlertTriangle,
  IconBug,
  IconFlame,
  IconSkull,
  IconCheck,
  IconX,
  IconClock,
  IconTerminal2,
  IconPlayerPlay,
  IconCircleFilled,
  IconActivity,
  IconSend,
  IconCopy,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  listScans,
  getScanResults,
  getScanLogs,
  retestVulnerability,
  type ScanResult,
  type ProbeLog,
  type ScanLogSummary,
  type RetestResult,
} from "@/lib/actions/scans";

// ============================================
// Types
// ============================================

interface ScanDisplay {
  id: string;
  scanType: string;
  status: string;
  vulnerabilitiesFound: number | null;
  riskScore: number | null;
  createdAt: string;
  completedAt: string | null;
}

interface RetestState {
  vulnId: string;
  isRunning: boolean;
  result: RetestResult | null;
  error: string | null;
}

interface RetestFormState {
  provider: string;
  model: string;
  apiKey: string;
  baseUrl: string;
  numAttempts: number;
}

// ============================================
// Helpers
// ============================================

function getSeverityIcon(severity: string) {
  switch (severity.toLowerCase()) {
    case "critical":
      return <IconSkull className="w-4 h-4 text-red-500" />;
    case "high":
      return <IconFlame className="w-4 h-4 text-orange-500" />;
    case "medium":
      return <IconAlertTriangle className="w-4 h-4 text-yellow-500" />;
    default:
      return <IconBug className="w-4 h-4 text-blue-400" />;
  }
}

function getSeverityColor(severity: string) {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-red-500 text-white";
    case "high":
      return "bg-orange-500 text-white";
    case "medium":
      return "bg-yellow-500 text-black";
    default:
      return "bg-blue-500 text-white";
  }
}

function getSeverityBorderColor(severity: string) {
  switch (severity.toLowerCase()) {
    case "critical":
      return "border-l-red-500";
    case "high":
      return "border-l-orange-500";
    case "medium":
      return "border-l-yellow-500";
    default:
      return "border-l-blue-500";
  }
}

function getConfirmationBadge(vuln: ScanResult) {
  if (vuln.confirmed === true) {
    return (
      <span className="flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 font-semibold">
        <IconCheck className="w-3 h-3" />
        CONFIRMED
      </span>
    );
  }
  if (vuln.confirmed === false) {
    return (
      <span className="flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-lime-500/20 text-lime-400 border border-lime-500/30 font-semibold">
        <IconX className="w-3 h-3" />
        NOT CONFIRMED
      </span>
    );
  }
  if ((vuln.retestCount ?? 0) === 0) {
    return (
      <span className="flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-zinc-700/50 text-stone-400 border border-zinc-600 font-mono">
        UNTESTED
      </span>
    );
  }
  return null;
}

function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "-";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

function getProbeStatusIcon(status: string) {
  switch (status) {
    case "passed":
      return <IconCheck className="w-3.5 h-3.5 text-lime-500" />;
    case "failed":
      return <IconX className="w-3.5 h-3.5 text-red-400" />;
    case "error":
      return <IconAlertTriangle className="w-3.5 h-3.5 text-orange-400" />;
    case "skipped":
      return <IconCircleFilled className="w-3.5 h-3.5 text-stone-500" />;
    default:
      return <IconCircleFilled className="w-3.5 h-3.5 text-stone-600" />;
  }
}

function getProbeStatusColor(status: string): string {
  switch (status) {
    case "passed":
      return "text-lime-400";
    case "failed":
      return "text-red-400";
    case "error":
      return "text-orange-400";
    case "skipped":
      return "text-stone-500";
    default:
      return "text-stone-400";
  }
}

// ============================================
// Sub-components
// ============================================

function RetestPanel({
  vuln,
  retestState,
  retestForm,
  onFormChange,
  onRunRetest,
}: {
  vuln: ScanResult;
  retestState: RetestState | null;
  retestForm: RetestFormState;
  onFormChange: (form: RetestFormState) => void;
  onRunRetest: (vulnId: string) => void;
}) {
  const isRunning = retestState?.isRunning ?? false;
  const result = retestState?.result ?? null;
  const error = retestState?.error ?? null;

  return (
    <div className="mt-4 p-4 bg-zinc-800/50 rounded-lg border border-zinc-700/50">
      <div className="flex items-center gap-2 mb-3">
        <IconRefresh className="w-4 h-4 text-blue-400" />
        <h4 className="text-sm font-semibold">Retest Vulnerability</h4>
        <span className="text-[10px] text-stone-500">
          Re-run the same attack prompt to confirm reproducibility
        </span>
      </div>

      {/* Config form */}
      <div className="grid grid-cols-4 gap-3 mb-3">
        <div className="space-y-1">
          <Label className="text-[10px] uppercase text-stone-500">
            Provider
          </Label>
          <Select
            value={retestForm.provider}
            onValueChange={(v) => onFormChange({ ...retestForm, provider: v })}
          >
            <SelectTrigger className="h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="openai">OpenAI</SelectItem>
              <SelectItem value="anthropic">Anthropic</SelectItem>
              <SelectItem value="huggingface">Hugging Face</SelectItem>
              <SelectItem value="ollama">Ollama</SelectItem>
              <SelectItem value="groq">Groq</SelectItem>
              <SelectItem value="together">Together AI</SelectItem>
              <SelectItem value="custom">Custom</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1">
          <Label className="text-[10px] uppercase text-stone-500">Model</Label>
          <Input
            className="h-8 text-xs"
            value={retestForm.model}
            onChange={(e) =>
              onFormChange({ ...retestForm, model: e.target.value })
            }
            placeholder="gpt-4o"
          />
        </div>
        <div className="space-y-1">
          <Label className="text-[10px] uppercase text-stone-500">
            API Key
          </Label>
          <Input
            className="h-8 text-xs"
            type="password"
            value={retestForm.apiKey}
            onChange={(e) =>
              onFormChange({ ...retestForm, apiKey: e.target.value })
            }
            placeholder="Required"
          />
        </div>
        <div className="space-y-1">
          <Label className="text-[10px] uppercase text-stone-500">
            Attempts
          </Label>
          <Select
            value={String(retestForm.numAttempts)}
            onValueChange={(v) =>
              onFormChange({ ...retestForm, numAttempts: parseInt(v) })
            }
          >
            <SelectTrigger className="h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1">1x</SelectItem>
              <SelectItem value="3">3x</SelectItem>
              <SelectItem value="5">5x</SelectItem>
              <SelectItem value="10">10x</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <Button
          size="sm"
          onClick={() => onRunRetest(vuln.id)}
          disabled={isRunning || !retestForm.model || !retestForm.apiKey}
          className="h-7 text-xs"
        >
          {isRunning ? (
            <>
              <IconLoader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
              Retesting...
            </>
          ) : (
            <>
              <IconPlayerPlay className="w-3.5 h-3.5 mr-1.5" />
              Run Retest ({retestForm.numAttempts}x)
            </>
          )}
        </Button>
        {!retestForm.apiKey && (
          <span className="text-[10px] text-orange-400">
            API key required for security — not stored from original scan
          </span>
        )}
      </div>

      {error && (
        <div className="mt-3 p-2 bg-red-900/20 border border-red-700/50 rounded text-red-400 text-xs">
          {error}
        </div>
      )}

      {/* Retest Results */}
      {result && (
        <div className="mt-3 space-y-3">
          <div className="flex items-center gap-4">
            <div
              className={`px-3 py-1.5 rounded-lg text-sm font-bold ${
                result.confirmationRate >= 0.5
                  ? "bg-red-500/20 text-red-400 border border-red-500/30"
                  : "bg-lime-500/20 text-lime-400 border border-lime-500/30"
              }`}
            >
              {result.confirmationRate >= 0.5
                ? "VULNERABILITY CONFIRMED"
                : "NOT CONSISTENTLY REPRODUCIBLE"}
            </div>
            <span className="text-xs text-stone-500">
              {result.vulnerableCount}/{result.totalAttempts} attempts
              vulnerable ({(result.confirmationRate * 100).toFixed(0)}%
              confirmation rate)
            </span>
          </div>

          {/* Per-attempt results */}
          <div className="space-y-1">
            {result.results.map((attempt) => (
              <div
                key={attempt.attemptNumber}
                className="flex items-center gap-3 p-2 bg-zinc-900/50 rounded text-xs"
              >
                <span className="text-stone-500 font-mono min-w-[5ch]">
                  #{attempt.attemptNumber}
                </span>
                {attempt.isVulnerable ? (
                  <span className="flex items-center gap-1 text-red-400 font-semibold min-w-[7rem]">
                    <IconX className="w-3 h-3" />
                    VULNERABLE
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-lime-400 font-semibold min-w-[7rem]">
                    <IconCheck className="w-3 h-3" />
                    SAFE
                  </span>
                )}
                <span className="text-stone-500">
                  Score: {(attempt.detectorScore * 100).toFixed(0)}%
                </span>
                <span className="text-stone-600">
                  {formatDuration(attempt.durationMs)}
                </span>
                {attempt.errorMessage && (
                  <span className="text-orange-400 truncate max-w-[200px]">
                    {attempt.errorMessage}
                  </span>
                )}
                {attempt.modelResponse && (
                  <span className="text-stone-600 truncate max-w-[300px] ml-auto">
                    &quot;{attempt.modelResponse.slice(0, 100)}...&quot;
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function VerboseLogsPanel({
  logs,
  summary,
}: {
  logs: ProbeLog[];
  summary: ScanLogSummary;
}) {
  const [expandedLog, setExpandedLog] = useState<string | null>(null);

  return (
    <div className="mt-4">
      {/* Summary bar */}
      <div className="flex items-center gap-4 mb-3 px-1 text-xs text-stone-500">
        <div className="flex items-center gap-1.5">
          <IconActivity className="w-3.5 h-3.5" />
          <span>{summary.totalProbes} probes</span>
        </div>
        <div className="flex items-center gap-1.5 text-lime-500/70">
          <IconCheck className="w-3.5 h-3.5" />
          <span>{summary.probesPassed} passed</span>
        </div>
        <div className="flex items-center gap-1.5 text-red-400/70">
          <IconX className="w-3.5 h-3.5" />
          <span>{summary.probesFailed} failed</span>
        </div>
        {summary.probesErrored > 0 && (
          <div className="flex items-center gap-1.5 text-orange-400/70">
            <IconAlertTriangle className="w-3.5 h-3.5" />
            <span>{summary.probesErrored} errors</span>
          </div>
        )}
        <div className="flex items-center gap-1.5">
          <IconSend className="w-3.5 h-3.5" />
          <span>{summary.totalPromptsSent} prompts sent</span>
        </div>
        <div className="flex items-center gap-1.5">
          <IconClock className="w-3.5 h-3.5" />
          <span>{formatDuration(summary.totalDurationMs)}</span>
        </div>
      </div>

      <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden divide-y divide-zinc-800/50">
        {logs.length === 0 ? (
          <div className="p-6 text-center text-stone-500 text-sm">
            <IconTerminal2 className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p>No verbose execution logs available for this scan</p>
          </div>
        ) : (
          logs.map((log) => (
            <div key={log.id}>
              <button
                onClick={() =>
                  setExpandedLog(expandedLog === log.id ? null : log.id)
                }
                className="w-full p-3 hover:bg-zinc-800/30 transition-colors text-left"
              >
                <div className="flex items-center gap-3">
                  {getProbeStatusIcon(log.status)}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">
                        {log.probeName}
                      </span>
                      <span
                        className={`text-[10px] font-mono uppercase ${getProbeStatusColor(log.status)}`}
                      >
                        {log.status}
                      </span>
                      {log.probeClass && (
                        <span className="text-[10px] text-stone-600 truncate max-w-[250px]">
                          {log.probeClass}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-4 mt-1 text-[10px] text-stone-500">
                      <span>
                        {log.promptsSent} sent / {log.promptsPassed} passed /{" "}
                        {log.promptsFailed} failed
                      </span>
                      <span>{formatDuration(log.durationMs)}</span>
                      {log.detectorName && <span>det: {log.detectorName}</span>}
                      <span>{log.logLines.length} log entries</span>
                    </div>
                  </div>
                  {expandedLog === log.id ? (
                    <IconChevronUp className="w-4 h-4 text-stone-500" />
                  ) : (
                    <IconChevronDown className="w-4 h-4 text-stone-500" />
                  )}
                </div>
              </button>
              {expandedLog === log.id && (
                <div className="bg-zinc-950 border-t border-zinc-800 px-4 py-3">
                  <div className="font-mono text-[11px] leading-5 space-y-0.5 max-h-[300px] overflow-auto">
                    {log.logLines.length > 0 ? (
                      log.logLines.map((line, i) => {
                        const isError =
                          line.toLowerCase().includes("error") ||
                          line.toLowerCase().includes("fatal");
                        const isWarning =
                          line.toLowerCase().includes("warning") ||
                          line.toLowerCase().includes("warn");
                        const isFailed =
                          line.toLowerCase().includes("failed") ||
                          line.toLowerCase().includes("vulns=");
                        const isResult =
                          line.toLowerCase().includes("results:") ||
                          line.toLowerCase().includes("→");

                        let textColor = "text-stone-400";
                        if (isError) textColor = "text-red-400";
                        else if (isWarning) textColor = "text-orange-400";
                        else if (isFailed) textColor = "text-yellow-400";
                        else if (isResult) textColor = "text-blue-300";

                        return (
                          <div key={i} className={textColor}>
                            <span className="text-stone-600 select-none mr-2">
                              {String(i + 1).padStart(2, "0")}
                            </span>
                            {line}
                          </div>
                        );
                      })
                    ) : (
                      <div className="text-stone-600 italic">
                        No verbose log lines for this probe
                      </div>
                    )}
                  </div>
                  {log.errorMessage && (
                    <div className="mt-2 text-[11px] text-red-400 bg-red-500/5 rounded px-2 py-1">
                      Error: {log.errorMessage}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// ============================================
// Main Page
// ============================================

export default function ReportsPage() {
  const searchParams = useSearchParams();
  const [scans, setScans] = useState<ScanDisplay[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<"vulns" | "logs">("vulns");
  const [probeLogs, setProbeLogs] = useState<ProbeLog[]>([]);
  const [logSummary, setLogSummary] = useState<ScanLogSummary | null>(null);
  const [isLoadingLogs, setIsLoadingLogs] = useState(false);

  // Retest state
  const [retestStates, setRetestStates] = useState<Record<string, RetestState>>(
    {},
  );
  const [retestForm, setRetestForm] = useState<RetestFormState>({
    provider: "openai",
    model: "",
    apiKey: "",
    baseUrl: "",
    numAttempts: 3,
  });
  const [showRetestFor, setShowRetestFor] = useState<string | null>(null);

  // Clipboard feedback
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const loadScans = useCallback(async () => {
    try {
      const data = await listScans(50);
      const completedScans = data.filter(
        (s) => s.status === "completed" || s.status === "failed",
      );
      setScans(
        completedScans.map((s) => ({
          id: s.id,
          scanType: s.scanType,
          status: s.status,
          vulnerabilitiesFound: s.vulnerabilitiesFound,
          riskScore: s.riskScore,
          createdAt: s.createdAt,
          completedAt: s.completedAt,
        })),
      );
    } catch (err) {
      console.error("Failed to load scans:", err);
    }
  }, []);

  const loadResults = useCallback(async (scanId: string) => {
    try {
      const data = await getScanResults(scanId);
      setResults(data);
    } catch (err) {
      console.error("Failed to load scan results:", err);
    }
  }, []);

  const loadLogs = useCallback(async (scanId: string) => {
    setIsLoadingLogs(true);
    try {
      const data = await getScanLogs(scanId);
      if ("error" in data) {
        console.error("Failed to load scan logs:", data.error);
        setProbeLogs([]);
        setLogSummary(null);
      } else {
        setProbeLogs(data.logs);
        setLogSummary(data.summary);
      }
    } catch (err) {
      console.error("Failed to load scan logs:", err);
    } finally {
      setIsLoadingLogs(false);
    }
  }, []);

  useEffect(() => {
    loadScans();
    const scanId = searchParams.get("scan");
    if (scanId) {
      setSelectedScanId(scanId);
      loadResults(scanId);
    }
  }, [searchParams, loadScans, loadResults]);

  const handleSelectScan = (scanId: string) => {
    setSelectedScanId(scanId);
    setExpandedVuln(null);
    setShowRetestFor(null);
    setActiveSection("vulns");
    loadResults(scanId);
  };

  const handleShowLogs = () => {
    if (selectedScanId && probeLogs.length === 0) {
      loadLogs(selectedScanId);
    }
    setActiveSection("logs");
  };

  const handleRunRetest = async (vulnId: string) => {
    setRetestStates((prev) => ({
      ...prev,
      [vulnId]: { vulnId, isRunning: true, result: null, error: null },
    }));

    const result = await retestVulnerability({
      vulnerabilityId: vulnId,
      provider: retestForm.provider,
      model: retestForm.model,
      apiKey: retestForm.apiKey || undefined,
      baseUrl: retestForm.baseUrl || undefined,
      numAttempts: retestForm.numAttempts,
    });

    if ("error" in result) {
      setRetestStates((prev) => ({
        ...prev,
        [vulnId]: {
          vulnId,
          isRunning: false,
          result: null,
          error: result.error,
        },
      }));
    } else {
      setRetestStates((prev) => ({
        ...prev,
        [vulnId]: { vulnId, isRunning: false, result, error: null },
      }));

      // Update the vuln's confirmed status in the results list
      setResults((prev) =>
        prev.map((v) =>
          v.id === vulnId
            ? {
                ...v,
                confirmed: result.confirmed,
                retestCount: (v.retestCount ?? 0) + result.totalAttempts,
                retestConfirmed:
                  (v.retestConfirmed ?? 0) + result.vulnerableCount,
              }
            : v,
        ),
      );
    }
  };

  const handleCopyPrompt = (text: string, vulnId: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedId(vulnId);
      setTimeout(() => setCopiedId(null), 2000);
    });
  };

  const selectedScan = scans.find((s) => s.id === selectedScanId);

  const criticalCount = results.filter((r) => r.severity === "critical").length;
  const highCount = results.filter((r) => r.severity === "high").length;
  const mediumCount = results.filter((r) => r.severity === "medium").length;
  const lowCount = results.filter((r) => r.severity === "low").length;
  const confirmedCount = results.filter((r) => r.confirmed === true).length;
  const untestedCount = results.filter(
    (r) => r.confirmed === null || r.confirmed === undefined,
  ).length;

  return (
    <section className="px-4 py-6 w-full flex flex-col gap-10">
      <div>
        <h1 className="text-xl font-bold">Scan Reports</h1>
        <p className="text-sm text-neutral-400">
          View detailed vulnerability reports, retest to confirm, and review
          verbose execution logs
        </p>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Scan List (Left Panel) */}
        <div className="flex flex-col gap-4">
          <div className="flex gap-4 items-center">
            <div className="flex gap-2 items-center">
              <IconFileAnalytics className="w-4 h-4 text-stone-500" />
              <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
                Completed Scans
              </span>
            </div>
          </div>

          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden">
            {scans.length === 0 ? (
              <div className="p-8 text-center text-stone-500">
                <IconFileAnalytics className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No completed scans</p>
                <p className="text-xs mt-1 text-stone-600">
                  Run a scan from the Scanner page to see results here
                </p>
              </div>
            ) : (
              <div className="divide-y divide-zinc-800 max-h-[600px] overflow-auto">
                {scans.map((scan) => (
                  <button
                    key={scan.id}
                    onClick={() => handleSelectScan(scan.id)}
                    className={`w-full p-4 text-left hover:bg-zinc-800 transition-colors ${
                      selectedScanId === scan.id ? "bg-zinc-800" : ""
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium capitalize">
                        {scan.scanType} Scan
                      </span>
                      <span
                        className={`text-xs px-2 py-0.5 rounded ${
                          scan.status === "completed"
                            ? "bg-lime-500/20 text-lime-400"
                            : "bg-red-500/20 text-red-400"
                        }`}
                      >
                        {scan.status}
                      </span>
                    </div>
                    <div className="text-sm text-stone-500">
                      {scan.vulnerabilitiesFound} vulnerabilities | Risk:{" "}
                      {scan.riskScore !== null
                        ? (scan.riskScore * 100).toFixed(0) + "%"
                        : "N/A"}
                    </div>
                    <div className="text-xs text-stone-600 mt-1">
                      {new Date(scan.createdAt).toLocaleString()}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Report Details (Right Panel) */}
        <div className="col-span-2 flex flex-col gap-4">
          <div className="flex gap-4 items-center">
            <div className="flex gap-2 items-center">
              <IconFileAnalytics className="w-4 h-4 text-stone-500" />
              <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
                Report Details
              </span>
            </div>
            <span className="flex-1 h-px bg-stone-200"></span>
          </div>

          {!selectedScan ? (
            <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-8 text-center text-stone-500">
              <IconFileAnalytics className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>Select a scan to view its report</p>
            </div>
          ) : (
            <div className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden">
              {/* Report Header */}
              <div className="p-6 border-b border-zinc-800">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold capitalize">
                    {selectedScan.scanType} Scan Report
                  </h2>
                  <div className="flex items-center gap-3">
                    {confirmedCount > 0 && (
                      <span className="px-2 py-1 rounded text-xs font-semibold bg-red-500/20 text-red-400">
                        {confirmedCount} confirmed
                      </span>
                    )}
                    <span
                      className={`px-3 py-1 rounded-lg font-semibold ${
                        (selectedScan.riskScore || 0) >= 0.7
                          ? "bg-red-500/20 text-red-400"
                          : (selectedScan.riskScore || 0) >= 0.4
                            ? "bg-orange-500/20 text-orange-400"
                            : "bg-lime-500/20 text-lime-400"
                      }`}
                    >
                      Risk:{" "}
                      {selectedScan.riskScore !== null
                        ? (selectedScan.riskScore * 100).toFixed(0) + "%"
                        : "N/A"}
                    </span>
                  </div>
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-6 gap-3">
                  <div className="p-3 bg-zinc-800 rounded-lg text-center">
                    <p className="text-2xl font-bold">
                      {selectedScan.vulnerabilitiesFound || 0}
                    </p>
                    <p className="text-[10px] text-stone-500 uppercase font-mono">
                      Total
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-800 rounded-lg text-center">
                    <p className="text-2xl font-bold text-red-500">
                      {criticalCount}
                    </p>
                    <p className="text-[10px] text-stone-500 uppercase font-mono">
                      Critical
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-800 rounded-lg text-center">
                    <p className="text-2xl font-bold text-orange-500">
                      {highCount}
                    </p>
                    <p className="text-[10px] text-stone-500 uppercase font-mono">
                      High
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-800 rounded-lg text-center">
                    <p className="text-2xl font-bold text-yellow-500">
                      {mediumCount}
                    </p>
                    <p className="text-[10px] text-stone-500 uppercase font-mono">
                      Medium
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-800 rounded-lg text-center">
                    <p className="text-2xl font-bold text-blue-400">
                      {lowCount}
                    </p>
                    <p className="text-[10px] text-stone-500 uppercase font-mono">
                      Low
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-800 rounded-lg text-center">
                    <p className="text-2xl font-bold text-stone-400">
                      {untestedCount}
                    </p>
                    <p className="text-[10px] text-stone-500 uppercase font-mono">
                      Untested
                    </p>
                  </div>
                </div>
              </div>

              {/* Section Tabs */}
              <div className="flex border-b border-zinc-800">
                <button
                  onClick={() => setActiveSection("vulns")}
                  className={`px-4 py-2.5 text-xs font-mono uppercase tracking-wider transition-colors ${
                    activeSection === "vulns"
                      ? "text-white border-b-2 border-blue-500 bg-zinc-800/50"
                      : "text-stone-500 hover:text-stone-300"
                  }`}
                >
                  <div className="flex items-center gap-1.5">
                    <IconBug className="w-3.5 h-3.5" />
                    Vulnerabilities ({results.length})
                  </div>
                </button>
                <button
                  onClick={handleShowLogs}
                  className={`px-4 py-2.5 text-xs font-mono uppercase tracking-wider transition-colors ${
                    activeSection === "logs"
                      ? "text-white border-b-2 border-blue-500 bg-zinc-800/50"
                      : "text-stone-500 hover:text-stone-300"
                  }`}
                >
                  <div className="flex items-center gap-1.5">
                    <IconTerminal2 className="w-3.5 h-3.5" />
                    Execution Logs
                    {isLoadingLogs && (
                      <IconLoader2 className="w-3 h-3 animate-spin" />
                    )}
                  </div>
                </button>
              </div>

              {/* Vulnerabilities Tab */}
              {activeSection === "vulns" && (
                <div className="max-h-[600px] overflow-auto">
                  {results.length === 0 ? (
                    <div className="p-8 text-center text-stone-500">
                      <IconShieldCheck className="w-12 h-12 mx-auto mb-4 text-lime-500" />
                      <p>No vulnerabilities found!</p>
                      <p className="text-xs mt-1">
                        Your model passed all security probes.
                      </p>
                    </div>
                  ) : (
                    <div className="divide-y divide-zinc-800">
                      {results.map((vuln) => (
                        <div
                          key={vuln.id}
                          className={`border-l-2 ${getSeverityBorderColor(vuln.severity)}`}
                        >
                          <button
                            onClick={() =>
                              setExpandedVuln(
                                expandedVuln === vuln.id ? null : vuln.id,
                              )
                            }
                            className="w-full p-4 text-left hover:bg-zinc-800/30 transition-colors"
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-3">
                                {getSeverityIcon(vuln.severity)}
                                <span
                                  className={`px-2 py-0.5 text-xs font-semibold uppercase rounded ${getSeverityColor(vuln.severity)}`}
                                >
                                  {vuln.severity}
                                </span>
                                <span className="font-medium">
                                  {vuln.probeName}
                                </span>
                                <span className="text-sm text-stone-500">
                                  {vuln.category}
                                </span>
                                {getConfirmationBadge(vuln)}
                              </div>
                              <div className="flex items-center gap-3">
                                {vuln.successRate != null && (
                                  <span className="text-[10px] text-stone-500">
                                    Score: {(vuln.successRate * 100).toFixed(0)}
                                    %
                                  </span>
                                )}
                                {vuln.probeDurationMs != null && (
                                  <span className="text-[10px] text-stone-600">
                                    {formatDuration(vuln.probeDurationMs)}
                                  </span>
                                )}
                                {(vuln.retestCount ?? 0) > 0 && (
                                  <span className="text-[10px] text-stone-500">
                                    {vuln.retestConfirmed ?? 0}/
                                    {vuln.retestCount ?? 0} retests
                                  </span>
                                )}
                                <IconChevronDown
                                  className={`w-4 h-4 text-stone-500 transition-transform ${
                                    expandedVuln === vuln.id ? "rotate-180" : ""
                                  }`}
                                />
                              </div>
                            </div>
                          </button>

                          {expandedVuln === vuln.id && (
                            <div className="px-4 pb-4 space-y-3">
                              {/* Meta info row */}
                              <div className="flex flex-wrap gap-3 text-[10px] text-stone-500">
                                {vuln.detectorName && (
                                  <span className="px-2 py-0.5 bg-zinc-800 rounded">
                                    Detector: {vuln.detectorName}
                                  </span>
                                )}
                                {vuln.probeClass && (
                                  <span className="px-2 py-0.5 bg-zinc-800 rounded font-mono">
                                    {vuln.probeClass}
                                  </span>
                                )}
                                {vuln.successRate != null && (
                                  <span className="px-2 py-0.5 bg-zinc-800 rounded">
                                    Detector Score:{" "}
                                    {(vuln.successRate * 100).toFixed(1)}%
                                  </span>
                                )}
                              </div>

                              {/* Description */}
                              <div>
                                <p className="text-xs text-stone-500 uppercase font-mono mb-1">
                                  Description
                                </p>
                                <p className="text-sm">{vuln.description}</p>
                              </div>

                              {/* Attack Prompt */}
                              {vuln.attackPrompt && (
                                <div>
                                  <div className="flex items-center justify-between mb-1">
                                    <p className="text-xs text-stone-500 uppercase font-mono">
                                      Attack Prompt
                                    </p>
                                    <button
                                      onClick={() =>
                                        handleCopyPrompt(
                                          vuln.attackPrompt,
                                          vuln.id,
                                        )
                                      }
                                      className="flex items-center gap-1 text-[10px] text-stone-500 hover:text-stone-300 transition-colors"
                                    >
                                      {copiedId === vuln.id ? (
                                        <>
                                          <IconCheck className="w-3 h-3 text-lime-400" />
                                          Copied
                                        </>
                                      ) : (
                                        <>
                                          <IconCopy className="w-3 h-3" />
                                          Copy
                                        </>
                                      )}
                                    </button>
                                  </div>
                                  <pre className="text-sm bg-zinc-800 p-3 rounded overflow-x-auto max-h-[200px] overflow-y-auto text-orange-300/80 font-mono text-xs leading-5">
                                    {vuln.attackPrompt}
                                  </pre>
                                </div>
                              )}

                              {/* Model Response */}
                              {vuln.modelResponse && (
                                <div>
                                  <p className="text-xs text-stone-500 uppercase font-mono mb-1">
                                    Model Response
                                  </p>
                                  <pre className="text-sm bg-zinc-800 p-3 rounded overflow-x-auto max-h-[200px] overflow-y-auto text-red-300/80 font-mono text-xs leading-5">
                                    {vuln.modelResponse}
                                  </pre>
                                </div>
                              )}

                              {/* Recommendation */}
                              {vuln.recommendation && (
                                <div>
                                  <p className="text-xs text-stone-500 uppercase font-mono mb-1">
                                    Recommendation
                                  </p>
                                  <p className="text-sm text-lime-400">
                                    {vuln.recommendation}
                                  </p>
                                </div>
                              )}

                              {/* Retest Toggle */}
                              <div className="pt-2">
                                <Button
                                  variant="outline"
                                  size="sm"
                                  className="h-7 text-xs"
                                  onClick={() =>
                                    setShowRetestFor(
                                      showRetestFor === vuln.id
                                        ? null
                                        : vuln.id,
                                    )
                                  }
                                >
                                  <IconRefresh className="w-3.5 h-3.5 mr-1.5" />
                                  {showRetestFor === vuln.id
                                    ? "Hide Retest"
                                    : "Retest to Confirm"}
                                </Button>
                              </div>

                              {/* Retest Panel */}
                              {showRetestFor === vuln.id && (
                                <RetestPanel
                                  vuln={vuln}
                                  retestState={retestStates[vuln.id] || null}
                                  retestForm={retestForm}
                                  onFormChange={setRetestForm}
                                  onRunRetest={handleRunRetest}
                                />
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Execution Logs Tab */}
              {activeSection === "logs" && (
                <div className="p-4 max-h-[600px] overflow-auto">
                  {isLoadingLogs ? (
                    <div className="p-8 text-center text-stone-500">
                      <IconLoader2 className="w-8 h-8 mx-auto mb-3 animate-spin" />
                      <p className="text-sm">Loading execution logs...</p>
                    </div>
                  ) : logSummary ? (
                    <VerboseLogsPanel logs={probeLogs} summary={logSummary} />
                  ) : (
                    <div className="p-8 text-center text-stone-500">
                      <IconTerminal2 className="w-10 h-10 mx-auto mb-3 opacity-50" />
                      <p className="text-sm">
                        No execution logs available for this scan
                      </p>
                      <p className="text-xs mt-1 text-stone-600">
                        Verbose logs are generated by the Garak scanner during
                        probe execution
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
