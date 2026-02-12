"use client";

import { useState, useEffect, useCallback } from "react";
import {
  IconShieldBolt,
  IconSend,
  IconLoader2,
  IconCheck,
  IconAlertTriangle,
  IconX,
  IconChevronDown,
  IconChevronRight,
  IconSettings,
  IconFilter,
  IconArrowRight,
  IconArrowLeft,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import {
  advancedScan,
  type AdvancedScanResult,
  type AdvancedScannerResultItem,
  type ScanMode,
  type ScannerConfigInput,
} from "@/lib/actions/guard";
import { listApiKeys } from "@/lib/actions/api-keys";
import {
  ALL_INPUT_SCANNERS,
  ALL_OUTPUT_SCANNERS,
  SCANNER_META,
  type InputScannerName,
  type OutputScannerName,
} from "@/lib/api";

// ============================================
// Types
// ============================================

type ScannerEntry = {
  enabled: boolean;
  threshold: number;
  settingsJson: string;
  expanded: boolean;
};

type Tab = "config" | "test";

// ============================================
// Constants
// ============================================

const DEFAULT_INPUT_SCANNERS: InputScannerName[] = [
  "prompt_injection",
  "toxicity",
  "anonymize",
  "secrets",
  "gibberish",
  "invisible_text",
];

const DEFAULT_OUTPUT_SCANNERS: OutputScannerName[] = [
  "sensitive",
  "toxicity",
  "malicious_urls",
  "bias",
  "deanonymize",
];

const CATEGORY_COLORS: Record<string, string> = {
  Security: "bg-red-500/15 text-red-400 border-red-500/30",
  Safety: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  Privacy: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  Content: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  Quality: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  Business: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  Custom: "bg-pink-500/15 text-pink-400 border-pink-500/30",
};

// ============================================
// Helpers
// ============================================

function buildDefaultInputScanners(): Record<string, ScannerEntry> {
  const entries: Record<string, ScannerEntry> = {};
  for (const name of ALL_INPUT_SCANNERS) {
    entries[name] = {
      enabled: DEFAULT_INPUT_SCANNERS.includes(name),
      threshold: 0.5,
      settingsJson: "",
      expanded: false,
    };
  }
  return entries;
}

function buildDefaultOutputScanners(): Record<string, ScannerEntry> {
  const entries: Record<string, ScannerEntry> = {};
  for (const name of ALL_OUTPUT_SCANNERS) {
    entries[name] = {
      enabled: DEFAULT_OUTPUT_SCANNERS.includes(name),
      threshold: 0.5,
      settingsJson: "",
      expanded: false,
    };
  }
  return entries;
}

function getSeverityColor(severity: string) {
  switch (severity.toLowerCase()) {
    case "critical":
      return "text-red-500 bg-red-500/10 border-red-500/30";
    case "high":
      return "text-orange-500 bg-orange-500/10 border-orange-500/30";
    case "medium":
      return "text-yellow-500 bg-yellow-500/10 border-yellow-500/30";
    default:
      return "text-blue-500 bg-blue-500/10 border-blue-500/30";
  }
}

function countEnabled(scanners: Record<string, ScannerEntry>): number {
  return Object.values(scanners).filter((s) => s.enabled).length;
}

// ============================================
// Scanner Card Component
// ============================================

function ScannerCard({
  name,
  entry,
  onToggle,
  onThresholdChange,
  onSettingsChange,
  onToggleExpand,
}: {
  name: string;
  entry: ScannerEntry;
  onToggle: () => void;
  onThresholdChange: (v: number) => void;
  onSettingsChange: (v: string) => void;
  onToggleExpand: () => void;
}) {
  const meta = SCANNER_META[name] || {
    label: name,
    description: "No description available",
    category: "Custom",
  };
  const catColor =
    CATEGORY_COLORS[meta.category] ||
    "bg-stone-500/15 text-stone-400 border-stone-500/30";

  return (
    <div
      className={`border rounded-xl transition-all duration-200 ${
        entry.enabled
          ? "border-zinc-700 bg-zinc-900"
          : "border-zinc-800/60 bg-zinc-900/40 opacity-60"
      }`}
    >
      {/* Header row */}
      <div className="flex items-center gap-3 px-4 py-3">
        {/* Toggle */}
        <button
          onClick={onToggle}
          className={`relative w-9 h-5 rounded-full transition-colors flex-shrink-0 ${
            entry.enabled ? "bg-lime-600" : "bg-zinc-700"
          }`}
          aria-label={`Toggle ${meta.label}`}
        >
          <span
            className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
              entry.enabled ? "translate-x-4" : "translate-x-0"
            }`}
          />
        </button>

        {/* Name + category */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-stone-200 truncate">
              {meta.label}
            </span>
            <span
              className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border ${catColor}`}
            >
              {meta.category}
            </span>
          </div>
          <p className="text-xs text-stone-500 mt-0.5 line-clamp-1">
            {meta.description}
          </p>
        </div>

        {/* Expand button */}
        <button
          onClick={onToggleExpand}
          className="text-stone-500 hover:text-stone-300 transition-colors p-1"
          aria-label="Expand settings"
        >
          {entry.expanded ? (
            <IconChevronDown className="w-4 h-4" />
          ) : (
            <IconChevronRight className="w-4 h-4" />
          )}
        </button>
      </div>

      {/* Expanded settings */}
      {entry.expanded && (
        <div className="border-t border-zinc-800 px-4 py-3 space-y-3">
          {/* Threshold */}
          <div className="flex items-center gap-3">
            <label className="text-xs text-stone-500 font-mono uppercase w-20">
              Threshold
            </label>
            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={entry.threshold}
              onChange={(e) => onThresholdChange(parseFloat(e.target.value))}
              className="flex-1 accent-lime-500 h-1.5"
            />
            <span className="text-xs font-mono text-stone-400 w-10 text-right">
              {entry.threshold.toFixed(2)}
            </span>
          </div>

          {/* Settings JSON */}
          {(meta.requiresSettings || meta.settingsHint) && (
            <div className="space-y-1">
              <label className="text-xs text-stone-500 font-mono uppercase">
                Settings (JSON)
              </label>
              <textarea
                className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-xs font-mono text-stone-300 min-h-[60px] focus:outline-none focus:border-zinc-600 resize-y"
                placeholder={meta.settingsHint || "{}"}
                value={entry.settingsJson}
                onChange={(e) => onSettingsChange(e.target.value)}
              />
              {meta.requiresSettings && !entry.settingsJson && (
                <p className="text-[10px] text-yellow-500">
                  ⚠ This scanner requires settings to work properly
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ============================================
// Scanner Result Card
// ============================================

function ScannerResultCard({ result }: { result: AdvancedScannerResultItem }) {
  const meta = SCANNER_META[result.scannerName] || {
    label: result.scannerName,
    description: "",
    category: "Custom",
  };

  return (
    <div
      className={`p-3 rounded-lg border ${
        result.isValid
          ? "border-zinc-800 bg-zinc-900/50"
          : getSeverityColor(result.severity)
      }`}
    >
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          {result.isValid ? (
            <IconCheck className="w-3.5 h-3.5 text-lime-500" />
          ) : (
            <IconAlertTriangle className="w-3.5 h-3.5" />
          )}
          <span className="font-semibold text-sm">{meta.label}</span>
        </div>
        <div className="flex items-center gap-2">
          {!result.isValid && (
            <span className="text-[10px] uppercase font-mono">
              {result.severity}
            </span>
          )}
          <span className="text-xs font-mono text-stone-500">
            {(result.score * 100).toFixed(0)}%
          </span>
        </div>
      </div>
      {result.description && (
        <p className="text-xs opacity-80 mt-0.5">{result.description}</p>
      )}
    </div>
  );
}

// ============================================
// Main Guard Page
// ============================================

export default function GuardPage() {
  // ── State ────────────────────────────────────────────────────
  const [activeTab, setActiveTab] = useState<Tab>("config");

  // API key
  const [apiKey, setApiKey] = useState("");
  const [apiKeys, setApiKeys] = useState<
    Array<{ id: string; name: string; keyPrefix: string }>
  >([]);

  // Scan mode
  const [scanMode, setScanMode] = useState<ScanMode>("prompt_only");

  // Scanner configs
  const [inputScanners, setInputScanners] = useState<
    Record<string, ScannerEntry>
  >(buildDefaultInputScanners);
  const [outputScanners, setOutputScanners] = useState<
    Record<string, ScannerEntry>
  >(buildDefaultOutputScanners);

  // Filter
  const [inputFilter, setInputFilter] = useState("");
  const [outputFilter, setOutputFilter] = useState("");

  // Test panel
  const [prompt, setPrompt] = useState("");
  const [output, setOutput] = useState("");
  const [sanitize, setSanitize] = useState(false);
  const [failFast, setFailFast] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<AdvancedScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // ── Load API keys ────────────────────────────────────────────
  useEffect(() => {
    (async () => {
      const keys = await listApiKeys();
      setApiKeys(
        keys.map((k) => ({
          id: k.id,
          name: k.name,
          keyPrefix: k.keyPrefix,
        })),
      );
    })();
  }, []);

  // ── Scanner update helpers ───────────────────────────────────

  const updateInputScanner = useCallback(
    (name: string, patch: Partial<ScannerEntry>) => {
      setInputScanners((prev) => ({
        ...prev,
        [name]: { ...prev[name], ...patch },
      }));
    },
    [],
  );

  const updateOutputScanner = useCallback(
    (name: string, patch: Partial<ScannerEntry>) => {
      setOutputScanners((prev) => ({
        ...prev,
        [name]: { ...prev[name], ...patch },
      }));
    },
    [],
  );

  const toggleAllInput = useCallback((enabled: boolean) => {
    setInputScanners((prev) => {
      const next = { ...prev };
      for (const key of Object.keys(next)) {
        next[key] = { ...next[key], enabled };
      }
      return next;
    });
  }, []);

  const toggleAllOutput = useCallback((enabled: boolean) => {
    setOutputScanners((prev) => {
      const next = { ...prev };
      for (const key of Object.keys(next)) {
        next[key] = { ...next[key], enabled };
      }
      return next;
    });
  }, []);

  const resetToDefaults = useCallback(() => {
    setInputScanners(buildDefaultInputScanners());
    setOutputScanners(buildDefaultOutputScanners());
    setScanMode("prompt_only");
    setSanitize(false);
    setFailFast(false);
  }, []);

  // ── Scan handler ─────────────────────────────────────────────

  const handleScan = async () => {
    if (!apiKey) return;

    // Validate required text based on scan mode
    if ((scanMode === "prompt_only" || scanMode === "both") && !prompt.trim()) {
      setScanError("Prompt is required for prompt_only or both scan modes");
      return;
    }
    if ((scanMode === "output_only" || scanMode === "both") && !output.trim()) {
      setScanError("Output is required for output_only or both scan modes");
      return;
    }

    setIsScanning(true);
    setScanError(null);
    setScanResult(null);

    try {
      // Build scanner configs — only include enabled scanners
      const inputCfg: Record<string, ScannerConfigInput> = {};
      for (const [name, entry] of Object.entries(inputScanners)) {
        inputCfg[name] = {
          enabled: entry.enabled,
          threshold: entry.threshold,
          settingsJson: entry.settingsJson,
        };
      }

      const outputCfg: Record<string, ScannerConfigInput> = {};
      for (const [name, entry] of Object.entries(outputScanners)) {
        outputCfg[name] = {
          enabled: entry.enabled,
          threshold: entry.threshold,
          settingsJson: entry.settingsJson,
        };
      }

      const result = await advancedScan({
        prompt: prompt || undefined,
        output: output || undefined,
        apiKey,
        scanMode,
        inputScanners: inputCfg,
        outputScanners: outputCfg,
        sanitize,
        failFast,
      });

      if ("error" in result) {
        setScanError(result.error);
      } else {
        setScanResult(result);
        // Automatically switch to test tab to show results
        setActiveTab("test");
      }
    } catch (err) {
      setScanError(
        err instanceof Error ? err.message : "Failed to run advanced scan",
      );
    } finally {
      setIsScanning(false);
    }
  };

  // ── Filtered scanner lists ───────────────────────────────────

  const filteredInputScanners = ALL_INPUT_SCANNERS.filter((name) => {
    if (!inputFilter) return true;
    const meta = SCANNER_META[name];
    const q = inputFilter.toLowerCase();
    return (
      name.includes(q) ||
      meta?.label.toLowerCase().includes(q) ||
      meta?.category.toLowerCase().includes(q)
    );
  });

  const filteredOutputScanners = ALL_OUTPUT_SCANNERS.filter((name) => {
    if (!outputFilter) return true;
    const meta = SCANNER_META[name];
    const q = outputFilter.toLowerCase();
    return (
      name.includes(q) ||
      meta?.label.toLowerCase().includes(q) ||
      meta?.category.toLowerCase().includes(q)
    );
  });

  const enabledInputCount = countEnabled(inputScanners);
  const enabledOutputCount = countEnabled(outputScanners);
  const showInputScanners = scanMode === "prompt_only" || scanMode === "both";
  const showOutputScanners = scanMode === "output_only" || scanMode === "both";

  // ── Render ───────────────────────────────────────────────────

  return (
    <section className="px-4 py-6 w-full flex flex-col gap-6">
      {/* Page Header */}
      <div>
        <h1 className="text-xl font-bold">LLM Guard</h1>
        <p className="text-sm text-neutral-400">
          Configure and test all LLM Guard scanners with full customization —
          prompt scanners, output scanners, or both
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-1 bg-zinc-900 border border-zinc-800 rounded-xl p-1 w-fit">
        <button
          onClick={() => setActiveTab("config")}
          className={`px-4 py-2 text-sm font-semibold rounded-lg transition-colors ${
            activeTab === "config"
              ? "bg-zinc-700 text-white"
              : "text-stone-500 hover:text-stone-300"
          }`}
        >
          <IconSettings className="w-4 h-4 inline mr-1.5 -mt-0.5" />
          Scanner Config
        </button>
        <button
          onClick={() => setActiveTab("test")}
          className={`px-4 py-2 text-sm font-semibold rounded-lg transition-colors ${
            activeTab === "test"
              ? "bg-zinc-700 text-white"
              : "text-stone-500 hover:text-stone-300"
          }`}
        >
          <IconShieldBolt className="w-4 h-4 inline mr-1.5 -mt-0.5" />
          Test & Results
        </button>
      </div>

      {/* ============================================ */}
      {/* Top controls: API Key + Scan Mode + Options  */}
      {/* ============================================ */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* API Key */}
          <div className="space-y-1.5">
            <Label className="text-xs font-mono uppercase text-stone-500">
              API Key
            </Label>
            <Input
              type="password"
              placeholder="ora_..."
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="font-mono text-sm"
            />
            <p className="text-[10px] text-stone-600">
              {apiKeys.length === 0 ? (
                <>
                  No API keys found.{" "}
                  <a
                    href="/credentials"
                    className="text-blue-500 hover:underline"
                  >
                    Create one
                  </a>{" "}
                  first.
                </>
              ) : (
                <>
                  Your keys: {apiKeys.map((k) => k.name).join(", ")}. Enter the
                  full key above.
                </>
              )}
            </p>
          </div>

          {/* Scan Mode */}
          <div className="space-y-1.5">
            <Label className="text-xs font-mono uppercase text-stone-500">
              Scan Mode
            </Label>
            <div className="flex gap-1.5">
              {(
                [
                  {
                    mode: "prompt_only" as ScanMode,
                    label: "Prompt Only",
                    icon: "→",
                  },
                  {
                    mode: "output_only" as ScanMode,
                    label: "Output Only",
                    icon: "←",
                  },
                  { mode: "both" as ScanMode, label: "Both", icon: "⇄" },
                ] as const
              ).map(({ mode, label, icon }) => (
                <button
                  key={mode}
                  onClick={() => setScanMode(mode)}
                  className={`flex-1 px-3 py-2 text-xs font-mono uppercase rounded-lg border transition-colors ${
                    scanMode === mode
                      ? "bg-brand-500/20 border-brand-500 text-brand-400"
                      : "border-zinc-700 text-stone-500 hover:text-stone-300"
                  }`}
                >
                  <span className="mr-1">{icon}</span>
                  {label}
                </button>
              ))}
            </div>
            <p className="text-[10px] text-stone-600">
              {scanMode === "prompt_only" &&
                "Scan input prompts before they reach the LLM"}
              {scanMode === "output_only" &&
                "Scan LLM output/responses for issues"}
              {scanMode === "both" && "Scan both the prompt and LLM output"}
            </p>
          </div>

          {/* Options */}
          <div className="space-y-1.5">
            <Label className="text-xs font-mono uppercase text-stone-500">
              Options
            </Label>
            <div className="flex flex-col gap-1.5">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={sanitize}
                  onChange={(e) => setSanitize(e.target.checked)}
                  className="rounded border-zinc-600 accent-lime-500"
                />
                <span className="text-xs text-stone-400">
                  Return sanitized text
                </span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={failFast}
                  onChange={(e) => setFailFast(e.target.checked)}
                  className="rounded border-zinc-600 accent-lime-500"
                />
                <span className="text-xs text-stone-400">
                  Fail fast (stop after first failure)
                </span>
              </label>
            </div>
            <button
              onClick={resetToDefaults}
              className="text-[10px] text-stone-600 hover:text-stone-400 underline"
            >
              Reset all to defaults
            </button>
          </div>
        </div>

        {/* Summary bar */}
        <div className="flex items-center justify-between pt-2 border-t border-zinc-800">
          <div className="flex items-center gap-4">
            {showInputScanners && (
              <span className="text-xs font-mono text-stone-500">
                <span className="text-lime-400 font-semibold">
                  {enabledInputCount}
                </span>{" "}
                / {ALL_INPUT_SCANNERS.length} input scanners
              </span>
            )}
            {showOutputScanners && (
              <span className="text-xs font-mono text-stone-500">
                <span className="text-lime-400 font-semibold">
                  {enabledOutputCount}
                </span>{" "}
                / {ALL_OUTPUT_SCANNERS.length} output scanners
              </span>
            )}
          </div>
          <Button
            onClick={handleScan}
            disabled={isScanning || !apiKey}
            size="sm"
          >
            {isScanning ? (
              <>
                <IconLoader2 className="w-4 h-4 mr-2 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <IconSend className="w-4 h-4 mr-2" />
                Run Scan
              </>
            )}
          </Button>
        </div>
      </div>

      {/* ============================================ */}
      {/* Config Tab                                   */}
      {/* ============================================ */}
      {activeTab === "config" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* ── Input (Prompt) Scanners ────────────────────── */}
          {showInputScanners && (
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <div className="flex gap-2 items-center">
                  <IconArrowRight className="w-4 h-4 text-stone-500" />
                  <span className="text-stone-400 font-semibold text-xs uppercase font-mono tracking-wider">
                    Input (Prompt) Scanners
                  </span>
                  <span className="text-[10px] font-mono bg-zinc-800 text-stone-500 px-1.5 py-0.5 rounded">
                    {enabledInputCount}/{ALL_INPUT_SCANNERS.length}
                  </span>
                </div>
                <div className="flex gap-1">
                  <button
                    onClick={() => toggleAllInput(true)}
                    className="text-[10px] font-mono text-lime-500 hover:text-lime-400 px-2 py-0.5 rounded border border-lime-500/20 hover:border-lime-500/40"
                  >
                    All on
                  </button>
                  <button
                    onClick={() => toggleAllInput(false)}
                    className="text-[10px] font-mono text-red-500 hover:text-red-400 px-2 py-0.5 rounded border border-red-500/20 hover:border-red-500/40"
                  >
                    All off
                  </button>
                </div>
              </div>

              {/* Search */}
              <div className="relative">
                <IconFilter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-stone-600" />
                <input
                  type="text"
                  placeholder="Filter scanners..."
                  value={inputFilter}
                  onChange={(e) => setInputFilter(e.target.value)}
                  className="w-full bg-zinc-900 border border-zinc-800 rounded-lg pl-8 pr-3 py-2 text-xs text-stone-400 placeholder-stone-600 focus:outline-none focus:border-zinc-700"
                />
              </div>

              {/* Scanner cards */}
              <div className="flex flex-col gap-2 max-h-[600px] overflow-y-auto pr-1">
                {filteredInputScanners.map((name) => (
                  <ScannerCard
                    key={`input-${name}`}
                    name={name}
                    entry={inputScanners[name]}
                    onToggle={() =>
                      updateInputScanner(name, {
                        enabled: !inputScanners[name].enabled,
                      })
                    }
                    onThresholdChange={(v) =>
                      updateInputScanner(name, { threshold: v })
                    }
                    onSettingsChange={(v) =>
                      updateInputScanner(name, { settingsJson: v })
                    }
                    onToggleExpand={() =>
                      updateInputScanner(name, {
                        expanded: !inputScanners[name].expanded,
                      })
                    }
                  />
                ))}
                {filteredInputScanners.length === 0 && (
                  <p className="text-xs text-stone-600 text-center py-4">
                    No scanners match &quot;{inputFilter}&quot;
                  </p>
                )}
              </div>
            </div>
          )}

          {/* ── Output Scanners ────────────────────────────── */}
          {showOutputScanners && (
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <div className="flex gap-2 items-center">
                  <IconArrowLeft className="w-4 h-4 text-stone-500" />
                  <span className="text-stone-400 font-semibold text-xs uppercase font-mono tracking-wider">
                    Output Scanners
                  </span>
                  <span className="text-[10px] font-mono bg-zinc-800 text-stone-500 px-1.5 py-0.5 rounded">
                    {enabledOutputCount}/{ALL_OUTPUT_SCANNERS.length}
                  </span>
                </div>
                <div className="flex gap-1">
                  <button
                    onClick={() => toggleAllOutput(true)}
                    className="text-[10px] font-mono text-lime-500 hover:text-lime-400 px-2 py-0.5 rounded border border-lime-500/20 hover:border-lime-500/40"
                  >
                    All on
                  </button>
                  <button
                    onClick={() => toggleAllOutput(false)}
                    className="text-[10px] font-mono text-red-500 hover:text-red-400 px-2 py-0.5 rounded border border-red-500/20 hover:border-red-500/40"
                  >
                    All off
                  </button>
                </div>
              </div>

              {/* Search */}
              <div className="relative">
                <IconFilter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-stone-600" />
                <input
                  type="text"
                  placeholder="Filter scanners..."
                  value={outputFilter}
                  onChange={(e) => setOutputFilter(e.target.value)}
                  className="w-full bg-zinc-900 border border-zinc-800 rounded-lg pl-8 pr-3 py-2 text-xs text-stone-400 placeholder-stone-600 focus:outline-none focus:border-zinc-700"
                />
              </div>

              {/* Scanner cards */}
              <div className="flex flex-col gap-2 max-h-[600px] overflow-y-auto pr-1">
                {filteredOutputScanners.map((name) => (
                  <ScannerCard
                    key={`output-${name}`}
                    name={name}
                    entry={outputScanners[name]}
                    onToggle={() =>
                      updateOutputScanner(name, {
                        enabled: !outputScanners[name].enabled,
                      })
                    }
                    onThresholdChange={(v) =>
                      updateOutputScanner(name, { threshold: v })
                    }
                    onSettingsChange={(v) =>
                      updateOutputScanner(name, { settingsJson: v })
                    }
                    onToggleExpand={() =>
                      updateOutputScanner(name, {
                        expanded: !outputScanners[name].expanded,
                      })
                    }
                  />
                ))}
                {filteredOutputScanners.length === 0 && (
                  <p className="text-xs text-stone-600 text-center py-4">
                    No scanners match &quot;{outputFilter}&quot;
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Single column message when only one panel */}
          {!showInputScanners && !showOutputScanners && (
            <div className="col-span-2 text-center py-12 text-stone-500">
              <IconShieldBolt className="w-12 h-12 mx-auto mb-4 opacity-30" />
              <p>Select a scan mode to configure scanners</p>
            </div>
          )}
        </div>
      )}

      {/* ============================================ */}
      {/* Test Tab                                     */}
      {/* ============================================ */}
      {activeTab === "test" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* ── Input Panel ──────────────────────────────── */}
          <div className="flex flex-col gap-4">
            <div className="flex gap-4 items-center">
              <div className="flex gap-2 items-center">
                <IconSend className="w-4 h-4 text-stone-500" />
                <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
                  Test Input
                </span>
              </div>
              <span className="flex-1 h-px bg-stone-200/10"></span>
            </div>

            <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-4">
              {/* Prompt */}
              {(scanMode === "prompt_only" || scanMode === "both") && (
                <div className="space-y-1.5">
                  <Label className="text-xs font-mono uppercase text-stone-500">
                    Prompt to Scan
                  </Label>
                  <Textarea
                    placeholder="Enter a prompt to scan for threats..."
                    value={prompt}
                    onChange={(e) => setPrompt(e.target.value)}
                    rows={6}
                    className="font-mono text-sm"
                  />
                </div>
              )}

              {/* Output */}
              {(scanMode === "output_only" || scanMode === "both") && (
                <div className="space-y-1.5">
                  <Label className="text-xs font-mono uppercase text-stone-500">
                    LLM Output to Scan
                  </Label>
                  <Textarea
                    placeholder="Enter LLM output to validate..."
                    value={output}
                    onChange={(e) => setOutput(e.target.value)}
                    rows={6}
                    className="font-mono text-sm"
                  />
                </div>
              )}

              {/* Active scanner summary */}
              <div className="flex flex-wrap gap-1.5 pt-2 border-t border-zinc-800">
                {showInputScanners && (
                  <span className="text-[10px] font-mono text-stone-600">
                    Input:{" "}
                    {Object.entries(inputScanners)
                      .filter(([, v]) => v.enabled)
                      .map(([k]) => {
                        const meta = SCANNER_META[k];
                        return meta ? meta.label : k;
                      })
                      .join(", ") || "none"}
                  </span>
                )}
                {showOutputScanners && showInputScanners && (
                  <span className="text-[10px] text-zinc-700">|</span>
                )}
                {showOutputScanners && (
                  <span className="text-[10px] font-mono text-stone-600">
                    Output:{" "}
                    {Object.entries(outputScanners)
                      .filter(([, v]) => v.enabled)
                      .map(([k]) => {
                        const meta = SCANNER_META[k];
                        return meta ? meta.label : k;
                      })
                      .join(", ") || "none"}
                  </span>
                )}
              </div>

              <Button
                onClick={handleScan}
                disabled={isScanning || !apiKey}
                className="w-full"
              >
                {isScanning ? (
                  <>
                    <IconLoader2 className="w-4 h-4 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <IconSend className="w-4 h-4 mr-2" />
                    Run Advanced Scan
                  </>
                )}
              </Button>
            </div>
          </div>

          {/* ── Results Panel ────────────────────────────── */}
          <div className="flex flex-col gap-4">
            <div className="flex gap-4 items-center">
              <div className="flex gap-2 items-center">
                <IconShieldBolt className="w-4 h-4 text-stone-500" />
                <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
                  Scan Results
                </span>
              </div>
              <span className="flex-1 h-px bg-stone-200/10"></span>
            </div>

            <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 min-h-[400px]">
              {/* Error */}
              {scanError && (
                <div className="p-4 bg-red-900/20 border border-red-700 rounded-lg text-red-400 mb-4">
                  <IconAlertTriangle className="w-5 h-5 inline mr-2" />
                  {scanError}
                </div>
              )}

              {/* Empty state */}
              {!scanResult && !scanError && (
                <div className="h-full flex items-center justify-center text-stone-500 min-h-[350px]">
                  <div className="text-center">
                    <IconShieldBolt className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>Configure scanners and click &quot;Run Scan&quot;</p>
                    <p className="text-xs mt-1">
                      Per-scanner results will appear here
                    </p>
                  </div>
                </div>
              )}

              {/* Results */}
              {scanResult && (
                <div className="space-y-5">
                  {/* Overall Status */}
                  <div className="flex items-center gap-3">
                    <div
                      className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg ${
                        scanResult.safe
                          ? "bg-lime-500/10 text-lime-400 border border-lime-500/30"
                          : "bg-red-500/10 text-red-400 border border-red-500/30"
                      }`}
                    >
                      {scanResult.safe ? (
                        <IconCheck className="w-5 h-5" />
                      ) : (
                        <IconX className="w-5 h-5" />
                      )}
                      <span className="font-semibold uppercase text-sm">
                        {scanResult.safe ? "Safe" : "Threats Detected"}
                      </span>
                    </div>

                    <span className="text-xs font-mono text-stone-500 uppercase px-2 py-1 bg-zinc-800 rounded">
                      {scanResult.scanMode.replace("_", " ")}
                    </span>
                  </div>

                  {/* Stats */}
                  <div className="grid grid-cols-4 gap-3">
                    <div className="p-3 bg-zinc-800 rounded-lg">
                      <p className="text-[10px] text-stone-500 uppercase font-mono">
                        Risk
                      </p>
                      <p
                        className={`text-lg font-bold ${
                          scanResult.riskScore >= 0.7
                            ? "text-red-500"
                            : scanResult.riskScore >= 0.4
                              ? "text-orange-500"
                              : "text-lime-500"
                        }`}
                      >
                        {(scanResult.riskScore * 100).toFixed(0)}%
                      </p>
                    </div>
                    <div className="p-3 bg-zinc-800 rounded-lg">
                      <p className="text-[10px] text-stone-500 uppercase font-mono">
                        Latency
                      </p>
                      <p className="text-lg font-bold">
                        {scanResult.latencyMs}ms
                      </p>
                    </div>
                    <div className="p-3 bg-zinc-800 rounded-lg">
                      <p className="text-[10px] text-stone-500 uppercase font-mono">
                        Input Scans
                      </p>
                      <p className="text-lg font-bold">
                        {scanResult.inputScannersRun}
                      </p>
                    </div>
                    <div className="p-3 bg-zinc-800 rounded-lg">
                      <p className="text-[10px] text-stone-500 uppercase font-mono">
                        Output Scans
                      </p>
                      <p className="text-lg font-bold">
                        {scanResult.outputScannersRun}
                      </p>
                    </div>
                  </div>

                  {/* Threat categories */}
                  {scanResult.threatCategories &&
                    scanResult.threatCategories.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        <span className="text-xs text-stone-500 font-mono uppercase mr-1">
                          Threats:
                        </span>
                        {scanResult.threatCategories.map((cat) => (
                          <span
                            key={cat}
                            className="text-[10px] px-2 py-0.5 rounded bg-red-500/10 text-red-400 font-mono border border-red-500/20"
                          >
                            {SCANNER_META[cat]?.label || cat}
                          </span>
                        ))}
                      </div>
                    )}

                  {/* Input scanner results */}
                  {scanResult.inputResults.length > 0 && (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <IconArrowRight className="w-3.5 h-3.5 text-stone-500" />
                        <p className="text-xs font-mono uppercase text-stone-500 font-semibold">
                          Input Scanner Results (
                          {scanResult.inputResults.length})
                        </p>
                      </div>
                      <div className="flex flex-col gap-1.5">
                        {scanResult.inputResults.map((r, i) => (
                          <ScannerResultCard
                            key={`input-result-${i}`}
                            result={r}
                          />
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Output scanner results */}
                  {scanResult.outputResults.length > 0 && (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <IconArrowLeft className="w-3.5 h-3.5 text-stone-500" />
                        <p className="text-xs font-mono uppercase text-stone-500 font-semibold">
                          Output Scanner Results (
                          {scanResult.outputResults.length})
                        </p>
                      </div>
                      <div className="flex flex-col gap-1.5">
                        {scanResult.outputResults.map((r, i) => (
                          <ScannerResultCard
                            key={`output-result-${i}`}
                            result={r}
                          />
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Sanitized outputs */}
                  {scanResult.sanitizedPrompt && (
                    <div className="space-y-1.5">
                      <p className="text-xs font-mono uppercase text-stone-500 font-semibold">
                        Sanitized Prompt
                      </p>
                      <pre className="p-3 bg-zinc-800 rounded-lg text-xs font-mono whitespace-pre-wrap text-lime-300/80 max-h-48 overflow-y-auto">
                        {scanResult.sanitizedPrompt}
                      </pre>
                    </div>
                  )}

                  {scanResult.sanitizedOutput && (
                    <div className="space-y-1.5">
                      <p className="text-xs font-mono uppercase text-stone-500 font-semibold">
                        Sanitized Output
                      </p>
                      <pre className="p-3 bg-zinc-800 rounded-lg text-xs font-mono whitespace-pre-wrap text-cyan-300/80 max-h-48 overflow-y-auto">
                        {scanResult.sanitizedOutput}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
