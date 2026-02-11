"use client";

import { useState, useEffect } from "react";
import {
  IconRadar,
  IconPlayerPlay,
  IconLoader2,
  IconCheck,
  IconX,
  IconAlertTriangle,
  IconInfoCircle,
  IconRefresh,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  startScan,
  listScans,
  getScanStatus,
  type Scan,
} from "@/lib/actions/scans";
import { listModelConfigs, type ModelConfig } from "@/lib/actions/models";
import Link from "next/link";

interface ScanDisplay {
  id: string;
  scanType: string;
  status: string;
  progress: number;
  vulnerabilitiesFound: number;
  riskScore: number | null;
  createdAt: string;
}

const SCAN_TYPES = [
  {
    value: "quick",
    label: "Quick Scan",
    desc: "Basic injection probes",
    duration: "~1 min",
  },
  {
    value: "standard",
    label: "Standard Scan",
    desc: "Common vulnerabilities",
    duration: "~5 min",
  },
  {
    value: "comprehensive",
    label: "Comprehensive",
    desc: "Full probe suite",
    duration: "~15 min",
  },
];

// Same provider list as Models page for consistency
const PROVIDERS = [
  { value: "openai", label: "OpenAI", placeholder: "gpt-4o, gpt-4-turbo" },
  {
    value: "anthropic",
    label: "Anthropic",
    placeholder: "claude-3-opus-20240229",
  },
  {
    value: "huggingface",
    label: "Hugging Face",
    placeholder: "meta-llama/Llama-2-70b-chat-hf",
  },
  { value: "ollama", label: "Ollama (Local)", placeholder: "llama2, mistral" },
  { value: "groq", label: "Groq", placeholder: "llama-3.1-70b-versatile" },
  {
    value: "together",
    label: "Together AI",
    placeholder: "meta-llama/Llama-3-70b-chat-hf",
  },
  {
    value: "openrouter",
    label: "OpenRouter",
    placeholder: "anthropic/claude-3-opus",
  },
  { value: "custom", label: "Custom", placeholder: "your-model-name" },
];

export default function ScannerPage() {
  const [scans, setScans] = useState<ScanDisplay[]>([]);
  const [models, setModels] = useState<ModelConfig[]>([]);
  const [isStarting, setIsStarting] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // "saved" = use saved model config, "manual" = enter details manually
  const [inputMode, setInputMode] = useState<"saved" | "manual">("saved");

  const [form, setForm] = useState({
    modelId: "",
    scanType: "standard",
    // Manual entry fields
    provider: "openai",
    model: "",
    apiKey: "",
    baseUrl: "",
  });

  const selectedProvider = PROVIDERS.find((p) => p.value === form.provider);

  useEffect(() => {
    loadData();
  }, []);

  // Poll running scans for status updates
  useEffect(() => {
    const runningScans = scans.filter(
      (s) => s.status === "running" || s.status === "pending",
    );
    if (runningScans.length === 0) return;

    const interval = setInterval(async () => {
      for (const scan of runningScans) {
        const result = await getScanStatus(scan.id);
        if (!("error" in result)) {
          setScans((prev) =>
            prev.map((s) =>
              s.id === scan.id
                ? {
                    ...s,
                    status: result.status,
                    progress: result.progress,
                    vulnerabilitiesFound: result.vulnerabilitiesFound,
                  }
                : s,
            ),
          );
        }
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [scans]);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [scanResults, modelResults] = await Promise.all([
        listScans(),
        listModelConfigs(),
      ]);
      setScans(
        scanResults.map((s) => ({
          id: s.id,
          scanType: s.scanType,
          status: s.status,
          progress: s.progress,
          vulnerabilitiesFound: s.vulnerabilitiesFound,
          riskScore: s.riskScore,
          createdAt: s.createdAt,
        })),
      );
      setModels(modelResults);

      // Auto-select first model if available
      if (modelResults.length > 0) {
        setForm((f) => ({ ...f, modelId: modelResults[0].id }));
        setInputMode("saved");
      } else {
        setInputMode("manual");
      }
    } catch (err) {
      console.error("Failed to load data:", err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleStartScan = async () => {
    setIsStarting(true);
    setError(null);

    try {
      let scanConfig: Parameters<typeof startScan>[0];

      if (inputMode === "saved" && form.modelId) {
        const selectedModel = models.find((m) => m.id === form.modelId);
        if (!selectedModel) {
          setError("Please select a model");
          setIsStarting(false);
          return;
        }
        scanConfig = {
          modelConfigId: form.modelId,
          scanType: form.scanType as "quick" | "standard" | "comprehensive",
          provider: selectedModel.provider,
          model: selectedModel.model,
        };
      } else {
        if (!form.model.trim()) {
          setError("Please enter a model identifier");
          setIsStarting(false);
          return;
        }
        scanConfig = {
          scanType: form.scanType as "quick" | "standard" | "comprehensive",
          provider: form.provider,
          model: form.model,
          apiKey: form.apiKey || undefined,
          baseUrl: form.baseUrl || undefined,
        };
      }

      const result = await startScan(scanConfig);

      if ("error" in result) {
        setError(result.error);
      } else {
        // Add new scan to list
        setScans((prev) => [
          {
            id: result.scanId,
            scanType: form.scanType,
            status: result.status,
            progress: 0,
            vulnerabilitiesFound: 0,
            riskScore: null,
            createdAt: new Date().toISOString(),
          },
          ...prev,
        ]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
    } finally {
      setIsStarting(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <IconCheck className="w-4 h-4 text-lime-500" />;
      case "failed":
        return <IconX className="w-4 h-4 text-red-500" />;
      case "running":
        return <IconLoader2 className="w-4 h-4 text-blue-500 animate-spin" />;
      case "pending":
        return (
          <IconLoader2 className="w-4 h-4 text-yellow-500 animate-pulse" />
        );
      default:
        return <IconRadar className="w-4 h-4 text-stone-500" />;
    }
  };

  const getRiskColor = (score: number | null) => {
    if (score === null) return "text-stone-500";
    if (score >= 0.7) return "text-red-500";
    if (score >= 0.4) return "text-orange-500";
    return "text-lime-500";
  };

  const getStatusBadge = (status: string) => {
    const colors: Record<string, string> = {
      completed: "bg-lime-500/20 text-lime-400",
      failed: "bg-red-500/20 text-red-400",
      running: "bg-blue-500/20 text-blue-400",
      pending: "bg-yellow-500/20 text-yellow-400",
    };
    return colors[status] || "bg-stone-500/20 text-stone-400";
  };

  return (
    <section className="px-4 py-6 w-full flex flex-col gap-10">
      <div>
        <h1 className="text-xl font-bold">Garak Scanner</h1>
        <p className="text-sm text-neutral-400">
          Run vulnerability scans against your LLM models using Garak probes
        </p>
      </div>

      <div className="flex flex-col gap-6">
        {/* Start New Scan */}
        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconRadar className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              New Scan
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200"></span>
        </div>

        <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
          {/* Model Source Toggle */}
          <div className="flex gap-2 mb-6">
            <Button
              variant={inputMode === "saved" ? "default" : "outline"}
              size="sm"
              onClick={() => setInputMode("saved")}
              disabled={models.length === 0}
            >
              Use Saved Model
              {models.length > 0 && (
                <span className="ml-2 text-xs bg-white/20 px-1.5 rounded">
                  {models.length}
                </span>
              )}
            </Button>
            <Button
              variant={inputMode === "manual" ? "default" : "outline"}
              size="sm"
              onClick={() => setInputMode("manual")}
            >
              Enter Manually
            </Button>
            {models.length === 0 && (
              <Link href="/models" className="ml-auto">
                <Button variant="link" size="sm" className="text-stone-400">
                  + Add Model Config
                </Button>
              </Link>
            )}
          </div>

          {/* Model Configuration */}
          {inputMode === "saved" ? (
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Select Model Configuration</Label>
                <Select
                  value={form.modelId}
                  onValueChange={(v) => setForm({ ...form, modelId: v })}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Choose a saved model" />
                  </SelectTrigger>
                  <SelectContent>
                    {models.map((m) => (
                      <SelectItem key={m.id} value={m.id}>
                        <div className="flex items-center gap-2">
                          <span>{m.name}</span>
                          <span className="text-xs text-stone-500">
                            ({m.provider}/{m.model})
                          </span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-stone-500">
                  Uses API key stored in model configuration
                </p>
              </div>
              <div className="space-y-2">
                <Label>Scan Type</Label>
                <Select
                  value={form.scanType}
                  onValueChange={(v) => setForm({ ...form, scanType: v })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SCAN_TYPES.map((t) => (
                      <SelectItem key={t.value} value={t.value}>
                        <div className="flex items-center justify-between w-full">
                          <span>{t.label}</span>
                          <span className="text-xs text-stone-500 ml-2">
                            {t.duration}
                          </span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-stone-500">
                  {SCAN_TYPES.find((t) => t.value === form.scanType)?.desc}
                </p>
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Provider</Label>
                  <Select
                    value={form.provider}
                    onValueChange={(v) =>
                      setForm({ ...form, provider: v, model: "" })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {PROVIDERS.map((p) => (
                        <SelectItem key={p.value} value={p.value}>
                          {p.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Label>Model Identifier</Label>
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger>
                          <IconInfoCircle className="w-4 h-4 text-stone-500" />
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>Enter the exact model name from the provider</p>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </div>
                  <Input
                    value={form.model}
                    onChange={(e) =>
                      setForm({ ...form, model: e.target.value })
                    }
                    placeholder={
                      selectedProvider?.placeholder || "Enter model name"
                    }
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>
                    API Key {form.provider === "ollama" && "(optional)"}
                  </Label>
                  <Input
                    type="password"
                    value={form.apiKey}
                    onChange={(e) =>
                      setForm({ ...form, apiKey: e.target.value })
                    }
                    placeholder={
                      form.provider === "ollama"
                        ? "Not required for local"
                        : "Required"
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label>Scan Type</Label>
                  <Select
                    value={form.scanType}
                    onValueChange={(v) => setForm({ ...form, scanType: v })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {SCAN_TYPES.map((t) => (
                        <SelectItem key={t.value} value={t.value}>
                          <div className="flex items-center justify-between w-full">
                            <span>{t.label}</span>
                            <span className="text-xs text-stone-500 ml-2">
                              {t.duration}
                            </span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-stone-500">
                    {SCAN_TYPES.find((t) => t.value === form.scanType)?.desc}
                  </p>
                </div>
              </div>
              {(form.provider === "ollama" || form.provider === "custom") && (
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Base URL</Label>
                    <Input
                      value={form.baseUrl}
                      onChange={(e) =>
                        setForm({ ...form, baseUrl: e.target.value })
                      }
                      placeholder={
                        form.provider === "ollama"
                          ? "http://localhost:11434"
                          : "https://api.example.com"
                      }
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {error && (
            <div className="mt-4 p-3 bg-red-900/20 border border-red-700 rounded-lg text-red-400 text-sm flex items-center gap-2">
              <IconAlertTriangle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          <div className="mt-6 flex gap-4">
            <Button
              onClick={handleStartScan}
              disabled={
                isStarting ||
                (inputMode === "saved" && !form.modelId) ||
                (inputMode === "manual" && !form.model)
              }
            >
              {isStarting ? (
                <>
                  <IconLoader2 className="w-4 h-4 mr-2 animate-spin" />
                  Starting Scan...
                </>
              ) : (
                <>
                  <IconPlayerPlay className="w-4 h-4 mr-2" />
                  Start Vulnerability Scan
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Scan History */}
        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconRadar className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              Scan History
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200"></span>
          <Button variant="ghost" size="sm" onClick={loadData} className="h-6">
            <IconRefresh className="w-3 h-3 mr-1" />
            Refresh
          </Button>
        </div>

        <div className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden">
          {isLoading ? (
            <div className="p-8 text-center text-stone-500">
              <IconLoader2 className="w-8 h-8 mx-auto mb-4 animate-spin" />
              <p>Loading scan history...</p>
            </div>
          ) : scans.length === 0 ? (
            <div className="p-8 text-center text-stone-500">
              <IconRadar className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No scans yet</p>
              <p className="text-xs mt-1">
                Start a scan to test your LLM for vulnerabilities
              </p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="border-b border-zinc-800">
                <tr className="text-left text-xs font-mono uppercase text-stone-500">
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Progress</th>
                  <th className="px-4 py-3">Vulnerabilities</th>
                  <th className="px-4 py-3">Risk Score</th>
                  <th className="px-4 py-3">Started</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-zinc-800 last:border-0 hover:bg-zinc-800/50"
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(scan.status)}
                        <span
                          className={`text-xs px-2 py-0.5 rounded capitalize ${getStatusBadge(scan.status)}`}
                        >
                          {scan.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 capitalize">{scan.scanType}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-24 h-2 bg-zinc-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-blue-500 transition-all duration-300"
                            style={{ width: `${scan.progress}%` }}
                          />
                        </div>
                        <span className="text-xs text-stone-500">
                          {scan.progress}%
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {scan.vulnerabilitiesFound > 0 ? (
                        <span className="text-orange-400 font-semibold">
                          {scan.vulnerabilitiesFound}
                        </span>
                      ) : (
                        <span className="text-stone-500">0</span>
                      )}
                    </td>
                    <td
                      className={`px-4 py-3 font-semibold ${getRiskColor(scan.riskScore)}`}
                    >
                      {scan.riskScore !== null
                        ? `${(scan.riskScore * 100).toFixed(0)}%`
                        : "-"}
                    </td>
                    <td className="px-4 py-3 text-stone-500 text-sm">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      {scan.status === "completed" && (
                        <Link href={`/reports?scan=${scan.id}`}>
                          <Button variant="ghost" size="sm">
                            View Report
                          </Button>
                        </Link>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Info Section */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <IconInfoCircle className="w-4 h-4" />
            About Garak Vulnerability Scanner
          </h3>
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div className="p-3 bg-zinc-800 rounded-lg">
              <p className="font-medium text-stone-200">Prompt Injection</p>
              <p className="text-xs text-stone-500 mt-1">
                Tests for attempts to override system instructions
              </p>
            </div>
            <div className="p-3 bg-zinc-800 rounded-lg">
              <p className="font-medium text-stone-200">Jailbreaking</p>
              <p className="text-xs text-stone-500 mt-1">
                Detects attempts to bypass safety guardrails
              </p>
            </div>
            <div className="p-3 bg-zinc-800 rounded-lg">
              <p className="font-medium text-stone-200">Data Leakage</p>
              <p className="text-xs text-stone-500 mt-1">
                Checks for training data extraction vulnerabilities
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
