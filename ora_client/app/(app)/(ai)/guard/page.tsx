"use client";

import { useState, useEffect } from "react";
import { IconShieldBolt, IconSend, IconLoader2, IconCheck, IconAlertTriangle, IconX } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { scanPrompt, type ScanPromptResult } from "@/lib/actions/guard";
import { listApiKeys } from "@/lib/actions/api-keys";

export default function GuardPage() {
  const [prompt, setPrompt] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [apiKeys, setApiKeys] = useState<Array<{ id: string; name: string; keyPrefix: string }>>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanPromptResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [options, setOptions] = useState({
    checkInjection: true,
    checkToxicity: true,
    checkPii: true,
    sanitize: false,
  });

  useEffect(() => {
    loadApiKeys();
  }, []);

  const loadApiKeys = async () => {
    const keys = await listApiKeys();
    setApiKeys(keys.map(k => ({
      id: k.id,
      name: k.name,
      keyPrefix: k.keyPrefix,
    })));
  };

  const handleScan = async () => {
    if (!prompt.trim() || !apiKey) return;
    
    setIsScanning(true);
    setError(null);
    setResult(null);

    try {
      const scanResult = await scanPrompt({
        prompt,
        apiKey,
        options,
      });

      if ("error" in scanResult) {
        setError(scanResult.error);
      } else {
        setResult(scanResult);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to scan prompt");
    } finally {
      setIsScanning(false);
    }
  };

  const getSeverityColor = (severity: string) => {
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
  };

  return (
    <section className="px-4 py-6 w-full flex flex-col gap-10">
      <div>
        <h1 className="text-xl font-bold">LLM Guard</h1>
        <p className="text-sm text-neutral-400">
          Test prompt scanning for injection attacks, toxicity, and PII detection
        </p>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Input Panel */}
        <div className="flex flex-col gap-6">
          <div className="flex gap-4 items-center">
            <div className="flex gap-2 items-center">
              <IconShieldBolt className="w-4 h-4 text-stone-500" />
              <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
                Test Prompt
              </span>
            </div>
            <span className="flex-1 h-px bg-stone-200"></span>
          </div>

          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 space-y-4">
            <div className="space-y-2">
              <Label>API Key</Label>
              <Input
                type="password"
                placeholder="ora_..."
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
              />
              <p className="text-xs text-stone-500">
                {apiKeys.length === 0 ? (
                  <>No API keys found. <a href="/credentials" className="text-blue-500 hover:underline">Create one</a> first.</>
                ) : (
                  <>Your keys: {apiKeys.map(k => k.name).join(", ")}. Enter the full key above.</>
                )}
              </p>
            </div>

            <div className="space-y-2">
              <Label>Prompt to Test</Label>
              <Textarea
                placeholder="Enter a prompt to scan for threats..."
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                rows={8}
                className="font-mono text-sm"
              />
            </div>

            <div className="space-y-2">
              <Label>Scan Options</Label>
              <div className="flex flex-wrap gap-2">
                {[
                  { key: "checkInjection", label: "Injection" },
                  { key: "checkToxicity", label: "Toxicity" },
                  { key: "checkPii", label: "PII" },
                  { key: "sanitize", label: "Sanitize" },
                ].map((opt) => (
                  <button
                    key={opt.key}
                    onClick={() =>
                      setOptions({ ...options, [opt.key]: !options[opt.key as keyof typeof options] })
                    }
                    className={`px-3 py-1 text-xs font-mono uppercase rounded-lg border transition-colors ${
                      options[opt.key as keyof typeof options]
                        ? "bg-brand-500/20 border-brand-500 text-brand-400"
                        : "border-zinc-700 text-stone-500"
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            <Button
              onClick={handleScan}
              disabled={isScanning || !prompt.trim() || !apiKey}
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
                  Scan Prompt
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Results Panel */}
        <div className="flex flex-col gap-6">
          <div className="flex gap-4 items-center">
            <div className="flex gap-2 items-center">
              <IconShieldBolt className="w-4 h-4 text-stone-500" />
              <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
                Scan Results
              </span>
            </div>
            <span className="flex-1 h-px bg-stone-200"></span>
          </div>

          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 min-h-[400px]">
            {error && (
              <div className="p-4 bg-red-900/20 border border-red-700 rounded-lg text-red-400">
                <IconAlertTriangle className="w-5 h-5 inline mr-2" />
                {error}
              </div>
            )}

            {!result && !error && (
              <div className="h-full flex items-center justify-center text-stone-500">
                <div className="text-center">
                  <IconShieldBolt className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>Enter a prompt and click scan</p>
                  <p className="text-xs mt-1">Results will appear here</p>
                </div>
              </div>
            )}

            {result && (
              <div className="space-y-4">
                {/* Status Badge */}
                <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg ${
                  result.safe
                    ? "bg-lime-500/10 text-lime-400 border border-lime-500/30"
                    : "bg-red-500/10 text-red-400 border border-red-500/30"
                }`}>
                  {result.safe ? (
                    <IconCheck className="w-5 h-5" />
                  ) : (
                    <IconX className="w-5 h-5" />
                  )}
                  <span className="font-semibold uppercase text-sm">
                    {result.safe ? "Safe" : "Threats Detected"}
                  </span>
                </div>

                {/* Stats */}
                <div className="grid grid-cols-3 gap-4">
                  <div className="p-3 bg-zinc-800 rounded-lg">
                    <p className="text-xs text-stone-500 uppercase font-mono">Risk Score</p>
                    <p className={`text-xl font-bold ${
                      result.riskScore >= 0.7 ? "text-red-500" :
                      result.riskScore >= 0.4 ? "text-orange-500" : "text-lime-500"
                    }`}>
                      {(result.riskScore * 100).toFixed(0)}%
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-800 rounded-lg">
                    <p className="text-xs text-stone-500 uppercase font-mono">Latency</p>
                    <p className="text-xl font-bold">{result.latencyMs}ms</p>
                  </div>
                  <div className="p-3 bg-zinc-800 rounded-lg">
                    <p className="text-xs text-stone-500 uppercase font-mono">Cached</p>
                    <p className="text-xl font-bold">{result.cached ? "Yes" : "No"}</p>
                  </div>
                </div>

                {/* Threats */}
                {result.threats.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-sm font-semibold">Detected Threats</p>
                    <div className="space-y-2">
                      {result.threats.map((threat, i) => (
                        <div
                          key={i}
                          className={`p-3 rounded-lg border ${getSeverityColor(threat.severity)}`}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-semibold text-sm">{threat.threatType}</span>
                            <span className="text-xs uppercase">{threat.severity}</span>
                          </div>
                          <p className="text-sm opacity-80">{threat.description}</p>
                          <p className="text-xs mt-1 opacity-60">
                            Confidence: {(threat.confidence * 100).toFixed(0)}%
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Sanitized Output */}
                {result.sanitizedPrompt && (
                  <div className="space-y-2">
                    <p className="text-sm font-semibold">Sanitized Prompt</p>
                    <pre className="p-3 bg-zinc-800 rounded-lg text-sm font-mono whitespace-pre-wrap">
                      {result.sanitizedPrompt}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
