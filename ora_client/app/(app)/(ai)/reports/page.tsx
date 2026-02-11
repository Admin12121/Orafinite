"use client";

import { useState, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import {
  IconFileAnalytics,
  IconShieldCheck,
  IconChevronDown,
} from "@tabler/icons-react";
import {
  listScans,
  getScanResults,
  type ScanResult,
} from "@/lib/actions/scans";

interface ScanDisplay {
  id: string;
  scanType: string;
  status: string;
  vulnerabilitiesFound: number | null;
  riskScore: number | null;
  createdAt: string;
  completedAt: string | null;
}

export default function ReportsPage() {
  const searchParams = useSearchParams();
  const [scans, setScans] = useState<ScanDisplay[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null);

  useEffect(() => {
    loadScans();
    const scanId = searchParams.get("scan");
    if (scanId) {
      setSelectedScanId(scanId);
      loadResults(scanId);
    }
  }, [searchParams]);

  const loadScans = async () => {
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
  };

  const loadResults = async (scanId: string) => {
    try {
      const data = await getScanResults(scanId);
      setResults(data);
    } catch (err) {
      console.error("Failed to load scan results:", err);
    }
  };

  const handleSelectScan = (scanId: string) => {
    setSelectedScanId(scanId);
    loadResults(scanId);
  };

  const getSeverityColor = (severity: string) => {
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
  };

  const selectedScan = scans.find((s) => s.id === selectedScanId);

  return (
    <section className="px-4 py-6 w-full flex flex-col gap-10">
      <div>
        <h1 className="text-xl font-bold">Scan Reports</h1>
        <p className="text-sm text-neutral-400">
          View detailed vulnerability reports from completed scans
        </p>
      </div>

      <div className="grid grid-cols-3 gap-6">
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
              <div className="p-6 border-b border-zinc-800">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold capitalize">
                    {selectedScan.scanType} Scan Report
                  </h2>
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
                <div className="grid grid-cols-4 gap-4">
                  <div className="p-3 bg-zinc-800 rounded-lg text-center">
                    <p className="text-2xl font-bold">
                      {selectedScan.vulnerabilitiesFound || 0}
                    </p>
                    <p className="text-xs text-stone-500 uppercase font-mono">
                      Vulnerabilities
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-800 rounded-lg text-center">
                    <p className="text-2xl font-bold text-red-500">
                      {results.filter((r) => r.severity === "critical").length}
                    </p>
                    <p className="text-xs text-stone-500 uppercase font-mono">
                      Critical
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-800 rounded-lg text-center">
                    <p className="text-2xl font-bold text-orange-500">
                      {results.filter((r) => r.severity === "high").length}
                    </p>
                    <p className="text-xs text-stone-500 uppercase font-mono">
                      High
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-800 rounded-lg text-center">
                    <p className="text-2xl font-bold text-yellow-500">
                      {results.filter((r) => r.severity === "medium").length}
                    </p>
                    <p className="text-xs text-stone-500 uppercase font-mono">
                      Medium
                    </p>
                  </div>
                </div>
              </div>

              <div className="max-h-[500px] overflow-auto">
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
                      <div key={vuln.id} className="p-4">
                        <button
                          onClick={() =>
                            setExpandedVuln(
                              expandedVuln === vuln.id ? null : vuln.id,
                            )
                          }
                          className="w-full flex items-center justify-between"
                        >
                          <div className="flex items-center gap-3">
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
                          </div>
                          <IconChevronDown
                            className={`w-4 h-4 transition-transform ${
                              expandedVuln === vuln.id ? "rotate-180" : ""
                            }`}
                          />
                        </button>

                        {expandedVuln === vuln.id && (
                          <div className="mt-4 space-y-3 pl-4 border-l-2 border-zinc-700">
                            <div>
                              <p className="text-xs text-stone-500 uppercase font-mono mb-1">
                                Description
                              </p>
                              <p className="text-sm">{vuln.description}</p>
                            </div>
                            {vuln.attackPrompt && (
                              <div>
                                <p className="text-xs text-stone-500 uppercase font-mono mb-1">
                                  Attack Prompt
                                </p>
                                <pre className="text-sm bg-zinc-800 p-3 rounded overflow-x-auto">
                                  {vuln.attackPrompt}
                                </pre>
                              </div>
                            )}
                            {vuln.modelResponse && (
                              <div>
                                <p className="text-xs text-stone-500 uppercase font-mono mb-1">
                                  Model Response
                                </p>
                                <pre className="text-sm bg-zinc-800 p-3 rounded overflow-x-auto">
                                  {vuln.modelResponse}
                                </pre>
                              </div>
                            )}
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
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
