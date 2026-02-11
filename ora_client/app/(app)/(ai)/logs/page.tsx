"use client";

import { useState, useEffect } from "react";
import {
  IconListSearch,
  IconShieldCheck,
  IconAlertTriangle,
  IconRefresh,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import {
  listGuardLogs,
  getGuardStats,
  type GuardLog,
} from "@/lib/actions/guard";

export default function LogsPage() {
  const [logs, setLogs] = useState<GuardLog[]>([]);
  const [stats, setStats] = useState({
    totalScans: 0,
    threatsBlocked: 0,
    safePrompts: 0,
    avgLatency: 0,
  });
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [logsData, statsData] = await Promise.all([
        listGuardLogs(100),
        getGuardStats(),
      ]);
      setLogs(logsData);
      setStats(statsData);
    } catch (err) {
      console.error("Failed to load logs:", err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <section className="px-4 py-6 w-full flex flex-col gap-10">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Activity Logs</h1>
          <p className="text-sm text-neutral-400">
            Monitor LLM Guard API activity and threat detection logs
          </p>
        </div>
        <Button
          variant="secondary"
          size="sm"
          onClick={loadData}
          disabled={isLoading}
        >
          <IconRefresh
            className={`w-4 h-4 mr-2 ${isLoading ? "animate-spin" : ""}`}
          />
          Refresh
        </Button>
      </div>

      <div className="flex flex-col gap-6">
        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconListSearch className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              Overview
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200"></span>
        </div>

        <div className="grid grid-cols-4 gap-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
            <p className="text-xs text-stone-500 uppercase font-mono mb-2">
              Total Scans
            </p>
            <p className="text-3xl font-bold">{stats.totalScans}</p>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
            <p className="text-xs text-stone-500 uppercase font-mono mb-2">
              Threats Blocked
            </p>
            <p className="text-3xl font-bold text-red-500">
              {stats.threatsBlocked}
            </p>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
            <p className="text-xs text-stone-500 uppercase font-mono mb-2">
              Safe Prompts
            </p>
            <p className="text-3xl font-bold text-lime-500">
              {stats.safePrompts}
            </p>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
            <p className="text-xs text-stone-500 uppercase font-mono mb-2">
              Avg Latency
            </p>
            <p className="text-3xl font-bold">{stats.avgLatency}ms</p>
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-6">
        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconListSearch className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              Recent Activity
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200"></span>
        </div>

        <div className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden">
          {logs.length === 0 ? (
            <div className="p-8 text-center text-stone-500">
              <IconListSearch className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No activity logs yet</p>
              <p className="text-xs mt-1">
                Logs will appear when the Guard API is used
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="border-b border-zinc-800 bg-zinc-800/50">
                  <tr className="text-left text-xs font-mono uppercase text-stone-500">
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Risk Score</th>
                    <th className="px-4 py-3">Threats</th>
                    <th className="px-4 py-3">Latency</th>
                    <th className="px-4 py-3">Cached</th>
                    <th className="px-4 py-3">IP Address</th>
                    <th className="px-4 py-3">Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {logs.map((log) => {
                    const threats = (log.threatsDetected as unknown[]) || [];
                    return (
                      <tr key={log.id} className="hover:bg-zinc-800/50">
                        <td className="px-4 py-3">
                          {log.isSafe ? (
                            <span className="inline-flex items-center gap-1 text-lime-500">
                              <IconShieldCheck className="w-4 h-4" />
                              Safe
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-red-500">
                              <IconAlertTriangle className="w-4 h-4" />
                              Threat
                            </span>
                          )}
                        </td>
                        <td
                          className={`px-4 py-3 font-semibold ${
                            (log.riskScore || 0) >= 0.7
                              ? "text-red-500"
                              : (log.riskScore || 0) >= 0.4
                                ? "text-orange-500"
                                : "text-lime-500"
                          }`}
                        >
                          {log.riskScore !== null
                            ? (log.riskScore * 100).toFixed(0) + "%"
                            : "-"}
                        </td>
                        <td className="px-4 py-3">
                          {threats.length > 0 ? (
                            <span className="text-red-400">
                              {threats.length} detected
                            </span>
                          ) : (
                            <span className="text-stone-500">None</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-stone-400">
                          {log.latencyMs}ms
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`text-xs px-2 py-0.5 rounded ${
                              log.cached
                                ? "bg-blue-500/20 text-blue-400"
                                : "bg-stone-700 text-stone-400"
                            }`}
                          >
                            {log.cached ? "Yes" : "No"}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-stone-500 font-mono text-sm">
                          {log.ipAddress || "-"}
                        </td>
                        <td className="px-4 py-3 text-stone-500 text-sm">
                          {new Date(log.createdAt).toLocaleString()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
