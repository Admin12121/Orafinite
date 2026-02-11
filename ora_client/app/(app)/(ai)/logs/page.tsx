"use client";

import { useState, useEffect, useCallback } from "react";
import {
  IconListSearch,
  IconShieldCheck,
  IconAlertTriangle,
  IconRefresh,
  IconChevronDown,
  IconChevronRight,
  IconChevronLeft,
  IconFilter,
  IconX,
  IconCircleFilled,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import {
  listGuardLogs,
  getGuardStats,
  type GuardLog,
  type PaginationInfo,
  type GuardStats,
} from "@/lib/actions/guard";
import { useGuardEvents } from "@/hooks/use-guard-events";

// ============================================
// Types
// ============================================

type StatusFilter = "all" | "safe" | "threat";
type RequestTypeFilter = "all" | "scan" | "validate" | "batch";

// ============================================
// Expandable Threat Detail Row
// ============================================

function ThreatDetailRow({ log }: { log: GuardLog }) {
  const threats =
    (log.threatsDetected as Array<{
      threat_type?: string;
      confidence?: number;
      description?: string;
      severity?: string;
    }>) || [];

  return (
    <tr className="bg-zinc-950 border-b border-zinc-800">
      <td colSpan={9} className="px-6 py-4">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Threat Details */}
          <div className="flex flex-col gap-3">
            <h4 className="text-xs font-mono uppercase text-stone-500 font-semibold">
              Threat Details
            </h4>
            {threats.length > 0 ? (
              <div className="flex flex-col gap-2">
                {threats.map((threat, i) => (
                  <div
                    key={i}
                    className="bg-zinc-900 border border-zinc-800 rounded-lg p-3 flex flex-col gap-1"
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-xs font-mono px-2 py-0.5 rounded ${
                          threat.severity === "critical"
                            ? "bg-red-500/20 text-red-400"
                            : threat.severity === "high"
                              ? "bg-orange-500/20 text-orange-400"
                              : threat.severity === "medium"
                                ? "bg-yellow-500/20 text-yellow-400"
                                : "bg-blue-500/20 text-blue-400"
                        }`}
                      >
                        {threat.severity?.toUpperCase() || "UNKNOWN"}
                      </span>
                      <span className="text-sm font-semibold text-stone-300">
                        {threat.threat_type || "Unknown"}
                      </span>
                      {threat.confidence !== undefined && (
                        <span className="text-xs text-stone-500 ml-auto font-mono">
                          {(threat.confidence * 100).toFixed(0)}% confidence
                        </span>
                      )}
                    </div>
                    {threat.description && (
                      <p className="text-xs text-stone-400 mt-1">
                        {threat.description}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-stone-500">
                No threat details available
              </p>
            )}

            {/* Categories */}
            {log.threatCategories && log.threatCategories.length > 0 && (
              <div className="flex flex-col gap-1 mt-2">
                <span className="text-xs font-mono uppercase text-stone-500 font-semibold">
                  Categories
                </span>
                <div className="flex gap-1 flex-wrap">
                  {log.threatCategories.map((cat, i) => (
                    <span
                      key={i}
                      className="text-xs px-2 py-0.5 rounded bg-purple-500/20 text-purple-400 font-mono"
                    >
                      {cat}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Prompt & Meta */}
          <div className="flex flex-col gap-3">
            {log.promptText && (
              <div className="flex flex-col gap-1">
                <h4 className="text-xs font-mono uppercase text-stone-500 font-semibold">
                  Prompt Content
                </h4>
                <pre className="bg-zinc-900 border border-zinc-800 rounded-lg p-3 text-xs text-stone-300 whitespace-pre-wrap wrap-break-word max-h-48 overflow-y-auto font-mono">
                  {log.promptText}
                </pre>
              </div>
            )}

            {log.sanitizedPrompt && (
              <div className="flex flex-col gap-1">
                <h4 className="text-xs font-mono uppercase text-stone-500 font-semibold">
                  Sanitized Output
                </h4>
                <pre className="bg-zinc-900 border border-zinc-800 rounded-lg p-3 text-xs text-lime-300/80 whitespace-pre-wrap wrap-break-word max-h-32 overflow-y-auto font-mono">
                  {log.sanitizedPrompt}
                </pre>
              </div>
            )}

            {/* Scan Options */}
            {log.scanOptions != null && (
              <div className="flex flex-col gap-1">
                <h4 className="text-xs font-mono uppercase text-stone-500 font-semibold">
                  Scan Configuration
                </h4>
                <pre className="bg-zinc-900 border border-zinc-800 rounded-lg p-2 text-xs text-stone-400 font-mono">
                  {JSON.stringify(log.scanOptions, null, 2)}
                </pre>
              </div>
            )}

            {/* Metadata row */}
            <div className="grid grid-cols-2 gap-2 mt-1">
              {log.userAgent && (
                <div className="flex flex-col gap-0.5">
                  <span className="text-[10px] font-mono uppercase text-stone-600">
                    User Agent
                  </span>
                  <span
                    className="text-xs text-stone-400 truncate"
                    title={log.userAgent}
                  >
                    {log.userAgent}
                  </span>
                </div>
              )}
              {log.responseId && (
                <div className="flex flex-col gap-0.5">
                  <span className="text-[10px] font-mono uppercase text-stone-600">
                    Response ID
                  </span>
                  <span className="text-xs text-stone-400 font-mono truncate">
                    {log.responseId}
                  </span>
                </div>
              )}
              <div className="flex flex-col gap-0.5">
                <span className="text-[10px] font-mono uppercase text-stone-600">
                  Prompt Hash
                </span>
                <span
                  className="text-xs text-stone-400 font-mono truncate"
                  title={log.promptHash}
                >
                  {log.promptHash.slice(0, 16)}...
                </span>
              </div>
              {log.requestType && (
                <div className="flex flex-col gap-0.5">
                  <span className="text-[10px] font-mono uppercase text-stone-600">
                    Request Type
                  </span>
                  <span className="text-xs text-stone-400 font-mono">
                    {log.requestType}
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      </td>
    </tr>
  );
}

// ============================================
// Pagination Controls
// ============================================

function PaginationControls({
  pagination,
  onPageChange,
  isLoading,
}: {
  pagination: PaginationInfo;
  onPageChange: (page: number) => void;
  isLoading: boolean;
}) {
  const { page, totalPages, totalItems, perPage, hasNext, hasPrev } =
    pagination;

  const startItem = totalItems === 0 ? 0 : (page - 1) * perPage + 1;
  const endItem = Math.min(page * perPage, totalItems);

  // Generate page numbers to show
  const pageNumbers: (number | "...")[] = [];
  if (totalPages <= 7) {
    for (let i = 1; i <= totalPages; i++) pageNumbers.push(i);
  } else {
    pageNumbers.push(1);
    if (page > 3) pageNumbers.push("...");
    for (
      let i = Math.max(2, page - 1);
      i <= Math.min(totalPages - 1, page + 1);
      i++
    ) {
      pageNumbers.push(i);
    }
    if (page < totalPages - 2) pageNumbers.push("...");
    pageNumbers.push(totalPages);
  }

  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-zinc-800">
      <div className="text-xs text-stone-500 font-mono">
        {totalItems > 0 ? (
          <>
            Showing {startItem.toLocaleString()}–{endItem.toLocaleString()} of{" "}
            {totalItems.toLocaleString()}
          </>
        ) : (
          "No results"
        )}
      </div>

      <div className="flex items-center gap-1">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => onPageChange(page - 1)}
          disabled={!hasPrev || isLoading}
          className="h-7 w-7 p-0"
        >
          <IconChevronLeft className="w-4 h-4" />
        </Button>

        {pageNumbers.map((p, i) =>
          p === "..." ? (
            <span key={`dots-${i}`} className="px-1 text-stone-600 text-xs">
              ...
            </span>
          ) : (
            <Button
              key={p}
              variant={p === page ? "default" : "ghost"}
              size="sm"
              onClick={() => onPageChange(p)}
              disabled={isLoading}
              className={`h-7 w-7 p-0 text-xs font-mono ${
                p === page ? "bg-zinc-700 text-white" : "text-stone-400"
              }`}
            >
              {p}
            </Button>
          ),
        )}

        <Button
          variant="ghost"
          size="sm"
          onClick={() => onPageChange(page + 1)}
          disabled={!hasNext || isLoading}
          className="h-7 w-7 p-0"
        >
          <IconChevronRight className="w-4 h-4" />
        </Button>
      </div>
    </div>
  );
}

// ============================================
// Main Logs Page
// ============================================

export default function LogsPage() {
  // ── State ────────────────────────────────────────────────────
  const [logs, setLogs] = useState<GuardLog[]>([]);
  const [pagination, setPagination] = useState<PaginationInfo>({
    page: 1,
    perPage: 50,
    totalItems: 0,
    totalPages: 1,
    nextCursor: null,
    hasNext: false,
    hasPrev: false,
  });
  const [stats, setStats] = useState<GuardStats>({
    totalScans: 0,
    threatsBlocked: 0,
    safePrompts: 0,
    avgLatency: 0,
  });
  const [isLoading, setIsLoading] = useState(true);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [currentPage, setCurrentPage] = useState(1);

  // Filters
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [typeFilter, setTypeFilter] = useState<RequestTypeFilter>("all");
  const [showFilters, setShowFilters] = useState(false);

  // Track how many new realtime events arrived since last data load
  const [pendingEventCount, setPendingEventCount] = useState(0);
  const [showNewEventsBanner, setShowNewEventsBanner] = useState(false);

  // ── Real-time SSE ────────────────────────────────────────────
  const {
    connected: sseConnected,
    reconnecting: sseReconnecting,
    events: realtimeEvents,
    stats: realtimeStats,
    clearEvents,
  } = useGuardEvents({
    enabled: true,
    maxEvents: 200,
    onGuardLog: () => {
      // Track pending events for the banner
      setPendingEventCount((prev) => prev + 1);
      if (currentPage !== 1) {
        setShowNewEventsBanner(true);
      }
    },
    onStatsUpdate: (s) => {
      setStats({
        totalScans: s.total_scans,
        threatsBlocked: s.threats_blocked,
        safePrompts: s.safe_prompts,
        avgLatency: s.avg_latency,
      });
    },
  });

  // ── Data loading ─────────────────────────────────────────────

  const loadData = useCallback(
    async (page: number = 1) => {
      setIsLoading(true);
      try {
        const [logsResult, statsData] = await Promise.all([
          listGuardLogs({
            page,
            perPage: 50,
            status: statusFilter === "all" ? undefined : statusFilter,
            requestType: typeFilter === "all" ? undefined : typeFilter,
          }),
          getGuardStats(),
        ]);
        setLogs(logsResult.logs);
        setPagination(logsResult.pagination);
        setStats(statsData);
        setExpandedRows(new Set());
        // Reset pending event tracking on fresh data load
        setPendingEventCount(0);
        setShowNewEventsBanner(false);
        clearEvents();
      } catch (err) {
        console.error("Failed to load logs:", err);
      } finally {
        setIsLoading(false);
      }
    },
    [statusFilter, typeFilter, clearEvents],
  );

  useEffect(() => {
    loadData(currentPage);
  }, [currentPage, loadData]);

  // Apply real-time stats if available
  useEffect(() => {
    if (realtimeStats) {
      setStats({
        totalScans: realtimeStats.total_scans,
        threatsBlocked: realtimeStats.threats_blocked,
        safePrompts: realtimeStats.safe_prompts,
        avgLatency: realtimeStats.avg_latency,
      });
    }
  }, [realtimeStats]);

  // Prepend real-time events to page 1, but cap total at perPage so
  // pagination stays consistent. New realtime events push out the oldest
  // server-fetched rows from the visible page.
  const perPage = pagination.perPage || 50;
  const displayLogs: GuardLog[] = (() => {
    if (currentPage !== 1) return logs;

    const newEvents = realtimeEvents
      .filter((e) => !logs.some((l) => l.id === e.id))
      .map((e) => ({
        id: e.id,
        organizationId: e.organization_id ?? "",
        apiKeyId: null,
        promptHash: "",
        isSafe: e.is_safe,
        riskScore: e.risk_score,
        threatsDetected: e.threats_detected,
        threatCategories: e.threat_categories,
        latencyMs: e.latency_ms,
        cached: e.cached,
        ipAddress: e.ip_address,
        requestType: e.request_type,
        userAgent: null,
        scanOptions: null,
        responseId: null,
        promptText: null,
        sanitizedPrompt: null,
        createdAt: e.created_at,
      }));

    // Combine and cap at perPage so the table never grows unbounded
    return [...newEvents, ...logs].slice(0, perPage);
  })();

  // Adjusted pagination metadata that accounts for realtime events
  const adjustedPagination: PaginationInfo =
    currentPage === 1 && pendingEventCount > 0
      ? {
          ...pagination,
          totalItems: pagination.totalItems + pendingEventCount,
          totalPages: Math.max(
            1,
            Math.ceil((pagination.totalItems + pendingEventCount) / perPage),
          ),
        }
      : pagination;

  // ── Handlers ─────────────────────────────────────────────────

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
    setShowNewEventsBanner(false);
  };

  const handleJumpToLatest = () => {
    setCurrentPage(1);
    setShowNewEventsBanner(false);
    loadData(1);
  };

  const toggleRow = (id: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const clearFilters = () => {
    setStatusFilter("all");
    setTypeFilter("all");
    setCurrentPage(1);
  };

  const hasActiveFilters = statusFilter !== "all" || typeFilter !== "all";

  // ── Render ───────────────────────────────────────────────────

  return (
    <section className="px-4 py-6 w-full flex flex-col gap-10">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Activity Logs</h1>
          <p className="text-sm text-neutral-400">
            Monitor LLM Guard API activity and threat detection logs
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* SSE Connection Indicator */}
          <div
            className="flex items-center gap-1.5 px-2 py-1 rounded-lg border border-zinc-800 bg-zinc-900"
            title={
              sseConnected
                ? "Real-time updates active"
                : sseReconnecting
                  ? "Reconnecting..."
                  : "Real-time updates disconnected"
            }
          >
            <IconCircleFilled
              className={`w-2 h-2 ${
                sseConnected
                  ? "text-lime-500"
                  : sseReconnecting
                    ? "text-yellow-500 animate-pulse"
                    : "text-red-500"
              }`}
            />
            <span className="text-[10px] font-mono uppercase text-stone-500">
              {sseConnected
                ? "Live"
                : sseReconnecting
                  ? "Reconnecting"
                  : "Offline"}
            </span>
          </div>

          <Button
            variant="secondary"
            size="sm"
            onClick={() => loadData(currentPage)}
            disabled={isLoading}
          >
            <IconRefresh
              className={`w-4 h-4 mr-2 ${isLoading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
        </div>
      </div>

      {/* New events banner — shown when on page > 1 and new events arrive */}
      {showNewEventsBanner && currentPage !== 1 && pendingEventCount > 0 && (
        <div className="flex items-center justify-between bg-indigo-500/10 border border-indigo-500/30 rounded-xl px-4 py-2.5">
          <span className="text-sm text-indigo-300 font-mono">
            <IconCircleFilled className="w-2 h-2 inline text-indigo-400 mr-2 animate-pulse" />
            {pendingEventCount} new event{pendingEventCount > 1 ? "s" : ""}{" "}
            arrived while viewing page {currentPage}
          </span>
          <Button
            variant="secondary"
            size="sm"
            onClick={handleJumpToLatest}
            className="text-xs"
          >
            Jump to latest
          </Button>
        </div>
      )}

      {/* Stats Overview */}
      <div className="flex flex-col gap-6">
        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconListSearch className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              Overview
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200/10"></span>
        </div>

        <div className="grid grid-cols-4 gap-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
            <p className="text-xs text-stone-500 uppercase font-mono mb-2">
              Total Scans
            </p>
            <p className="text-3xl font-bold">
              {stats.totalScans.toLocaleString()}
            </p>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
            <p className="text-xs text-stone-500 uppercase font-mono mb-2">
              Threats Blocked
            </p>
            <p className="text-3xl font-bold text-red-500">
              {stats.threatsBlocked.toLocaleString()}
            </p>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
            <p className="text-xs text-stone-500 uppercase font-mono mb-2">
              Safe Prompts
            </p>
            <p className="text-3xl font-bold text-lime-500">
              {stats.safePrompts.toLocaleString()}
            </p>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
            <p className="text-xs text-stone-500 uppercase font-mono mb-2">
              Avg Latency
            </p>
            <p className="text-3xl font-bold">{stats.avgLatency}ms</p>
          </div>
        </div>

        {/* Top categories (if available) */}
        {stats.topCategories && stats.topCategories.length > 0 && (
          <div className="flex gap-2 items-center flex-wrap">
            <span className="text-xs text-stone-500 font-mono uppercase">
              Top Threats:
            </span>
            {stats.topCategories.map((c) => (
              <span
                key={c.category}
                className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-400 font-mono border border-red-500/20"
              >
                {c.category} ({c.count})
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Activity Logs Table */}
      <div className="flex flex-col gap-6">
        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconListSearch className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              Recent Activity
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200/10"></span>

          {/* Filter Toggle */}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowFilters(!showFilters)}
            className={`text-xs font-mono uppercase gap-1 ${
              hasActiveFilters ? "text-purple-400" : "text-stone-500"
            }`}
          >
            <IconFilter className="w-3.5 h-3.5" />
            Filters
            {hasActiveFilters && (
              <span className="w-1.5 h-1.5 rounded-full bg-purple-500"></span>
            )}
          </Button>
        </div>

        {/* Filter Bar */}
        {showFilters && (
          <div className="flex gap-3 items-center bg-zinc-900/50 border border-zinc-800 rounded-xl p-3">
            <div className="flex gap-2 items-center">
              <span className="text-xs text-stone-500 font-mono">Status:</span>
              {(["all", "safe", "threat"] as StatusFilter[]).map((s) => (
                <button
                  key={s}
                  onClick={() => {
                    setStatusFilter(s);
                    setCurrentPage(1);
                  }}
                  className={`text-xs px-2.5 py-1 rounded-md font-mono uppercase transition-colors ${
                    statusFilter === s
                      ? s === "safe"
                        ? "bg-lime-500/20 text-lime-400 border border-lime-500/30"
                        : s === "threat"
                          ? "bg-red-500/20 text-red-400 border border-red-500/30"
                          : "bg-zinc-700 text-white border border-zinc-600"
                      : "text-stone-500 hover:text-stone-300 border border-transparent"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>

            <div className="w-px h-4 bg-zinc-800"></div>

            <div className="flex gap-2 items-center">
              <span className="text-xs text-stone-500 font-mono">Type:</span>
              {(
                ["all", "scan", "validate", "batch"] as RequestTypeFilter[]
              ).map((t) => (
                <button
                  key={t}
                  onClick={() => {
                    setTypeFilter(t);
                    setCurrentPage(1);
                  }}
                  className={`text-xs px-2.5 py-1 rounded-md font-mono uppercase transition-colors ${
                    typeFilter === t
                      ? "bg-zinc-700 text-white border border-zinc-600"
                      : "text-stone-500 hover:text-stone-300 border border-transparent"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>

            {hasActiveFilters && (
              <>
                <div className="w-px h-4 bg-zinc-800"></div>
                <button
                  onClick={clearFilters}
                  className="text-xs text-stone-500 hover:text-stone-300 flex items-center gap-1"
                >
                  <IconX className="w-3 h-3" />
                  Clear
                </button>
              </>
            )}
          </div>
        )}

        <div className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden">
          {displayLogs.length === 0 && !isLoading ? (
            <div className="p-8 text-center text-stone-500">
              <IconListSearch className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No activity logs yet</p>
              <p className="text-xs mt-1">
                Logs will appear when the Guard API is used
              </p>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="border-b border-zinc-800 bg-zinc-800/50">
                    <tr className="text-left text-xs font-mono uppercase text-stone-500">
                      <th className="px-2 py-3 w-8"></th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Risk Score</th>
                      <th className="px-4 py-3">Threats</th>
                      <th className="px-4 py-3">Latency</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Cached</th>
                      <th className="px-4 py-3">IP Address</th>
                      <th className="px-4 py-3">Time</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800">
                    {displayLogs.map((log) => {
                      const threats = (log.threatsDetected as unknown[]) || [];
                      const isExpanded = expandedRows.has(log.id);
                      const isNewRealtime = realtimeEvents.some(
                        (e) => e.id === log.id,
                      );

                      return (
                        <Fragment key={log.id}>
                          <tr
                            className={`hover:bg-zinc-800/50 cursor-pointer transition-colors ${
                              isExpanded ? "bg-zinc-800/30" : ""
                            } ${isNewRealtime ? "animate-in fade-in slide-in-from-top-1 duration-300" : ""}`}
                            onClick={() => toggleRow(log.id)}
                          >
                            <td className="px-2 py-3 text-stone-600">
                              {isExpanded ? (
                                <IconChevronDown className="w-4 h-4" />
                              ) : (
                                <IconChevronRight className="w-4 h-4" />
                              )}
                            </td>
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
                                <span className="text-red-400 flex items-center gap-1">
                                  {threats.length} detected
                                  {log.threatCategories &&
                                    log.threatCategories.length > 0 && (
                                      <span className="text-[10px] text-stone-500 font-mono ml-1">
                                        (
                                        {log.threatCategories
                                          .slice(0, 2)
                                          .join(", ")}
                                        {log.threatCategories.length > 2 &&
                                          ` +${log.threatCategories.length - 2}`}
                                        )
                                      </span>
                                    )}
                                </span>
                              ) : (
                                <span className="text-stone-500">None</span>
                              )}
                            </td>
                            <td className="px-4 py-3 text-stone-400 font-mono text-sm">
                              {log.latencyMs !== null &&
                              log.latencyMs !== undefined
                                ? `${log.latencyMs}ms`
                                : "-"}
                            </td>
                            <td className="px-4 py-3">
                              {log.requestType ? (
                                <span
                                  className={`text-xs px-2 py-0.5 rounded font-mono ${
                                    log.requestType === "batch"
                                      ? "bg-indigo-500/20 text-indigo-400"
                                      : log.requestType === "validate"
                                        ? "bg-cyan-500/20 text-cyan-400"
                                        : "bg-stone-700 text-stone-400"
                                  }`}
                                >
                                  {log.requestType}
                                </span>
                              ) : (
                                <span className="text-xs px-2 py-0.5 rounded bg-stone-700 text-stone-400 font-mono">
                                  scan
                                </span>
                              )}
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
                            <td className="px-4 py-3 text-stone-500 text-sm whitespace-nowrap">
                              {new Date(log.createdAt).toLocaleString()}
                            </td>
                          </tr>

                          {/* Expanded threat detail row */}
                          {isExpanded && <ThreatDetailRow log={log} />}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              <PaginationControls
                pagination={adjustedPagination}
                onPageChange={handlePageChange}
                isLoading={isLoading}
              />
            </>
          )}

          {/* Loading overlay */}
          {isLoading && displayLogs.length > 0 && (
            <div className="absolute inset-0 bg-zinc-900/50 flex items-center justify-center rounded-2xl">
              <IconRefresh className="w-6 h-6 animate-spin text-stone-400" />
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

// Fragment import for rendering multiple table rows per item
import { Fragment } from "react";
