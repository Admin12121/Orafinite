"use client";

import {
  useState,
  useEffect,
  useCallback,
  useRef,
  type MutableRefObject,
} from "react";

// ============================================
// Types
// ============================================

export interface GuardLogEvent {
  id: string;
  organization_id: string | null;
  is_safe: boolean;
  risk_score: number;
  threats_detected: unknown;
  threat_categories: string[];
  latency_ms: number;
  cached: boolean;
  ip_address: string | null;
  request_type: string;
  created_at: string;
}

export interface StatsUpdate {
  total_scans: number;
  threats_blocked: number;
  safe_prompts: number;
  avg_latency: number;
}

export interface ConnectionEvent {
  organization_id: string;
  user_id: string;
  message: string;
}

export type GuardEventType = "guard_log" | "stats_update" | "connected";

export interface UseGuardEventsOptions {
  /** Whether to auto-connect on mount. Defaults to true. */
  enabled?: boolean;
  /** Maximum number of recent events to keep in memory. Defaults to 200. */
  maxEvents?: number;
  /** Callback fired for every new guard log event */
  onGuardLog?: (event: GuardLogEvent) => void;
  /** Callback fired for stats updates (every ~10s) */
  onStatsUpdate?: (stats: StatsUpdate) => void;
  /** Callback fired when connected */
  onConnected?: (info: ConnectionEvent) => void;
  /** Callback fired on errors */
  onError?: (error: Event) => void;
}

export interface UseGuardEventsReturn {
  /** Whether the SSE connection is currently open */
  connected: boolean;
  /** Whether we're attempting to reconnect after a disconnect */
  reconnecting: boolean;
  /** Most recent guard log events (newest first, capped at maxEvents) */
  events: GuardLogEvent[];
  /** Most recent stats snapshot from the server */
  stats: StatsUpdate | null;
  /** Connection info from the server */
  connectionInfo: ConnectionEvent | null;
  /** Manually disconnect */
  disconnect: () => void;
  /** Manually reconnect */
  reconnect: () => void;
  /** Clear the in-memory event buffer */
  clearEvents: () => void;
}

// ============================================
// Hook
// ============================================

/**
 * React hook that subscribes to the Rust API's SSE endpoint for
 * real-time guard log events.
 *
 * The SSE endpoint requires session auth. The browser automatically
 * sends the `better-auth.session_token` cookie, so we use
 * a proxy through Next.js (the `/v1/guard/events` path is proxied
 * by nginx to the Rust API).
 *
 * ## Usage
 *
 * ```tsx
 * const { connected, events, stats } = useGuardEvents({
 *   onGuardLog: (e) => console.log("New event:", e),
 * });
 * ```
 */
export function useGuardEvents(
  options: UseGuardEventsOptions = {},
): UseGuardEventsReturn {
  const {
    enabled = true,
    maxEvents = 200,
    onGuardLog,
    onStatsUpdate,
    onConnected,
    onError,
  } = options;

  const [connected, setConnected] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [events, setEvents] = useState<GuardLogEvent[]>([]);
  const [stats, setStats] = useState<StatsUpdate | null>(null);
  const [connectionInfo, setConnectionInfo] = useState<ConnectionEvent | null>(
    null,
  );

  // Refs to keep callback references stable across renders
  const onGuardLogRef = useRef(onGuardLog);
  const onStatsUpdateRef = useRef(onStatsUpdate);
  const onConnectedRef = useRef(onConnected);
  const onErrorRef = useRef(onError);
  const maxEventsRef = useRef(maxEvents);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptRef = useRef(0);
  const connectRef: MutableRefObject<(() => Promise<void>) | null> =
    useRef(null);

  // Update refs when callbacks change
  useEffect(() => {
    onGuardLogRef.current = onGuardLog;
  }, [onGuardLog]);
  useEffect(() => {
    onStatsUpdateRef.current = onStatsUpdate;
  }, [onStatsUpdate]);
  useEffect(() => {
    onConnectedRef.current = onConnected;
  }, [onConnected]);
  useEffect(() => {
    onErrorRef.current = onError;
  }, [onError]);
  useEffect(() => {
    maxEventsRef.current = maxEvents;
  }, [maxEvents]);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  const disconnect = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setConnected(false);
    setReconnecting(false);
    reconnectAttemptRef.current = 0;
  }, []);

  const connect: () => Promise<void> = useCallback(async () => {
    // Clean up any existing connection
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }

    // The SSE endpoint is proxied through nginx to the Rust API.
    //
    // EventSource does NOT support custom headers, so we use two
    // strategies for authentication:
    //
    // 1. The `better-auth.session_token` cookie is sent automatically
    //    for same-origin requests (handled by nginx proxy).
    //
    // 2. As a fallback, we obtain a short-lived, single-use ticket
    //    from `POST /v1/guard/events/ticket` and pass it as
    //    `?ticket=<ticket>`. This avoids leaking the real session
    //    token in URLs, logs, Referer headers, or browser history.

    let url = `/v1/guard/events`;

    // Obtain a one-time SSE ticket (NOT the raw session token)
    try {
      const res = await fetch("/v1/guard/events/ticket", {
        method: "POST",
        credentials: "include",
      });
      if (res.ok) {
        const data = (await res.json()) as {
          ticket: string;
          expires_in: number;
        };
        if (data.ticket) {
          url += `?ticket=${encodeURIComponent(data.ticket)}`;
        }
      } else {
        // Cookie-based auth will be used as fallback
        console.debug(
          "[useGuardEvents] Could not obtain SSE ticket, relying on cookie auth",
        );
      }
    } catch {
      // Cookie-based auth will be used as fallback
      console.debug(
        "[useGuardEvents] Could not obtain SSE ticket, relying on cookie auth",
      );
    }

    const es = new EventSource(url, { withCredentials: true });
    eventSourceRef.current = es;

    es.addEventListener("connected", (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data) as ConnectionEvent;
        setConnectionInfo(data);
        setConnected(true);
        setReconnecting(false);
        reconnectAttemptRef.current = 0;
        onConnectedRef.current?.(data);
      } catch (err) {
        console.error("[useGuardEvents] Failed to parse connected event:", err);
      }
    });

    es.addEventListener("guard_log", (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data) as GuardLogEvent;

        setEvents((prev) => {
          const next = [data, ...prev];
          // Cap at maxEvents to prevent unbounded memory growth
          if (next.length > maxEventsRef.current) {
            return next.slice(0, maxEventsRef.current);
          }
          return next;
        });

        onGuardLogRef.current?.(data);
      } catch (err) {
        console.error("[useGuardEvents] Failed to parse guard_log event:", err);
      }
    });

    es.addEventListener("stats_update", (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data) as StatsUpdate;
        setStats(data);
        onStatsUpdateRef.current?.(data);
      } catch (err) {
        console.error(
          "[useGuardEvents] Failed to parse stats_update event:",
          err,
        );
      }
    });

    es.onopen = () => {
      setConnected(true);
      setReconnecting(false);
      reconnectAttemptRef.current = 0;
    };

    es.onerror = (e: Event) => {
      setConnected(false);
      onErrorRef.current?.(e);

      // Auto-reconnect with exponential backoff
      const attempt = reconnectAttemptRef.current;
      const delay = Math.min(1000 * Math.pow(2, attempt), 30000); // max 30s

      console.warn(
        `[useGuardEvents] Connection lost. Reconnecting in ${delay}ms (attempt ${attempt + 1})...`,
      );

      setReconnecting(true);
      reconnectAttemptRef.current = attempt + 1;

      // Close the current connection
      es.close();
      eventSourceRef.current = null;

      reconnectTimerRef.current = setTimeout(() => {
        reconnectTimerRef.current = null;
        if (connectRef.current) {
          void connectRef.current();
        }
      }, delay);
    };
  }, []);

  // Keep the ref in sync so reconnect callbacks always call the latest version
  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  const reconnect = useCallback(() => {
    disconnect();
    void connect();
  }, [disconnect, connect]);

  // Auto-connect on mount if enabled
  useEffect(() => {
    if (!enabled) {
      // Use cleanup-style disconnect to avoid synchronous setState in effect body
      return () => {
        disconnect();
      };
    }

    void connect();

    return () => {
      disconnect();
    };
  }, [enabled, connect, disconnect]);

  return {
    connected,
    reconnecting,
    events,
    stats,
    connectionInfo,
    disconnect,
    reconnect,
    clearEvents,
  };
}
