// ============================================
// Async Write Buffer for Guard Log Inserts
// ============================================
//
// Batches guard_log INSERT operations to reduce DB round-trips under high load.
// Uses a tokio mpsc channel: producers send log entries, a background task
// flushes them in batches (every FLUSH_INTERVAL_MS or when BATCH_SIZE is reached).

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use uuid::Uuid;

// ============================================
// Configuration
// ============================================

/// Maximum number of log entries to batch in a single INSERT
const BATCH_SIZE: usize = 100;

/// How often to flush pending entries (milliseconds)
const FLUSH_INTERVAL_MS: u64 = 500;

/// Channel buffer size — how many entries can queue before backpressure
const CHANNEL_BUFFER: usize = 10_000;

// ============================================
// Guard Log Entry (queued for batch insert)
// ============================================

#[derive(Debug, Clone)]
pub struct GuardLogEntry {
    pub id: Uuid,
    pub organization_id: Option<Uuid>,
    pub api_key_id: Option<Uuid>,
    pub prompt_hash: String,
    pub is_safe: bool,
    pub risk_score: f32,
    pub threats_detected: serde_json::Value,
    pub latency_ms: i32,
    pub cached: bool,
    pub ip_address: Option<String>,
    pub prompt_text: Option<String>,
    pub threat_categories: Vec<String>,
    pub scan_options: serde_json::Value,
    pub user_agent: Option<String>,
    pub request_type: String,
    pub sanitized_prompt: Option<String>,
    pub response_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl GuardLogEntry {
    /// Create a new entry for a scan request.
    /// If the prompt is NOT safe, the full prompt_text is stored for forensics.
    /// If the prompt IS safe, prompt_text is omitted to save space.
    #[allow(clippy::too_many_arguments)]
    pub fn new_scan(
        organization_id: Option<Uuid>,
        api_key_id: Option<Uuid>,
        prompt_hash: String,
        is_safe: bool,
        risk_score: f32,
        threats_detected: serde_json::Value,
        latency_ms: i32,
        cached: bool,
        ip_address: Option<String>,
        prompt_text: Option<String>,
        threat_categories: Vec<String>,
        scan_options: serde_json::Value,
        user_agent: Option<String>,
        sanitized_prompt: Option<String>,
        response_id: Option<Uuid>,
    ) -> Self {
        // Only store full prompt text for threats — safe prompts just get the hash
        let stored_prompt = if is_safe { None } else { prompt_text };

        Self {
            id: Uuid::new_v4(),
            organization_id,
            api_key_id,
            prompt_hash,
            is_safe,
            risk_score,
            threats_detected,
            latency_ms,
            cached,
            ip_address,
            prompt_text: stored_prompt,
            threat_categories,
            scan_options,
            user_agent,
            request_type: "scan".to_string(),
            sanitized_prompt,
            response_id,
            created_at: Utc::now(),
        }
    }
}

// ============================================
// Write Buffer Handle (clone-friendly sender)
// ============================================

#[derive(Clone)]
pub struct WriteBufferHandle {
    tx: mpsc::Sender<GuardLogEntry>,
}

impl WriteBufferHandle {
    /// Queue a guard log entry for batch insertion.
    /// Returns immediately. If the buffer is full, logs a warning and drops the entry.
    pub async fn queue(&self, entry: GuardLogEntry) {
        if let Err(e) = self.tx.try_send(entry) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!(
                        "Guard log write buffer full ({} capacity). Dropping entry. \
                         Consider increasing CHANNEL_BUFFER or adding more DB capacity.",
                        CHANNEL_BUFFER
                    );
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::error!("Guard log write buffer channel closed unexpectedly");
                }
            }
        }
    }

    /// Queue a guard log entry, waiting if the buffer is full (backpressure).
    /// Use this when you absolutely cannot drop the entry.
    #[allow(dead_code)]
    pub async fn queue_blocking(&self, entry: GuardLogEntry) {
        if let Err(e) = self.tx.send(entry).await {
            tracing::error!("Guard log write buffer send failed: {}", e);
        }
    }
}

// ============================================
// Write Buffer (background flush task)
// ============================================

pub struct WriteBuffer {
    pool: PgPool,
    rx: mpsc::Receiver<GuardLogEntry>,
}

impl WriteBuffer {
    /// Spawn the write buffer. Returns a handle for sending entries.
    pub fn spawn(pool: PgPool) -> WriteBufferHandle {
        let (tx, rx) = mpsc::channel(CHANNEL_BUFFER);

        let buffer = WriteBuffer { pool, rx };

        tokio::spawn(async move {
            buffer.run().await;
        });

        tracing::info!(
            "Guard log write buffer started (batch_size={}, flush_interval={}ms, channel_buffer={})",
            BATCH_SIZE,
            FLUSH_INTERVAL_MS,
            CHANNEL_BUFFER
        );

        WriteBufferHandle { tx }
    }

    /// Main loop: collect entries and flush in batches
    async fn run(mut self) {
        let mut batch: Vec<GuardLogEntry> = Vec::with_capacity(BATCH_SIZE);
        let mut flush_timer = interval(Duration::from_millis(FLUSH_INTERVAL_MS));

        // Also publish to Redis for SSE subscribers
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let redis_client = redis::Client::open(redis_url).ok();
        let mut redis_conn = if let Some(ref client) = redis_client {
            match redis::aio::ConnectionManager::new(client.clone()).await {
                Ok(conn) => Some(conn),
                Err(e) => {
                    tracing::warn!(
                        "Write buffer: Redis connection failed (SSE events disabled): {}",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        loop {
            tokio::select! {
                // Receive entries from producers
                entry = self.rx.recv() => {
                    match entry {
                        Some(e) => {
                            batch.push(e);
                            // Flush immediately if batch is full
                            if batch.len() >= BATCH_SIZE {
                                self.flush_batch(&mut batch, &mut redis_conn).await;
                            }
                        }
                        None => {
                            // Channel closed — flush remaining and exit
                            if !batch.is_empty() {
                                self.flush_batch(&mut batch, &mut redis_conn).await;
                            }
                            tracing::info!("Guard log write buffer shutting down");
                            return;
                        }
                    }
                }
                // Periodic flush timer
                _ = flush_timer.tick() => {
                    if !batch.is_empty() {
                        self.flush_batch(&mut batch, &mut redis_conn).await;
                    }
                }
            }
        }
    }

    /// Flush a batch of entries to the database using a single multi-row INSERT
    async fn flush_batch(
        &self,
        batch: &mut Vec<GuardLogEntry>,
        redis_conn: &mut Option<redis::aio::ConnectionManager>,
    ) {
        if batch.is_empty() {
            return;
        }

        let count = batch.len();
        let entries: Vec<GuardLogEntry> = batch.drain(..).collect();

        match self.batch_insert(&entries).await {
            Ok(()) => {
                tracing::debug!("Flushed {} guard log entries to DB", count);

                // Publish events to Redis for SSE subscribers (best-effort)
                if let Some(ref mut conn) = redis_conn {
                    for entry in &entries {
                        if let Ok(json) = serde_json::to_string(&GuardLogEvent::from(entry)) {
                            let result: Result<(), _> = redis::cmd("PUBLISH")
                                .arg("guard_log_events")
                                .arg(&json)
                                .query_async(conn)
                                .await;
                            if let Err(e) = result {
                                tracing::debug!(
                                    "Failed to publish guard log event to Redis: {}",
                                    e
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to flush {} guard log entries: {}", count, e);
                // TODO: implement retry logic or dead-letter queue for critical entries
            }
        }
    }

    /// Execute a batch INSERT using raw SQL with multiple value tuples
    async fn batch_insert(&self, entries: &[GuardLogEntry]) -> Result<(), sqlx::Error> {
        if entries.is_empty() {
            return Ok(());
        }

        // Build a multi-row INSERT using query builder
        // For large batches this is much more efficient than individual inserts
        let mut query = String::from(
            "INSERT INTO guard_log (
                id, organization_id, api_key_id, prompt_hash, is_safe,
                risk_score, threats_detected, latency_ms, cached, ip_address,
                prompt_text, threat_categories, scan_options, user_agent,
                request_type, sanitized_prompt, response_id, created_at
            ) VALUES ",
        );

        let mut param_idx = 1u32;
        for (i, _) in entries.iter().enumerate() {
            if i > 0 {
                query.push_str(", ");
            }
            query.push('(');
            for j in 0..18 {
                if j > 0 {
                    query.push_str(", ");
                }
                query.push('$');
                query.push_str(&param_idx.to_string());
                param_idx += 1;
            }
            query.push(')');
        }

        let mut q = sqlx::query(&query);

        for entry in entries {
            q = q
                .bind(entry.id)
                .bind(entry.organization_id)
                .bind(entry.api_key_id)
                .bind(&entry.prompt_hash)
                .bind(entry.is_safe)
                .bind(entry.risk_score)
                .bind(&entry.threats_detected)
                .bind(entry.latency_ms)
                .bind(entry.cached)
                .bind(&entry.ip_address)
                .bind(&entry.prompt_text)
                .bind(&entry.threat_categories)
                .bind(&entry.scan_options)
                .bind(&entry.user_agent)
                .bind(&entry.request_type)
                .bind(&entry.sanitized_prompt)
                .bind(entry.response_id)
                .bind(entry.created_at.naive_utc());
        }

        q.execute(&self.pool).await?;
        Ok(())
    }
}

// ============================================
// SSE Event payload (published to Redis)
// ============================================

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct GuardLogEvent {
    pub id: Uuid,
    pub organization_id: Option<Uuid>,
    pub is_safe: bool,
    pub risk_score: f32,
    pub threats_detected: serde_json::Value,
    pub threat_categories: Vec<String>,
    pub latency_ms: i32,
    pub cached: bool,
    pub ip_address: Option<String>,
    pub request_type: String,
    pub created_at: String,
}

impl From<&GuardLogEntry> for GuardLogEvent {
    fn from(entry: &GuardLogEntry) -> Self {
        Self {
            id: entry.id,
            organization_id: entry.organization_id,
            is_safe: entry.is_safe,
            risk_score: entry.risk_score,
            threats_detected: entry.threats_detected.clone(),
            threat_categories: entry.threat_categories.clone(),
            latency_ms: entry.latency_ms,
            cached: entry.cached,
            ip_address: entry.ip_address.clone(),
            request_type: entry.request_type.clone(),
            created_at: entry.created_at.to_rfc3339(),
        }
    }
}
