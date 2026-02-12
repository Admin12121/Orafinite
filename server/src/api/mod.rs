use redis::aio::ConnectionManager;
use sqlx::PgPool;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::db::write_buffer::WriteBufferHandle;
use crate::grpc::ml_client::MlClient;

pub mod api_keys;
pub mod auth;
pub mod events;
pub mod guard;
pub mod guard_logs;
pub mod health;
pub mod models;
pub mod organization;
pub mod routes;
pub mod scan;

// ============================================
// Circuit Breaker Configuration
// ============================================

/// Number of consecutive failures before circuit opens
const CIRCUIT_FAILURE_THRESHOLD: u32 = 5;

/// Time to wait before attempting to close the circuit (in seconds)
const CIRCUIT_RESET_TIMEOUT_SECS: u64 = 30;

/// Maximum time to cache a client connection (in seconds)
const CLIENT_CACHE_TTL_SECS: u64 = 300;

// ============================================
// Circuit Breaker State
// ============================================

#[derive(Debug, Clone, Copy, PartialEq)]
enum CircuitState {
    Closed,   // Normal operation
    Open,     // Failing, reject requests
    HalfOpen, // Testing if service recovered
}

struct CircuitBreaker {
    failure_count: AtomicU32,
    last_failure_time: AtomicU64,
    state: RwLock<CircuitState>,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            failure_count: AtomicU32::new(0),
            last_failure_time: AtomicU64::new(0),
            state: RwLock::new(CircuitState::Closed),
        }
    }

    async fn record_success(&self) {
        self.failure_count.store(0, Ordering::SeqCst);
        let mut state = self.state.write().await;
        *state = CircuitState::Closed;
    }

    async fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
        self.last_failure_time.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::SeqCst,
        );

        if count >= CIRCUIT_FAILURE_THRESHOLD {
            let mut state = self.state.write().await;
            *state = CircuitState::Open;
            tracing::warn!(
                "Circuit breaker opened after {} consecutive failures",
                count
            );
        }
    }

    async fn can_attempt(&self) -> bool {
        let state = *self.state.read().await;

        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if enough time has passed to try again
                let last_failure = self.last_failure_time.load(Ordering::SeqCst);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if now - last_failure >= CIRCUIT_RESET_TIMEOUT_SECS {
                    // Move to half-open state
                    let mut state = self.state.write().await;
                    *state = CircuitState::HalfOpen;
                    tracing::info!("Circuit breaker moving to half-open state");
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    async fn get_state(&self) -> CircuitState {
        *self.state.read().await
    }
}

// ============================================
// Application State
// ============================================

struct CachedClient {
    client: MlClient,
    created_at: Instant,
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: ConnectionManager,
    pub write_buffer: WriteBufferHandle,
    ml_client: Arc<RwLock<Option<CachedClient>>>,
    ml_sidecar_url: String,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl AppState {
    pub fn new(
        db: PgPool,
        redis: ConnectionManager,
        ml_sidecar_url: String,
        write_buffer: WriteBufferHandle,
    ) -> Self {
        Self {
            db,
            redis,
            write_buffer,
            ml_client: Arc::new(RwLock::new(None)),
            ml_sidecar_url,
            circuit_breaker: Arc::new(CircuitBreaker::new()),
        }
    }

    /// Get an ML client, with circuit breaker protection
    ///
    /// This method implements:
    /// - Connection caching with TTL
    /// - Circuit breaker pattern to prevent cascade failures
    /// - Proper error propagation
    pub async fn get_ml_client(&self) -> Result<MlClient, String> {
        // Check circuit breaker
        if !self.circuit_breaker.can_attempt().await {
            let state = self.circuit_breaker.get_state().await;
            return Err(format!(
                "ML service circuit breaker is {:?}. Service temporarily unavailable. Will retry in {} seconds.",
                state, CIRCUIT_RESET_TIMEOUT_SECS
            ));
        }

        // Check for cached client
        {
            let cache = self.ml_client.read().await;
            if let Some(ref cached) = *cache {
                // Check if cache is still valid
                if cached.created_at.elapsed() < Duration::from_secs(CLIENT_CACHE_TTL_SECS) {
                    return Ok(cached.client.clone());
                }
            }
        }

        // Need to create new client
        let mut cache = self.ml_client.write().await;

        // Double-check after acquiring write lock
        if let Some(ref cached) = *cache {
            if cached.created_at.elapsed() < Duration::from_secs(CLIENT_CACHE_TTL_SECS) {
                return Ok(cached.client.clone());
            }
        }

        // Create new client
        match MlClient::new(&self.ml_sidecar_url).await {
            Ok(client) => {
                self.circuit_breaker.record_success().await;
                *cache = Some(CachedClient {
                    client: client.clone(),
                    created_at: Instant::now(),
                });
                Ok(client)
            }
            Err(e) => {
                self.circuit_breaker.record_failure().await;
                // Clear cached client on error
                *cache = None;
                Err(format!("Failed to connect to ML sidecar: {}", e))
            }
        }
    }

    /// Record a successful ML operation (resets circuit breaker)
    #[allow(dead_code)]
    pub async fn record_ml_success(&self) {
        self.circuit_breaker.record_success().await;
    }

    /// Record a failed ML operation (may open circuit breaker)
    #[allow(dead_code)]
    pub async fn record_ml_failure(&self) {
        self.circuit_breaker.record_failure().await;
    }

    /// Invalidate the cached ML client (force reconnection on next request)
    #[allow(dead_code)]
    pub async fn invalidate_ml_client(&self) {
        let mut cache = self.ml_client.write().await;
        *cache = None;
    }

    /// Get the ML sidecar URL
    #[allow(dead_code)]
    pub fn ml_sidecar_url(&self) -> &str {
        &self.ml_sidecar_url
    }
}
