use redis::AsyncCommands;

/// Check rate limit for a given key
/// Returns (allowed, remaining, reset_time_seconds)
pub async fn check_rate_limit(
    redis_conn: &mut redis::aio::ConnectionManager,
    key: &str,
    max_requests: u32,
    window_seconds: u64,
) -> Result<(bool, u32, u64), redis::RedisError> {
    let cache_key = format!("ratelimit:{}", key);

    // Get current count
    let current: u32 = redis_conn.get(&cache_key).await.unwrap_or(0);

    if current >= max_requests {
        let ttl: i64 = redis_conn.ttl(&cache_key).await.unwrap_or(0);
        return Ok((false, 0, ttl.max(0) as u64));
    }

    // Increment counter
    let new_count: u32 = redis_conn.incr(&cache_key, 1).await?;

    // Set expiry on first request
    if new_count == 1 {
        let _: () = redis_conn.expire(&cache_key, window_seconds as i64).await?;
    }

    let ttl: i64 = redis_conn
        .ttl(&cache_key)
        .await
        .unwrap_or(window_seconds as i64);
    let remaining = max_requests.saturating_sub(new_count);

    Ok((true, remaining, ttl.max(0) as u64))
}

/// Generate rate limit key from API key or IP
pub fn rate_limit_key(api_key: Option<&str>, ip: Option<&str>) -> String {
    if let Some(key) = api_key {
        // Use first 16 chars of API key as identifier
        let key_prefix = if key.len() > 16 { &key[..16] } else { key };
        format!("apikey:{}", key_prefix)
    } else if let Some(ip) = ip {
        format!("ip:{}", ip)
    } else {
        "unknown".to_string()
    }
}

pub const RATE_LIMIT_WINDOW_SECONDS: u64 = 60;

/// Monthly quota: 10,000 requests per API key (Basic plan)
/// TODO: Replace with plan-based lookup from database when pricing tiers are implemented
pub const MONTHLY_QUOTA_BASIC: u32 = 10_000;

/// Seconds in ~30 days (used as Redis TTL for monthly counters)
const MONTHLY_WINDOW_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Check monthly usage quota for an API key.
/// Returns (allowed, used, limit, days_until_reset)
pub async fn check_monthly_quota(
    redis_conn: &mut redis::aio::ConnectionManager,
    api_key_id: &str,
    monthly_limit: u32,
) -> Result<(bool, u32, u32, u64), redis::RedisError> {
    // Key resets at the start of each calendar month via TTL
    let month_key = format!("quota:monthly:{}", api_key_id);

    // Get current usage
    let current: u32 = redis_conn.get(&month_key).await.unwrap_or(0);

    if current >= monthly_limit {
        let ttl: i64 = redis_conn.ttl(&month_key).await.unwrap_or(0);
        let days_left = (ttl.max(0) as u64) / 86400 + 1;
        return Ok((false, current, monthly_limit, days_left));
    }

    // Increment counter
    let new_count: u32 = redis_conn.incr(&month_key, 1).await?;

    // Set expiry on first request of the month
    if new_count == 1 {
        let _: () = redis_conn
            .expire(&month_key, MONTHLY_WINDOW_SECONDS as i64)
            .await?;
    }

    let ttl: i64 = redis_conn
        .ttl(&month_key)
        .await
        .unwrap_or(MONTHLY_WINDOW_SECONDS as i64);
    let days_left = (ttl.max(0) as u64) / 86400 + 1;

    Ok((true, new_count, monthly_limit, days_left))
}

/// Check monthly quota without incrementing (for pre-checks like batch)
pub async fn check_monthly_quota_remaining(
    redis_conn: &mut redis::aio::ConnectionManager,
    api_key_id: &str,
    monthly_limit: u32,
) -> Result<u32, redis::RedisError> {
    let month_key = format!("quota:monthly:{}", api_key_id);
    let current: u32 = redis_conn.get(&month_key).await.unwrap_or(0);
    Ok(monthly_limit.saturating_sub(current))
}

/// Increment monthly quota by a specific amount (for batch requests)
pub async fn increment_monthly_quota(
    redis_conn: &mut redis::aio::ConnectionManager,
    api_key_id: &str,
    count: u32,
) -> Result<u32, redis::RedisError> {
    let month_key = format!("quota:monthly:{}", api_key_id);
    let new_count: u32 = redis_conn.incr(&month_key, count).await?;

    // Ensure TTL is set
    let ttl: i64 = redis_conn.ttl(&month_key).await.unwrap_or(-1);
    if ttl < 0 {
        let _: () = redis_conn
            .expire(&month_key, MONTHLY_WINDOW_SECONDS as i64)
            .await?;
    }

    Ok(new_count)
}
