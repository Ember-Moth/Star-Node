use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

const NANOS_PER_SECOND: u128 = 1_000_000_000;
const MIN_BURST_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BandwidthLimit {
    pub bytes_per_second: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst_bytes: Option<u64>,
}

impl BandwidthLimit {
    pub fn new(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second,
            burst_bytes: None,
        }
    }

    pub fn with_burst(bytes_per_second: u64, burst_bytes: u64) -> Self {
        Self {
            bytes_per_second,
            burst_bytes: Some(burst_bytes),
        }
    }

    fn capacity(&self) -> u64 {
        self.burst_bytes
            .unwrap_or(self.bytes_per_second)
            .max(MIN_BURST_BYTES)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    Delayed(Duration),
    Disabled,
}

#[derive(Debug)]
pub struct TokenBucket {
    bytes_per_second: u64,
    capacity: u64,
    state: Mutex<TokenBucketState>,
}

#[derive(Debug)]
struct TokenBucketState {
    tokens: u64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(limit: BandwidthLimit) -> Self {
        let capacity = limit.capacity();
        Self {
            bytes_per_second: limit.bytes_per_second,
            capacity,
            state: Mutex::new(TokenBucketState {
                tokens: capacity,
                last_refill: Instant::now(),
            }),
        }
    }

    pub fn try_consume(&self, bytes: u64) -> RateLimitDecision {
        if bytes == 0 {
            return RateLimitDecision::Allowed;
        }

        if self.bytes_per_second == 0 {
            return RateLimitDecision::Disabled;
        }

        let mut state = self.state.lock();
        self.refill(&mut state);

        if state.tokens >= bytes {
            state.tokens -= bytes;
            return RateLimitDecision::Allowed;
        }

        let missing = bytes.saturating_sub(state.tokens);
        let wait_nanos =
            (missing as u128 * NANOS_PER_SECOND).div_ceil(self.bytes_per_second as u128);
        RateLimitDecision::Delayed(Duration::from_nanos(wait_nanos.min(u64::MAX as u128) as u64))
    }

    pub async fn consume(&self, bytes: u64) -> RateLimitDecision {
        loop {
            match self.try_consume(bytes) {
                RateLimitDecision::Allowed => return RateLimitDecision::Allowed,
                RateLimitDecision::Disabled => return RateLimitDecision::Disabled,
                RateLimitDecision::Delayed(delay) => tokio::time::sleep(delay).await,
            }
        }
    }

    fn refill(&self, state: &mut TokenBucketState) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(state.last_refill);
        if elapsed.is_zero() {
            return;
        }

        let added = (self.bytes_per_second as u128 * elapsed.as_nanos() / NANOS_PER_SECOND) as u64;
        if added > 0 {
            state.tokens = state.tokens.saturating_add(added).min(self.capacity);
            state.last_refill = now;
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BandwidthLimiter {
    upload: Option<Arc<TokenBucket>>,
    download: Option<Arc<TokenBucket>>,
}

impl BandwidthLimiter {
    pub fn new(upload: Option<BandwidthLimit>, download: Option<BandwidthLimit>) -> Self {
        Self {
            upload: upload.map(TokenBucket::new).map(Arc::new),
            download: download.map(TokenBucket::new).map(Arc::new),
        }
    }

    pub fn try_consume(&self, direction: RateLimitDirection, bytes: u64) -> RateLimitDecision {
        match direction {
            RateLimitDirection::Upload => self.upload.as_ref(),
            RateLimitDirection::Download => self.download.as_ref(),
        }
        .map(|bucket| bucket.try_consume(bytes))
        .unwrap_or(RateLimitDecision::Allowed)
    }

    pub async fn consume(&self, direction: RateLimitDirection, bytes: u64) -> RateLimitDecision {
        let bucket = match direction {
            RateLimitDirection::Upload => self.upload.as_ref(),
            RateLimitDirection::Download => self.download.as_ref(),
        };

        match bucket {
            Some(bucket) => bucket.consume(bytes).await,
            None => RateLimitDecision::Allowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_initial_burst() {
        let bucket = TokenBucket::new(BandwidthLimit::with_burst(1, MIN_BURST_BYTES));
        assert_eq!(
            bucket.try_consume(MIN_BURST_BYTES),
            RateLimitDecision::Allowed
        );
        assert!(matches!(
            bucket.try_consume(1),
            RateLimitDecision::Delayed(_)
        ));
    }

    #[test]
    fn zero_rate_is_disabled() {
        let bucket = TokenBucket::new(BandwidthLimit::new(0));
        assert_eq!(bucket.try_consume(1), RateLimitDecision::Disabled);
    }
}
