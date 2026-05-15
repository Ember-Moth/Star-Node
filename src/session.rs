use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::account::UserId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionContext {
    pub session_id: SessionId,
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<UserId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_addr: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub started_at_ms: u64,
}

impl SessionContext {
    pub fn set_user(&mut self, user_id: impl Into<UserId>) {
        self.user_id = Some(user_id.into());
    }

    pub fn set_target(&mut self, target: impl Into<String>) {
        self.target = Some(target.into());
    }
}

#[derive(Debug, Clone)]
pub struct SessionTracker {
    next_id: Arc<AtomicU64>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn next_session_id(&self) -> SessionId {
        SessionId(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    pub fn start(
        &self,
        protocol: impl Into<String>,
        client_addr: Option<SocketAddr>,
    ) -> SessionContext {
        SessionContext {
            session_id: self.next_session_id(),
            protocol: protocol.into(),
            user_id: None,
            client_addr,
            target: None,
            started_at_ms: now_millis(),
        }
    }
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_monotonic() {
        let tracker = SessionTracker::new();
        assert_eq!(tracker.next_session_id(), SessionId(1));
        assert_eq!(tracker.next_session_id(), SessionId(2));
    }

    #[test]
    fn session_context_can_attach_user_and_target() {
        let tracker = SessionTracker::new();
        let mut session = tracker.start("vless", None);
        session.set_user("u1");
        session.set_target("example.com:443");

        assert_eq!(session.user_id.as_deref(), Some("u1"));
        assert_eq!(session.target.as_deref(), Some("example.com:443"));
    }
}
