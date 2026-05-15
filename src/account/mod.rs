mod rate_limit;

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::uuid_util::normalize_uuid;

pub use rate_limit::{
    BandwidthLimit, BandwidthLimiter, RateLimitDecision, RateLimitDirection, TokenBucket,
};

pub type UserId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    #[serde(rename = "anytls")]
    AnyTls,
    Http,
    Hysteria2,
    #[serde(alias = "mix")]
    Mixed,
    #[serde(rename = "naiveproxy")]
    NaiveProxy,
    Shadowsocks,
    Snell,
    #[serde(alias = "socks")]
    Socks5,
    Trojan,
    Tuic,
    Vless,
    Vmess,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialKey {
    protocol: ProtocolKind,
    value: String,
}

impl CredentialKey {
    pub fn new(protocol: ProtocolKind, value: impl Into<String>) -> Self {
        Self {
            protocol,
            value: value.into(),
        }
    }

    pub fn user_password(
        protocol: ProtocolKind,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Self {
        Self::new(
            protocol,
            format!("{}\0{}", username.as_ref(), password.as_ref()),
        )
    }

    pub fn tuic(uuid: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        Self::new(
            ProtocolKind::Tuic,
            format!("{}\0{}", uuid.as_ref(), password.as_ref()),
        )
    }

    pub fn protocol(&self) -> ProtocolKind {
        self.protocol
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProtocolCredential {
    #[serde(rename = "anytls")]
    AnyTls {
        password: String,
    },
    Http {
        username: String,
        password: String,
    },
    Hysteria2 {
        password: String,
    },
    #[serde(alias = "mix")]
    Mixed {
        username: String,
        password: String,
    },
    #[serde(rename = "naiveproxy")]
    NaiveProxy {
        username: String,
        password: String,
    },
    Shadowsocks {
        password: String,
    },
    Snell {
        password: String,
    },
    #[serde(alias = "socks")]
    Socks5 {
        username: String,
        password: String,
    },
    Trojan {
        password: String,
    },
    Tuic {
        uuid: String,
        password: String,
    },
    Vless {
        uuid: String,
    },
    Vmess {
        uuid: String,
    },
}

impl ProtocolCredential {
    pub fn credential_keys(&self) -> Vec<CredentialKey> {
        match self {
            ProtocolCredential::AnyTls { password } => {
                vec![CredentialKey::new(ProtocolKind::AnyTls, password)]
            }
            ProtocolCredential::Http { username, password } => {
                vec![CredentialKey::user_password(
                    ProtocolKind::Http,
                    username,
                    password,
                )]
            }
            ProtocolCredential::Hysteria2 { password } => {
                vec![CredentialKey::new(ProtocolKind::Hysteria2, password)]
            }
            ProtocolCredential::Mixed { username, password } => {
                vec![CredentialKey::user_password(
                    ProtocolKind::Mixed,
                    username,
                    password,
                )]
            }
            ProtocolCredential::NaiveProxy { username, password } => {
                vec![CredentialKey::user_password(
                    ProtocolKind::NaiveProxy,
                    username,
                    password,
                )]
            }
            ProtocolCredential::Shadowsocks { password } => {
                vec![CredentialKey::new(ProtocolKind::Shadowsocks, password)]
            }
            ProtocolCredential::Snell { password } => {
                vec![CredentialKey::new(ProtocolKind::Snell, password)]
            }
            ProtocolCredential::Socks5 { username, password } => {
                vec![CredentialKey::user_password(
                    ProtocolKind::Socks5,
                    username,
                    password,
                )]
            }
            ProtocolCredential::Trojan { password } => {
                vec![CredentialKey::new(ProtocolKind::Trojan, password)]
            }
            ProtocolCredential::Tuic { uuid, password } => {
                vec![CredentialKey::tuic(uuid, password)]
            }
            ProtocolCredential::Vless { uuid } => {
                vec![CredentialKey::new(ProtocolKind::Vless, uuid)]
            }
            ProtocolCredential::Vmess { uuid } => {
                vec![CredentialKey::new(ProtocolKind::Vmess, uuid)]
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<BandwidthLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<BandwidthLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserProfile {
    pub id: UserId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub credentials: Vec<ProtocolCredential>,
    #[serde(default)]
    pub limits: UserLimits,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug)]
pub struct UserRuntime {
    profile: Arc<UserProfile>,
    limiter: BandwidthLimiter,
    active_connections: AtomicU32,
}

impl UserRuntime {
    fn new(profile: UserProfile) -> Self {
        let limiter = BandwidthLimiter::new(
            profile.limits.upload.clone(),
            profile.limits.download.clone(),
        );
        Self {
            profile: Arc::new(profile),
            limiter,
            active_connections: AtomicU32::new(0),
        }
    }

    pub fn profile(&self) -> &UserProfile {
        &self.profile
    }

    pub fn limiter(&self) -> &BandwidthLimiter {
        &self.limiter
    }

    pub fn active_connections(&self) -> u32 {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub fn try_open_session(self: &Arc<Self>) -> Result<UserSessionGuard, UserLimitError> {
        if !self.profile.enabled {
            return Err(UserLimitError::Disabled);
        }

        if let Some(limit) = self.profile.limits.max_connections {
            loop {
                let current = self.active_connections.load(Ordering::Relaxed);
                if current >= limit {
                    return Err(UserLimitError::TooManyConnections { limit });
                }

                if self
                    .active_connections
                    .compare_exchange_weak(
                        current,
                        current + 1,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    return Ok(UserSessionGuard {
                        user: Arc::clone(self),
                    });
                }
            }
        }

        self.active_connections.fetch_add(1, Ordering::AcqRel);
        Ok(UserSessionGuard {
            user: Arc::clone(self),
        })
    }
}

#[derive(Debug)]
pub struct UserSessionGuard {
    user: Arc<UserRuntime>,
}

impl UserSessionGuard {
    pub fn user(&self) -> &Arc<UserRuntime> {
        &self.user
    }
}

impl Drop for UserSessionGuard {
    fn drop(&mut self) {
        self.user.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: UserId,
    pub revision: u64,
    runtime: Arc<UserRuntime>,
}

impl AuthenticatedUser {
    fn new(user_id: UserId, revision: u64, runtime: Arc<UserRuntime>) -> Self {
        Self {
            user_id,
            revision,
            runtime,
        }
    }

    pub fn profile(&self) -> &UserProfile {
        self.runtime.profile()
    }

    pub fn runtime(&self) -> &Arc<UserRuntime> {
        &self.runtime
    }

    pub fn try_open_session(&self) -> Result<UserSessionGuard, UserLimitError> {
        self.runtime.try_open_session()
    }
}

#[derive(Debug, Clone)]
pub struct UserSnapshot {
    revision: u64,
    users: HashMap<UserId, Arc<UserRuntime>>,
    credentials: HashMap<CredentialKey, UserId>,
}

impl UserSnapshot {
    pub fn empty() -> Self {
        Self {
            revision: 0,
            users: HashMap::new(),
            credentials: HashMap::new(),
        }
    }

    pub fn from_users(users: Vec<UserProfile>, revision: u64) -> Result<Self, UserRegistryError> {
        let mut runtimes = HashMap::with_capacity(users.len());
        let mut credentials = HashMap::new();

        for profile in users {
            if profile.id.is_empty() {
                return Err(UserRegistryError::EmptyUserId);
            }

            if runtimes.contains_key(&profile.id) {
                return Err(UserRegistryError::DuplicateUserId {
                    user_id: profile.id,
                });
            }

            for credential in &profile.credentials {
                for key in credential.credential_keys() {
                    let key = normalize_credential_key(key).map_err(|reason| {
                        UserRegistryError::InvalidCredential {
                            user_id: profile.id.clone(),
                            protocol: reason.protocol,
                            reason: reason.reason,
                        }
                    })?;
                    if let Some(existing_user_id) =
                        credentials.insert(key.clone(), profile.id.clone())
                    {
                        return Err(UserRegistryError::DuplicateCredential {
                            protocol: key.protocol(),
                            existing_user_id,
                            user_id: profile.id,
                        });
                    }
                }
            }

            let runtime = Arc::new(UserRuntime::new(profile));
            runtimes.insert(runtime.profile.id.clone(), runtime);
        }

        Ok(Self {
            revision,
            users: runtimes,
            credentials,
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }

    pub fn has_protocol_credentials(&self, protocol: ProtocolKind) -> bool {
        self.credentials.keys().any(|key| key.protocol == protocol)
    }

    pub fn credentials_for_protocol(
        &self,
        protocol: ProtocolKind,
    ) -> Vec<(String, AuthenticatedUser)> {
        self.credentials
            .iter()
            .filter_map(|(key, user_id)| {
                if key.protocol != protocol {
                    return None;
                }

                let runtime = self.users.get(user_id)?;
                if !runtime.profile.enabled {
                    return None;
                }

                Some((
                    key.value.clone(),
                    AuthenticatedUser::new(user_id.clone(), self.revision, Arc::clone(runtime)),
                ))
            })
            .collect()
    }

    pub fn get_user(&self, user_id: &str) -> Option<Arc<UserRuntime>> {
        self.users.get(user_id).cloned()
    }

    pub fn authenticate(&self, key: &CredentialKey) -> Option<AuthenticatedUser> {
        let user_id = self.credentials.get(key)?;
        let runtime = self.users.get(user_id)?;
        if !runtime.profile.enabled {
            return None;
        }

        Some(AuthenticatedUser::new(
            user_id.clone(),
            self.revision,
            Arc::clone(runtime),
        ))
    }

    pub fn authenticate_protocol(
        &self,
        protocol: ProtocolKind,
        credential: impl Into<String>,
    ) -> Option<AuthenticatedUser> {
        let credential = normalize_credential_value(protocol, credential.into()).ok()?;
        self.authenticate(&CredentialKey::new(protocol, credential))
    }
}

struct NormalizedCredentialError {
    protocol: ProtocolKind,
    reason: String,
}

fn normalize_credential_key(
    key: CredentialKey,
) -> Result<CredentialKey, NormalizedCredentialError> {
    let protocol = key.protocol;
    let value =
        normalize_credential_value(protocol, key.value).map_err(|e| NormalizedCredentialError {
            protocol,
            reason: e.reason,
        })?;
    Ok(CredentialKey::new(protocol, value))
}

fn normalize_credential_value(
    protocol: ProtocolKind,
    value: String,
) -> Result<String, NormalizedCredentialError> {
    match protocol {
        ProtocolKind::Vless | ProtocolKind::Vmess => {
            normalize_uuid(&value).map_err(|e| NormalizedCredentialError {
                protocol,
                reason: e.to_string(),
            })
        }
        _ => Ok(value),
    }
}

impl Default for UserSnapshot {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Clone)]
pub struct UserRegistry {
    snapshot: Arc<RwLock<Arc<UserSnapshot>>>,
}

impl UserRegistry {
    pub fn new() -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(Arc::new(UserSnapshot::empty()))),
        }
    }

    pub fn replace_snapshot(&self, snapshot: UserSnapshot) {
        *self.snapshot.write() = Arc::new(snapshot);
    }

    pub fn update_users(
        &self,
        users: Vec<UserProfile>,
        revision: u64,
    ) -> Result<(), UserRegistryError> {
        self.replace_snapshot(UserSnapshot::from_users(users, revision)?);
        Ok(())
    }

    pub fn snapshot(&self) -> Arc<UserSnapshot> {
        Arc::clone(&self.snapshot.read())
    }

    pub fn authenticate(
        &self,
        protocol: ProtocolKind,
        credential: impl Into<String>,
    ) -> Option<AuthenticatedUser> {
        self.snapshot().authenticate_protocol(protocol, credential)
    }

    pub fn has_protocol_credentials(&self, protocol: ProtocolKind) -> bool {
        self.snapshot().has_protocol_credentials(protocol)
    }

    pub fn credentials_for_protocol(
        &self,
        protocol: ProtocolKind,
    ) -> Vec<(String, AuthenticatedUser)> {
        self.snapshot().credentials_for_protocol(protocol)
    }

    pub fn authenticate_user_password(
        &self,
        protocol: ProtocolKind,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Option<AuthenticatedUser> {
        let key = CredentialKey::user_password(protocol, username, password);
        self.snapshot().authenticate(&key)
    }

    pub fn authenticate_tuic(
        &self,
        uuid: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Option<AuthenticatedUser> {
        let key = CredentialKey::tuic(uuid, password);
        self.snapshot().authenticate(&key)
    }
}

impl Default for UserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserRegistryError {
    EmptyUserId,
    DuplicateUserId {
        user_id: UserId,
    },
    InvalidCredential {
        user_id: UserId,
        protocol: ProtocolKind,
        reason: String,
    },
    DuplicateCredential {
        protocol: ProtocolKind,
        existing_user_id: UserId,
        user_id: UserId,
    },
}

impl fmt::Display for UserRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserRegistryError::EmptyUserId => write!(f, "user id must not be empty"),
            UserRegistryError::DuplicateUserId { user_id } => {
                write!(f, "duplicate user id: {user_id}")
            }
            UserRegistryError::InvalidCredential {
                user_id,
                protocol,
                reason,
            } => write!(
                f,
                "invalid credential for {protocol:?} user {user_id}: {reason}"
            ),
            UserRegistryError::DuplicateCredential {
                protocol,
                existing_user_id,
                user_id,
            } => write!(
                f,
                "duplicate credential for {protocol:?}: user {user_id} conflicts with {existing_user_id}"
            ),
        }
    }
}

impl std::error::Error for UserRegistryError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserLimitError {
    Disabled,
    TooManyConnections { limit: u32 },
}

impl fmt::Display for UserLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserLimitError::Disabled => write!(f, "user is disabled"),
            UserLimitError::TooManyConnections { limit } => {
                write!(f, "user reached max connection limit: {limit}")
            }
        }
    }
}

impl std::error::Error for UserLimitError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn vless_user(id: &str, uuid: &str) -> UserProfile {
        UserProfile {
            id: id.to_string(),
            name: None,
            enabled: true,
            credentials: vec![ProtocolCredential::Vless {
                uuid: uuid.to_string(),
            }],
            limits: UserLimits::default(),
            tags: vec![],
        }
    }

    const UUID_1: &str = "550e8400-e29b-41d4-a716-446655440000";
    const UUID_1_COMPACT: &str = "550e8400e29b41d4a716446655440000";
    const UUID_2: &str = "660e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn authenticates_from_current_snapshot() {
        let registry = UserRegistry::new();
        registry
            .update_users(vec![vless_user("u1", UUID_1_COMPACT)], 7)
            .unwrap();

        let user = registry
            .authenticate(ProtocolKind::Vless, UUID_1)
            .expect("user should authenticate");

        assert_eq!(user.user_id, "u1");
        assert_eq!(user.revision, 7);
    }

    #[test]
    fn rejects_duplicate_credentials() {
        let result = UserSnapshot::from_users(
            vec![vless_user("u1", UUID_1), vless_user("u2", UUID_1_COMPACT)],
            1,
        );

        assert!(matches!(
            result,
            Err(UserRegistryError::DuplicateCredential { .. })
        ));
    }

    #[test]
    fn enforces_connection_limit() {
        let mut user = vless_user("u1", UUID_1);
        user.limits.max_connections = Some(1);

        let snapshot = UserSnapshot::from_users(vec![user], 1).unwrap();
        let authenticated = snapshot
            .authenticate_protocol(ProtocolKind::Vless, UUID_1_COMPACT)
            .unwrap();

        let guard = authenticated.try_open_session().unwrap();
        assert!(matches!(
            authenticated.try_open_session(),
            Err(UserLimitError::TooManyConnections { limit: 1 })
        ));
        drop(guard);
        assert!(authenticated.try_open_session().is_ok());
    }

    #[test]
    fn exposes_credentials_by_protocol() {
        let snapshot =
            UserSnapshot::from_users(vec![vless_user("u1", UUID_1), vless_user("u2", UUID_2)], 1)
                .unwrap();

        let mut credentials = snapshot
            .credentials_for_protocol(ProtocolKind::Vless)
            .into_iter()
            .map(|(credential, user)| (credential, user.user_id))
            .collect::<Vec<_>>();
        credentials.sort();

        assert_eq!(
            credentials,
            vec![
                (UUID_1.to_string(), "u1".to_string()),
                (UUID_2.to_string(), "u2".to_string()),
            ]
        );
    }
}
