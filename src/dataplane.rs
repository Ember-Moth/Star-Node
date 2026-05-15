//! Data plane lifecycle API.
//!
//! The embedding control plane owns the Tokio runtime, configuration source,
//! process lifecycle, and reporting. This module only validates configs and
//! starts/stops proxy listeners.

use std::io;

use tokio::task::JoinHandle;

use crate::config::{self, Config};
use crate::thread_util;
use crate::transport::tcp::tcp_server::start_servers;

/// Runtime hints used by the data plane.
///
/// The crate does not create a Tokio runtime. `num_threads` is only used for
/// internal auto-sizing, primarily QUIC endpoint counts, and should normally
/// match the worker count chosen by the embedding control plane.
#[derive(Debug, Clone, Copy, Default)]
pub struct DataPlaneOptions {
    pub num_threads: Option<usize>,
}

impl DataPlaneOptions {
    pub fn with_num_threads(num_threads: usize) -> Self {
        Self {
            num_threads: Some(num_threads),
        }
    }
}

/// Running proxy data plane.
#[derive(Debug)]
pub struct DataPlane {
    join_handles: Vec<JoinHandle<()>>,
}

impl DataPlane {
    /// Validate configs and start all configured server listeners.
    pub async fn start(configs: Vec<Config>) -> io::Result<Self> {
        Self::start_with_options(configs, DataPlaneOptions::default()).await
    }

    /// Validate configs and start all configured server listeners with runtime hints.
    pub async fn start_with_options(
        configs: Vec<Config>,
        options: DataPlaneOptions,
    ) -> io::Result<Self> {
        let join_handles = start_join_handles(configs, options).await?;
        Ok(Self { join_handles })
    }

    /// Stop current listeners, then start from a new config set.
    pub async fn reload(&mut self, configs: Vec<Config>) -> io::Result<()> {
        self.reload_with_options(configs, DataPlaneOptions::default())
            .await
    }

    /// Stop current listeners, then start from a new config set with runtime hints.
    pub async fn reload_with_options(
        &mut self,
        configs: Vec<Config>,
        options: DataPlaneOptions,
    ) -> io::Result<()> {
        self.shutdown().await;
        *self = Self::start_with_options(configs, options).await?;
        Ok(())
    }

    /// Abort all running listener tasks and wait until they are cancelled.
    pub async fn shutdown(&mut self) {
        abort_join_handles(std::mem::take(&mut self.join_handles)).await;
    }

    pub fn listener_count(&self) -> usize {
        self.join_handles.len()
    }

    pub fn is_running(&self) -> bool {
        !self.join_handles.is_empty()
    }
}

impl Drop for DataPlane {
    fn drop(&mut self) {
        for join_handle in &self.join_handles {
            join_handle.abort();
        }
    }
}

/// Configure the data plane's worker hint once.
///
/// This does not create or resize a Tokio runtime. It only controls internal
/// sizing decisions that need to know the runtime worker count.
pub fn configure_worker_threads(num_threads: usize) -> io::Result<()> {
    if num_threads == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "num_threads must be greater than zero",
        ));
    }

    match thread_util::try_set_num_threads(num_threads) {
        Ok(()) => Ok(()),
        Err(existing) if existing == num_threads => Ok(()),
        Err(existing) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("worker thread hint is already configured as {existing}"),
        )),
    }
}

/// Return the current worker hint, initializing it to the platform default if needed.
pub fn worker_threads() -> usize {
    thread_util::get_num_threads()
}

/// Validate configs and return the expanded startable server configs.
pub fn validate_configs(configs: Vec<Config>) -> io::Result<config::ValidatedConfigs> {
    config::create_server_configs(configs)
}

async fn start_join_handles(
    configs: Vec<Config>,
    options: DataPlaneOptions,
) -> io::Result<Vec<JoinHandle<()>>> {
    if let Some(num_threads) = options.num_threads {
        configure_worker_threads(num_threads)?;
    }

    let config::ValidatedConfigs {
        configs: server_configs,
        dns_groups,
    } = config::create_server_configs(configs)?;

    let mut dns_registry = crate::dns::build_dns_registry(dns_groups).await?;
    let mut join_handles = Vec::new();

    for server_config in server_configs {
        let dns_ref = match &server_config {
            Config::Server(config) => config.dns.as_ref(),
            _ => None,
        };
        let resolver = dns_registry.get_for_server(dns_ref);

        match start_servers(server_config, resolver).await {
            Ok(mut handles) => join_handles.append(&mut handles),
            Err(err) => {
                abort_join_handles(join_handles).await;
                return Err(err);
            }
        }
    }

    Ok(join_handles)
}

async fn abort_join_handles(join_handles: Vec<JoinHandle<()>>) {
    for join_handle in &join_handles {
        join_handle.abort();
    }

    for join_handle in join_handles {
        let _ = join_handle.await;
    }
}
