//! 数据面生命周期 API。
//!
//! 嵌入方控制面负责 Tokio runtime、配置来源、进程生命周期和上报；
//! 本模块只负责校验配置并启动/停止代理监听器。

use std::io;

use tokio::task::JoinHandle;

use crate::account::{UserProfile, UserRegistry, UserRegistryError};
use crate::config::{self, Config};
use crate::session::SessionTracker;
use crate::telemetry::TrafficCollector;
use crate::thread_util;
use crate::transport::tcp::tcp_server::start_servers;

/// 数据面运行时提示。
///
/// 本 crate 不创建 Tokio runtime。`num_threads` 只用于内部自动 sizing，
/// 主要影响 QUIC endpoint 数量，通常应与控制面选择的 runtime worker 数一致。
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

/// 数据面协议 handler 共享的运行时服务。
#[derive(Debug, Clone, Default)]
pub struct DataPlaneRuntime {
    user_registry: UserRegistry,
    traffic_collector: TrafficCollector,
    session_tracker: SessionTracker,
}

impl DataPlaneRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn user_registry(&self) -> &UserRegistry {
        &self.user_registry
    }

    pub fn traffic_collector(&self) -> &TrafficCollector {
        &self.traffic_collector
    }

    pub fn session_tracker(&self) -> &SessionTracker {
        &self.session_tracker
    }

    pub fn update_users(
        &self,
        users: Vec<UserProfile>,
        revision: u64,
    ) -> Result<(), UserRegistryError> {
        self.user_registry.update_users(users, revision)
    }
}

/// 正在运行的代理数据面。
#[derive(Debug)]
pub struct DataPlane {
    join_handles: Vec<JoinHandle<()>>,
    runtime: DataPlaneRuntime,
}

impl DataPlane {
    /// 校验配置并启动所有已配置的服务端监听器。
    pub async fn start(configs: Vec<Config>) -> io::Result<Self> {
        Self::start_with_options(configs, DataPlaneOptions::default()).await
    }

    /// 使用运行时提示校验配置并启动所有已配置的服务端监听器。
    pub async fn start_with_options(
        configs: Vec<Config>,
        options: DataPlaneOptions,
    ) -> io::Result<Self> {
        Self::start_with_runtime(configs, options, DataPlaneRuntime::new()).await
    }

    /// 使用已有数据面运行时校验配置并启动所有监听器。
    pub async fn start_with_runtime(
        configs: Vec<Config>,
        options: DataPlaneOptions,
        runtime: DataPlaneRuntime,
    ) -> io::Result<Self> {
        let join_handles = start_join_handles(configs, options, runtime.clone()).await?;
        Ok(Self {
            join_handles,
            runtime,
        })
    }

    /// 停止当前监听器，然后使用新的配置集启动。
    pub async fn reload(&mut self, configs: Vec<Config>) -> io::Result<()> {
        self.reload_with_options(configs, DataPlaneOptions::default())
            .await
    }

    /// 停止当前监听器，然后使用新的配置集和运行时提示启动。
    pub async fn reload_with_options(
        &mut self,
        configs: Vec<Config>,
        options: DataPlaneOptions,
    ) -> io::Result<()> {
        self.shutdown().await;
        self.join_handles = start_join_handles(configs, options, self.runtime.clone()).await?;
        Ok(())
    }

    /// 中止所有正在运行的监听任务，并等待任务取消完成。
    pub async fn shutdown(&mut self) {
        abort_join_handles(std::mem::take(&mut self.join_handles)).await;
    }

    pub fn listener_count(&self) -> usize {
        self.join_handles.len()
    }

    pub fn is_running(&self) -> bool {
        !self.join_handles.is_empty()
    }

    pub fn runtime(&self) -> &DataPlaneRuntime {
        &self.runtime
    }

    pub fn user_registry(&self) -> &UserRegistry {
        self.runtime.user_registry()
    }

    pub fn traffic_collector(&self) -> &TrafficCollector {
        self.runtime.traffic_collector()
    }

    pub fn session_tracker(&self) -> &SessionTracker {
        self.runtime.session_tracker()
    }

    pub fn update_users(
        &self,
        users: Vec<UserProfile>,
        revision: u64,
    ) -> Result<(), UserRegistryError> {
        self.runtime.update_users(users, revision)
    }
}

impl Drop for DataPlane {
    fn drop(&mut self) {
        for join_handle in &self.join_handles {
            join_handle.abort();
        }
    }
}

/// 配置一次数据面的 worker 数提示。
///
/// 这不会创建或调整 Tokio runtime，只影响需要知道 worker 数的内部 sizing 决策。
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

/// 返回当前 worker 数提示；如尚未初始化，则使用平台默认值初始化。
pub fn worker_threads() -> usize {
    thread_util::get_num_threads()
}

/// 校验配置，并返回展开后的可启动服务端配置。
pub fn validate_configs(configs: Vec<Config>) -> io::Result<config::ValidatedConfigs> {
    config::create_server_configs(configs)
}

async fn start_join_handles(
    configs: Vec<Config>,
    options: DataPlaneOptions,
    runtime: DataPlaneRuntime,
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

        match start_servers(server_config, resolver, runtime.clone()).await {
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
