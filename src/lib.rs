// 公共 API 刻意保持小而稳定；具体协议分支由数据面的配置驱动分发进入。
#![allow(dead_code)]

//! shoes - 高性能多协议代理数据面。
//!
//! 本库提供可嵌入的代理监听器生命周期管理。
//!
//! # 特性
//!
//! - **多协议支持**：VLESS、VMess、Trojan、Shadowsocks 等
//! - **代理链**：通过多个上游代理连接
//! - **灵活路由**：基于规则的流量路由
//!
//! # 平台支持
//!
//! - Linux (x86_64, aarch64)

// 内部模块默认保持私有，通过数据面 API 统一暴露。
pub mod account;
mod client;
mod crypto;
pub mod dataplane;
pub mod dns;
mod io;
mod mux;
mod net;
mod proxy;
mod routing;
mod runtime;
mod security;
pub mod session;
mod support;
pub mod telemetry;
mod transport;

pub(crate) use client::proxy_chain as client_proxy_chain;
pub(crate) use client::proxy_selector as client_proxy_selector;
pub(crate) use io::async_stream;
pub(crate) use io::buf_reader;
pub(crate) use io::copy_bidirectional;
pub(crate) use io::copy_bidirectional_message;
pub(crate) use io::slide_buffer;
pub(crate) use io::stream_reader;
pub(crate) use io::sync_adapter;
pub(crate) use mux::h2mux;
pub(crate) use net::address;
pub use net::resolver;
pub(crate) use net::socket_util;
pub(crate) use proxy::http as http_handler;
pub(crate) use proxy::hysteria2 as hysteria2_server;
pub(crate) use proxy::mixed as mixed_handler;
pub(crate) use proxy::port_forward as port_forward_handler;
pub(crate) use proxy::socks::handler as socks_handler;
pub(crate) use proxy::socks::udp_relay as socks5_udp_relay;
pub(crate) use proxy::trojan as trojan_handler;
pub(crate) use proxy::tuic as tuic_server;
pub(crate) use proxy::vless::xudp;
pub(crate) use proxy::{anytls, naiveproxy, shadowsocks, snell, vless, vmess};
pub(crate) use runtime::thread_util;
pub(crate) use security::reality;
pub(crate) use security::reality::client_handler as reality_client_handler;
pub(crate) use security::rustls_config_util;
pub(crate) use security::rustls_connection_util;
pub(crate) use security::tls::client_handler as tls_client_handler;
pub(crate) use security::tls::server_handler as tls_server_handler;
pub(crate) use support::option_util;
pub(crate) use support::util;
pub(crate) use support::uuid_util;
pub(crate) use transport::quic::server as quic_server;
pub(crate) use transport::quic::stream as quic_stream;
pub(crate) use transport::{shadow_tls, tcp, uot, websocket};

pub use dataplane::{
    DataPlane, DataPlaneOptions, DataPlaneRuntime, configure_worker_threads, validate_configs,
    worker_threads,
};

/// 配置类型。
pub mod config;

/// 多输出日志基础设施。
pub mod logging;
