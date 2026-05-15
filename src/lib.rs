// This library shares code with the shoes binary. Server-side code appears "unused"
// in lib builds but is used by the binary for server mode.
// The client/server code is intermingled within modules - a proper fix would require
// splitting into separate client/server modules or using feature flags.
#![allow(dead_code)]

//! shoes - A high-performance multi-protocol proxy server.
//!
//! This library provides the core functionality for shoes.
//!
//! # Features
//!
//! - **Multi-protocol support**: VLESS, VMess, Trojan, Shadowsocks, and more
//! - **TUN device support**: Virtual network interface for VPN mode
//! - **Proxy chaining**: Connect through multiple proxies
//! - **Flexible routing**: Rule-based traffic routing
//!
//! # Platform Support
//!
//! - Linux (x86_64, aarch64)

// Modules are declared here (mirroring main.rs) so the library crate can share
// implementation with the binary.
mod client;
mod crypto;
pub mod dns;
mod io;
mod mux;
mod net;
mod proxy;
mod routing;
mod runtime;
mod security;
mod support;
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

/// Configuration types.
pub mod config;

/// Multi-output logging infrastructure.
pub mod logging;

/// TUN device support for VPN mode.
#[cfg(unix)]
pub mod tun;
