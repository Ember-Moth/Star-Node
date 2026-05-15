use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use crate::account::AuthenticatedUser;
use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream, AsyncTargetedMessageStream};
use crate::client_proxy_selector::ClientProxySelector;

pub enum TcpServerSetupResult {
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        authenticated_user: Option<AuthenticatedUser>,
        need_initial_flush: bool,
        /// 连接到远端成功后写回服务端流的响应。
        connection_success_response: Option<Box<[u8]>>,
        /// 需要发送到远端的初始数据。
        initial_remote_data: Option<Box<[u8]>>,
        /// 本连接使用的出站路由选择器。
        proxy_selector: Arc<ClientProxySelector>,
    },
    BidirectionalUdp {
        need_initial_flush: bool,
        remote_location: NetLocation,
        stream: Box<dyn AsyncMessageStream>,
        authenticated_user: Option<AuthenticatedUser>,
        /// 本连接使用的出站路由选择器。
        proxy_selector: Arc<ClientProxySelector>,
    },
    MultiDirectionalUdp {
        need_initial_flush: bool,
        stream: Box<dyn AsyncTargetedMessageStream>,
        authenticated_user: Option<AuthenticatedUser>,
        /// 本连接使用的出站路由选择器。
        proxy_selector: Arc<ClientProxySelector>,
    },
    SessionBasedUdp {
        need_initial_flush: bool,
        stream: Box<dyn crate::async_stream::AsyncSessionMessageStream>,
        authenticated_user: Option<AuthenticatedUser>,
        /// 本连接使用的出站路由选择器。
        proxy_selector: Arc<ClientProxySelector>,
    },
    /// 连接已被 handler 完整处理，调用方不需要继续处理。
    AlreadyHandled,
}

impl TcpServerSetupResult {
    pub fn set_need_initial_flush(&mut self, need_initial_flush: bool) {
        match self {
            TcpServerSetupResult::TcpForward {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::BidirectionalUdp {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::MultiDirectionalUdp {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::SessionBasedUdp {
                need_initial_flush: flush,
                ..
            } => {
                *flush = need_initial_flush;
            }
            TcpServerSetupResult::AlreadyHandled => {}
        }
    }
}

#[async_trait]
pub trait TcpServerHandler: Send + Sync + Debug {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult>;
}

pub struct TcpClientSetupResult {
    pub client_stream: Box<dyn AsyncStream>,
    /// 协议握手期间缓冲的早期应用数据。
    /// 只有最终目标可能返回早期数据，中间代理 hop 不应该返回。
    pub early_data: Option<Vec<u8>>,
}

#[async_trait]
pub trait TcpClientHandler: Send + Sync + Debug {
    /// 通过当前代理建立客户端连接。
    ///
    /// # 参数
    /// * `client_stream` - 到代理服务器的传输流
    /// * `remote_location` - 需要通过代理连接的目标，可能包含已解析地址以避免重复 DNS 查询。
    ///
    /// # 返回
    /// * `client_stream` - 已完成包装、可传输应用数据的流
    /// * `early_data` - 握手期间收到的早期应用数据
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult>;

    /// 返回当前 handler 是否支持 UDP-over-TCP 隧道。
    fn supports_udp_over_tcp(&self) -> bool {
        false
    }

    /// 在 TCP 连接上建立双向 UDP message stream。
    /// 仅在 `supports_udp_over_tcp()` 返回 true 时调用。
    ///
    /// # 参数
    /// * `client_stream` - 到代理服务器的传输流
    /// * `target` - UDP 包目标，可能包含已解析地址以避免重复 DNS 查询。
    ///
    /// # 返回
    /// 用于向目标收发 UDP 包的 message stream。
    async fn setup_client_udp_bidirectional(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP-over-TCP not supported by this protocol",
        ))
    }
}
