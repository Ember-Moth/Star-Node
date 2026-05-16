use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use log::debug;
use parking_lot::Mutex;
use rand::{Rng, RngExt};
use tokio::io::AsyncWriteExt;

use super::salt_checker::SaltChecker;
use super::timed_salt_checker::TimedSaltChecker;
use crate::account::ProtocolKind;
use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::dataplane::DataPlaneRuntime;
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session};
use crate::resolver::Resolver;
use crate::socks_handler::{read_location, write_location_to_vec};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::uot::{UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS, UotV1ServerStream, UotV2Stream};
use crate::util::write_all;

use super::blake3_key::Blake3Key;
use super::default_key::DefaultKey;
use super::shadowsocks_cipher::ShadowsocksCipher;
use super::shadowsocks_key::ShadowsocksKey;
use super::shadowsocks_stream::{ShadowsocksServerUserKey, ShadowsocksStream};
use super::shadowsocks_stream_type::ShadowsocksStreamType;

#[derive(Debug)]
pub struct ShadowsocksTcpHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
    aead2022: bool,
    salt_checker: Option<Arc<Mutex<dyn SaltChecker>>>,
    udp_enabled: bool,
    /// Proxy selector for server handler use. None when used as client handler.
    proxy_selector: Option<Arc<ClientProxySelector>>,
    /// DNS resolver for h2mux sessions. None when used as client handler.
    resolver: Option<Arc<dyn Resolver>>,
    runtime: Option<DataPlaneRuntime>,
}

impl ShadowsocksTcpHandler {
    /// Create a new handler for server use (with proxy_selector for routing)
    pub fn new_server(
        cipher: ShadowsocksCipher,
        password: &str,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        runtime: DataPlaneRuntime,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            aead2022: false,
            salt_checker: None,
            udp_enabled,
            proxy_selector: Some(proxy_selector),
            resolver: Some(resolver),
            runtime: Some(runtime),
        }
    }

    /// Create a new handler for client use (no proxy_selector needed)
    pub fn new_client(cipher: ShadowsocksCipher, password: &str, udp_enabled: bool) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            aead2022: false,
            salt_checker: None,
            udp_enabled,
            proxy_selector: None,
            resolver: None,
            runtime: None,
        }
    }

    /// Create a new AEAD2022 handler for server use
    pub fn new_aead2022_server(
        cipher: ShadowsocksCipher,
        key_bytes: &[u8],
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        runtime: DataPlaneRuntime,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(Blake3Key::new(
            key_bytes.to_vec().into_boxed_slice(),
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            aead2022: true,
            salt_checker: Some(Arc::new(Mutex::new(TimedSaltChecker::new(60)))),
            udp_enabled,
            proxy_selector: Some(proxy_selector),
            resolver: Some(resolver),
            runtime: Some(runtime),
        }
    }

    /// Create a new AEAD2022 handler for client use
    pub fn new_aead2022_client(
        cipher: ShadowsocksCipher,
        key_bytes: &[u8],
        udp_enabled: bool,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(Blake3Key::new(
            key_bytes.to_vec().into_boxed_slice(),
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            aead2022: true,
            salt_checker: Some(Arc::new(Mutex::new(TimedSaltChecker::new(60)))),
            udp_enabled,
            proxy_selector: None,
            resolver: None,
            runtime: None,
        }
    }

    fn dynamic_user_keys(&self) -> std::io::Result<Option<Vec<ShadowsocksServerUserKey>>> {
        let Some(runtime) = &self.runtime else {
            return Ok(None);
        };

        let snapshot = runtime.user_registry().snapshot();
        if !snapshot.has_protocol_credentials(ProtocolKind::Shadowsocks) {
            return Ok(None);
        }

        let credentials = snapshot.credentials_for_protocol(ProtocolKind::Shadowsocks);
        if credentials.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Shadowsocks user is disabled",
            ));
        }

        let mut user_keys = Vec::with_capacity(credentials.len());
        for (password, authenticated_user) in credentials {
            let key: Arc<Box<dyn ShadowsocksKey>> = if self.aead2022 {
                let key_bytes = BASE64.decode(password.as_bytes()).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid Shadowsocks AEAD2022 user key: {e}"),
                    )
                })?;
                if key_bytes.len() != self.cipher.salt_len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "invalid Shadowsocks AEAD2022 key length: expected {}, got {}",
                            self.cipher.salt_len(),
                            key_bytes.len()
                        ),
                    ));
                }
                Arc::new(Box::new(Blake3Key::new(
                    key_bytes.into_boxed_slice(),
                    self.cipher.algorithm().key_len(),
                )))
            } else {
                Arc::new(Box::new(DefaultKey::new(
                    &password,
                    self.cipher.algorithm().key_len(),
                )))
            };

            user_keys.push(ShadowsocksServerUserKey {
                key,
                authenticated_user,
            });
        }

        Ok(Some(user_keys))
    }
}

#[async_trait]
impl TcpServerHandler for ShadowsocksTcpHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Server
        } else {
            ShadowsocksStreamType::Aead
        };

        let dynamic_user_keys = self.dynamic_user_keys()?;
        let mut server_stream = ShadowsocksStream::new_with_user_keys(
            server_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            dynamic_user_keys,
            self.salt_checker.clone(),
        );

        let mut stream_reader = StreamReader::new_with_buffer_size(1024);

        // Blocks waiting for the location since the client always sends it before expecting a response.
        let remote_location = read_location(&mut server_stream, &mut stream_reader).await?;

        if self.aead2022 {
            let padding_len = stream_reader.read_u16_be(&mut server_stream).await?;

            if padding_len > 0 {
                if padding_len > 900 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid padding length: {padding_len}"),
                    ));
                }
                stream_reader
                    .read_slice(&mut server_stream, padding_len as usize)
                    .await?;
            }
        }
        let authenticated_user = server_stream.authenticated_user();

        // Checks for h2mux magic destination
        if let Address::Hostname(host) = remote_location.address()
            && host == MUX_DESTINATION_HOST
            && remote_location.port() == MUX_DESTINATION_PORT
        {
            let proxy_selector = self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler");
            let resolver = self.resolver.clone().expect("resolver required for h2mux");
            let udp_enabled = self.udp_enabled;

            let initial_data = stream_reader.unparsed_data_owned();

            tokio::spawn(async move {
                if let Err(e) = handle_h2mux_session(
                    server_stream,
                    initial_data,
                    udp_enabled,
                    proxy_selector,
                    resolver,
                )
                .await
                {
                    debug!("Shadowsocks h2mux session ended: {}", e);
                }
            });

            return Ok(TcpServerSetupResult::AlreadyHandled);
        }

        // Checks for UDP-over-TCP (UoT) magic addresses
        if let Address::Hostname(host) = remote_location.address() {
            if !self.udp_enabled && (host == UOT_V1_MAGIC_ADDRESS || host == UOT_V2_MAGIC_ADDRESS) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "UDP-over-TCP is disabled for this Shadowsocks server",
                ));
            }
            if host == UOT_V1_MAGIC_ADDRESS {
                // UoT V1: Multi-destination UDP
                // Each packet has: ATYP + address + port + length + data
                let mut uot_stream = UotV1ServerStream::new_uot(server_stream);

                // Feeds unparsed data since first UoT packet might be in same TCP segment
                let unparsed_data = stream_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    log::debug!(
                        "Shadowsocks UoT V1: feeding {} bytes of initial data",
                        unparsed_data.len()
                    );
                    uot_stream.feed_initial_data(unparsed_data);
                }

                return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                    stream: Box::new(uot_stream),
                    authenticated_user: authenticated_user.clone(),
                    need_initial_flush: false,
                    proxy_selector: self
                        .proxy_selector
                        .clone()
                        .expect("proxy_selector required for server handler"),
                });
            } else if host == UOT_V2_MAGIC_ADDRESS {
                // UoT V2: Read request header first
                // Request: isConnect(u8) + ATYP + address + port
                // Note: V2 uses SOCKS address format (0x01=IPv4, 0x03=Domain, 0x04=IPv6),
                // NOT UoT address format!
                let is_connect = stream_reader.read_u8(&mut server_stream).await?;
                log::debug!("Shadowsocks UoT V2: is_connect = {}", is_connect);

                // Reads destination address using SOCKS address format
                let destination = read_location(&mut server_stream, &mut stream_reader).await?;
                log::debug!("Shadowsocks UoT V2: destination = {:?}", destination);

                if is_connect == 1 {
                    // V2 Connect mode: Single destination, length-prefixed packets only
                    // Reuse UotV2Stream which has identical format: length(u16be) + data
                    let unparsed_data = stream_reader.unparsed_data();
                    let mut uot_v2_stream = UotV2Stream::new(server_stream);
                    if !unparsed_data.is_empty() {
                        uot_v2_stream.feed_initial_read_data(unparsed_data)?;
                    }

                    return Ok(TcpServerSetupResult::BidirectionalUdp {
                        remote_location: destination,
                        stream: Box::new(uot_v2_stream),
                        authenticated_user: authenticated_user.clone(),
                        need_initial_flush: false,
                        proxy_selector: self
                            .proxy_selector
                            .clone()
                            .expect("proxy_selector required for server handler"),
                    });
                } else {
                    // V2 Non-connect mode: Same as V1 (multi-destination)
                    let mut uot_stream = UotV1ServerStream::new_uot(server_stream);
                    let unparsed_data = stream_reader.unparsed_data();
                    if !unparsed_data.is_empty() {
                        log::debug!(
                            "Shadowsocks UoT V2 non-connect: feeding {} bytes of initial data",
                            unparsed_data.len()
                        );
                        uot_stream.feed_initial_data(unparsed_data);
                    }

                    return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                        stream: Box::new(uot_stream),
                        authenticated_user: authenticated_user.clone(),
                        need_initial_flush: false,
                        proxy_selector: self
                            .proxy_selector
                            .clone()
                            .expect("proxy_selector required for server handler"),
                    });
                }
            }
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(server_stream),
            authenticated_user,
            // Lets the IV be written when data actually arrives rather than flushing here.
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data: stream_reader.unparsed_data_owned(),
            proxy_selector: self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler"),
        })
    }
}

#[async_trait]
impl TcpClientHandler for ShadowsocksTcpHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Client
        } else {
            ShadowsocksStreamType::Aead
        };

        let mut client_stream: Box<dyn AsyncStream> = Box::new(ShadowsocksStream::new(
            client_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            self.salt_checker.clone(),
        ));

        let mut location_vec = write_location_to_vec(remote_location.location());

        if self.aead2022 {
            let location_len = location_vec.len();

            let mut rng = rand::rng();
            let padding_len: usize = rng.random_range(1..=900);
            location_vec.resize(location_len + padding_len + 2, 0);

            let padding_len_bytes = (padding_len as u16).to_be_bytes();
            location_vec[location_len..location_len + 2].copy_from_slice(&padding_len_bytes);

            rng.fill_bytes(&mut location_vec[location_len + 2..]);
        }

        write_all(&mut client_stream, &location_vec).await?;
        client_stream.flush().await?;

        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        use crate::uot::{UOT_V2_MAGIC_ADDRESS, UotV2Stream};

        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Client
        } else {
            ShadowsocksStreamType::Aead
        };

        let mut client_stream: Box<dyn AsyncStream> = Box::new(ShadowsocksStream::new(
            client_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            self.salt_checker.clone(),
        ));

        // UoT V2 connect mode: Single destination. Writes magic address first.
        let magic_location =
            NetLocation::new(Address::Hostname(UOT_V2_MAGIC_ADDRESS.to_string()), 0);
        let mut location_vec = write_location_to_vec(&magic_location);

        if self.aead2022 {
            let location_len = location_vec.len();
            let mut rng = rand::rng();
            let padding_len: usize = rng.random_range(1..=900);
            location_vec.resize(location_len + padding_len + 2, 0);
            let padding_len_bytes = (padding_len as u16).to_be_bytes();
            location_vec[location_len..location_len + 2].copy_from_slice(&padding_len_bytes);
            rng.fill_bytes(&mut location_vec[location_len + 2..]);
        }

        write_all(&mut client_stream, &location_vec).await?;

        // Writes UoT V2 request header: isConnect(1) + SOCKS address
        let mut uot_header = Vec::with_capacity(64);
        uot_header.push(1u8); // isConnect = 1 (connect mode)
        let target_bytes = write_location_to_vec(target.location());
        uot_header.extend_from_slice(&target_bytes);
        write_all(&mut client_stream, &uot_header).await?;
        client_stream.flush().await?;

        // Uses UotV2Stream for length-prefixed packets
        let message_stream = UotV2Stream::new(client_stream);

        Ok(Box::new(message_stream))
    }
}
