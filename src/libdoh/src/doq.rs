use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _, Result};
use bytes::{BufMut, BytesMut};
use quiche::{Connection, ConnectionId, Header, RecvInfo};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::globals::Globals;
use crate::dns;

const MIN_DNS_PACKET_LEN: usize = 12;

#[derive(Clone, Debug)]
struct DnsResponse {
    packet: Vec<u8>,
    ttl: u32,
}

const MAX_DATAGRAM_SIZE: usize = 1350;
const MAX_PENDING_DNS: usize = 1000;
const DEFAULT_IDLE_TIMEOUT: u64 = 30000;

pub struct DoQServer {
    globals: Arc<Globals>,
    connections: Arc<Mutex<HashMap<ConnectionId<'static>, ClientConnection>>>,
    pending_dns: Arc<Mutex<HashMap<u64, PendingQuery>>>,
    next_query_id: Arc<Mutex<u64>>,
    rng: SystemRandom,
}

struct ClientConnection {
    conn: Connection,
    client_addr: SocketAddr,
    last_activity: Instant,
}

struct PendingQuery {
    stream_id: u64,
    conn_id: ConnectionId<'static>,
    query: Vec<u8>,
    created_at: Instant,
}

impl DoQServer {
    pub fn new(globals: Arc<Globals>) -> Result<Self> {
        // Validate TLS certificates are available
        #[cfg(feature = "tls")]
        {
            if globals.tls_cert_path.is_none() || globals.tls_cert_key_path.is_none() {
                return Err(anyhow!("TLS certificates required for DoQ. Use --tls-cert-path and --tls-cert-key-path"));
            }
        }

        #[cfg(not(feature = "tls"))]
        {
            return Err(anyhow!("DoQ requires TLS support. Build with default features enabled"));
        }

        Ok(DoQServer {
            globals,
            connections: Arc::new(Mutex::new(HashMap::new())),
            pending_dns: Arc::new(Mutex::new(HashMap::new())),
            next_query_id: Arc::new(Mutex::new(0)),
            rng: SystemRandom::new(),
        })
    }

    fn create_config(&self) -> Result<quiche::Config> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

        // Configure QUIC parameters
        config.set_application_protos(&[b"doq"])?;
        config.set_max_idle_timeout(self.globals.doq_idle_timeout * 1000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(0);
        config.set_disable_active_migration(true);

        // Load TLS certificates
        #[cfg(feature = "tls")]
        {
            if let (Some(cert_path), Some(key_path)) =
                (self.globals.tls_cert_path.as_ref(), self.globals.tls_cert_key_path.as_ref())
            {
                config.load_cert_chain_from_pem_file(&cert_path.to_string_lossy())
                    .with_context(|| format!("Failed to load certificate chain from {:?}", cert_path))?;
                config.load_priv_key_from_pem_file(&key_path.to_string_lossy())
                    .with_context(|| format!("Failed to load private key from {:?}", key_path))?;
            }
        }

        config.enable_early_data();
        Ok(config)
    }

    pub async fn run(self, bind_addr: SocketAddr) -> Result<()> {
        let socket = UdpSocket::bind(bind_addr).await?;
        println!("DoQ server listening on {}", bind_addr);

        let mut buf = vec![0u8; 65535];
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];

        loop {
            // Try to receive a packet
            let (len, from) = match timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    eprintln!("DoQ recv error: {}", e);
                    continue;
                }
                Err(_) => {
                    // Timeout - process existing connections
                    self.process_connections(&socket, &mut out).await;
                    self.cleanup_connections().await;
                    continue;
                }
            };

            let pkt_buf = &buf[..len];

            // Parse QUIC header
            let mut pkt_buf_copy = pkt_buf.to_vec();
            let hdr = match Header::from_slice(&mut pkt_buf_copy, quiche::MAX_CONN_ID_LEN) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Failed to parse QUIC header: {}", e);
                    continue;
                }
            };

            let conn_id = ConnectionId::from_vec(hdr.dcid.to_vec());

            // Handle the packet
            self.handle_packet(&socket, conn_id, pkt_buf, from, &mut out).await;

            // Process connections
            self.process_connections(&socket, &mut out).await;

            // Cleanup old connections
            self.cleanup_connections().await;
        }
    }

    async fn handle_packet(
        &self,
        socket: &UdpSocket,
        conn_id: ConnectionId<'static>,
        pkt_buf: &[u8],
        from: SocketAddr,
        out: &mut [u8],
    ) {
        let mut connections = self.connections.lock().await;

        // Get or create connection
        let conn = if !connections.contains_key(&conn_id) {
            // Parse header to check if it's an Initial packet
            let mut pkt_buf_copy = pkt_buf.to_vec();
            let hdr = match Header::from_slice(&mut pkt_buf_copy, quiche::MAX_CONN_ID_LEN) {
                Ok(v) => v,
                Err(_) => return,
            };

            if hdr.ty != quiche::Type::Initial {
                return;
            }

            if connections.len() >= self.globals.max_clients {
                eprintln!("DoQ: Max clients reached, rejecting connection");
                return;
            }

            // Generate server connection ID
            let mut scid = [0; quiche::MAX_CONN_ID_LEN];
            self.rng.fill(&mut scid).ok();
            let scid = ConnectionId::from_vec(scid.to_vec());

            // Accept new connection
            let local_addr = socket.local_addr().unwrap();
            let mut config = match self.create_config() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to create QUIC config: {}", e);
                    return;
                }
            };
            let conn = match quiche::accept(&scid, None, local_addr, from, &mut config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to accept QUIC connection: {}", e);
                    return;
                }
            };

            connections.insert(
                conn_id.clone(),
                ClientConnection {
                    conn,
                    client_addr: from,
                    last_activity: Instant::now(),
                },
            );

            &mut connections.get_mut(&conn_id).unwrap().conn
        } else {
            &mut connections.get_mut(&conn_id).unwrap().conn
        };

        // Process the packet
        let recv_info = RecvInfo {
            from,
            to: socket.local_addr().unwrap(),
        };

        let mut pkt_buf_copy = pkt_buf.to_vec();
        match conn.recv(&mut pkt_buf_copy, recv_info) {
            Ok(_) => {}
            Err(quiche::Error::Done) => {}
            Err(e) => {
                eprintln!("QUIC recv error: {:?}", e);
                connections.remove(&conn_id);
                return;
            }
        }

        // Update last activity
        if let Some(client) = connections.get_mut(&conn_id) {
            client.last_activity = Instant::now();
        }

        // Process readable streams
        self.process_streams(&conn_id, &mut connections).await;

        // Send pending data
        self.send_pending(socket, &conn_id, from, out, &mut connections).await;
    }

    async fn process_streams(
        &self,
        conn_id: &ConnectionId<'static>,
        connections: &mut HashMap<ConnectionId<'static>, ClientConnection>,
    ) {
        let conn = match connections.get_mut(conn_id) {
            Some(c) => &mut c.conn,
            None => return,
        };

        let readable: Vec<u64> = conn.readable().collect();

        for stream_id in readable {
            let mut buf = vec![0; 4096];

            match conn.stream_recv(stream_id, &mut buf) {
                Ok((read, fin)) => {
                    if read >= 2 {
                        // Parse DNS message length prefix (2 bytes, big-endian)
                        let msg_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;

                        if read >= msg_len + 2 && msg_len > 0 {
                            let dns_query = buf[2..msg_len + 2].to_vec();

                            // Process DNS query asynchronously
                            let globals = self.globals.clone();
                            let conn_id_clone = conn_id.clone();
                            let pending_dns = self.pending_dns.clone();
                            let next_query_id = self.next_query_id.clone();

                            tokio::spawn(async move {
                                // Process DNS query by sending to upstream DNS server
                                match process_dns_query(&globals, &dns_query).await {
                                    Ok(response) => {
                                        let mut query_id = next_query_id.lock().await;
                                        let id = *query_id;
                                        *query_id = query_id.wrapping_add(1);
                                        drop(query_id);

                                        let mut pending = pending_dns.lock().await;
                                        pending.insert(id, PendingQuery {
                                            stream_id,
                                            conn_id: conn_id_clone,
                                            query: response.packet,
                                            created_at: Instant::now(),
                                        });
                                    }
                                    Err(e) => {
                                        eprintln!("DNS query processing failed: {}", e);
                                    }
                                }
                            });
                        }
                    }

                    if fin {
                        let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0);
                    }
                }
                Err(quiche::Error::Done) => {}
                Err(_) => {
                    let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0);
                }
            }
        }
    }

    async fn process_connections(&self, socket: &UdpSocket, out: &mut [u8]) {
        let mut connections = self.connections.lock().await;
        let mut pending_dns = self.pending_dns.lock().await;

        // Process pending DNS responses
        for (_query_id, pending) in pending_dns.iter() {
            if let Some(client) = connections.get_mut(&pending.conn_id) {
                // Frame the DNS response with 2-byte length prefix
                let mut response_buf = BytesMut::with_capacity(pending.query.len() + 2);
                response_buf.put_u16(pending.query.len() as u16);
                response_buf.put_slice(&pending.query);

                // Send response on the same stream
                match client.conn.stream_send(pending.stream_id, &response_buf, true) {
                    Ok(written) => {
                        if written == response_buf.len() {
                            // Successfully sent, mark for removal
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to send DNS response on stream {}: {:?}", pending.stream_id, e);
                    }
                }
            }
        }

        // Remove processed queries
        pending_dns.retain(|_, pending| {
            if let Some(client) = connections.get(&pending.conn_id) {
                !client.conn.stream_finished(pending.stream_id)
            } else {
                false
            }
        });

        // Send pending QUIC packets for all connections
        let conn_ids: Vec<_> = connections.keys().cloned().collect();
        for conn_id in conn_ids {
            if let Some(client) = connections.get(&conn_id) {
                let to = client.client_addr;
                self.send_pending(socket, &conn_id, to, out, &mut connections).await;
            }
        }
    }

    async fn send_pending(
        &self,
        socket: &UdpSocket,
        conn_id: &ConnectionId<'static>,
        to: SocketAddr,
        out: &mut [u8],
        connections: &mut HashMap<ConnectionId<'static>, ClientConnection>,
    ) {
        let conn = match connections.get_mut(conn_id) {
            Some(c) => &mut c.conn,
            None => return,
        };

        loop {
            let (write, _send_info) = match conn.send(out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    eprintln!("QUIC send error: {:?}", e);
                    break;
                }
            };

            if let Err(e) = socket.send_to(&out[..write], to).await {
                eprintln!("Failed to send QUIC packet: {}", e);
                break;
            }
        }
    }

    async fn cleanup_connections(&self) {
        let now = Instant::now();
        let timeout = Duration::from_secs(self.globals.doq_idle_timeout);

        let mut connections = self.connections.lock().await;
        connections.retain(|_, client| {
            now.duration_since(client.last_activity) < timeout
        });

        let mut pending_dns = self.pending_dns.lock().await;
        pending_dns.retain(|_, query| {
            now.duration_since(query.created_at) < Duration::from_secs(10)
        });
    }
}

async fn process_dns_query(globals: &Arc<Globals>, query: &[u8]) -> Result<DnsResponse> {
    let mut packet = vec![0u8; 4096];

    // UDP transaction
    let socket = UdpSocket::bind(&globals.local_bind_address)
        .await
        .map_err(|e| anyhow!("Failed to bind UDP socket: {}", e))?;

    socket
        .send_to(&query, &globals.server_address)
        .await
        .map_err(|e| anyhow!("Failed to send DNS query: {}", e))?;

    let (len, response_server_address) = timeout(
        globals.timeout,
        socket.recv_from(&mut packet)
    )
    .await
    .map_err(|_| anyhow!("DNS query timeout"))?
    .map_err(|e| anyhow!("Failed to receive DNS response: {}", e))?;

    if len < MIN_DNS_PACKET_LEN || globals.server_address != response_server_address {
        return Err(anyhow!("Invalid DNS response"));
    }

    packet.truncate(len);

    // Calculate TTL from response
    let ttl = if dns::rcode(&packet) == 0 && dns::ancount(&packet) > 0 {
        dns::min_ttl(&packet, globals.min_ttl, globals.max_ttl, globals.err_ttl)
            .unwrap_or(globals.err_ttl)
    } else {
        globals.err_ttl
    };

    Ok(DnsResponse { packet, ttl })
}

pub async fn start_doq_server(globals: Arc<Globals>) -> Result<()> {
    if !globals.enable_doq {
        return Ok(());
    }

    let bind_addr = SocketAddr::new(
        globals.listen_address.ip(),
        globals.doq_port,
    );

    println!("Starting DoQ server on UDP port {}", bind_addr);

    let server = DoQServer::new(globals)?;
    server.run(bind_addr).await
}