use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use byteorder::{BigEndian, ByteOrder};
use futures::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::Semaphore;

use crate::constants::*;
use crate::errors::DoHError;
use crate::resolver::{CachePolicy, DnsResponse, DoHType, Query, Resolver};
use crate::{dns, edns_ecs};

/// Forwards queries to a DNS server over UDP, and retries over TCP when the
/// response is truncated.
#[derive(Debug)]
pub struct Forwarder {
    pub server_address: SocketAddr,
    pub local_bind_address: SocketAddr,
    pub min_ttl: u32,
    pub max_ttl: u32,
    /// TTL of SERVFAIL and REFUSED responses, and of responses without records.
    pub err_ttl: u32,
    /// Adds the client address to queries, from `X-Forwarded-For` or
    /// `X-Real-IP` if present.
    pub enable_ecs: bool,
    pub ecs_prefix_v4: u8,
    pub ecs_prefix_v6: u8,
    pub(crate) tcp: Semaphore,
}

impl Forwarder {
    /// `max_tcp_connections` limits how many queries can be retried over TCP
    /// at the same time, and is at least 1.
    pub fn new(server_address: SocketAddr, max_tcp_connections: usize) -> Forwarder {
        let local_bind_address = match server_address {
            SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(s) => SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                0,
                s.flowinfo(),
                s.scope_id(),
            )),
        };
        Forwarder {
            server_address,
            local_bind_address,
            min_ttl: 10,
            max_ttl: 86400 * 7,
            err_ttl: 2,
            enable_ecs: false,
            ecs_prefix_v4: 24,
            ecs_prefix_v6: 56,
            tcp: Semaphore::new(max_tcp_connections.max(1)),
        }
    }
}

impl Resolver for Forwarder {
    async fn resolve(&self, query: Query) -> Result<DnsResponse, DoHError> {
        // Oblivious clients must stay anonymous.
        let client_ip = (self.enable_ecs && query.kind != DoHType::Oblivious)
            .then(|| edns_ecs::extract_client_ip(&query.headers, query.remote_addr));
        let mut query = query.packet;
        let _ = dns::set_edns_max_payload_size(&mut query, MAX_DNS_RESPONSE_LEN as _);
        if let Some(client_ip) = client_ip {
            if let Err(e) = edns_ecs::add_ecs_to_packet(
                &mut query,
                client_ip,
                self.ecs_prefix_v4,
                self.ecs_prefix_v6,
            ) {
                log::warn!("Failed to add EDNS Client Subnet: {}", e);
            }
        }
        let mut packet = vec![0; MAX_DNS_RESPONSE_LEN];

        {
            let socket = UdpSocket::bind(&self.local_bind_address)
                .await
                .map_err(DoHError::Io)?;
            let expected_server_address = self.server_address;
            socket
                .send_to(&query, &self.server_address)
                .map_err(DoHError::Io)
                .await?;
            let (len, response_server_address) =
                socket.recv_from(&mut packet).map_err(DoHError::Io).await?;
            if len < MIN_DNS_PACKET_LEN || expected_server_address != response_server_address {
                return Err(DoHError::UpstreamIssue);
            }
            packet.truncate(len);
        }

        if dns::is_truncated(&packet) {
            let _permit = self
                .tcp
                .acquire()
                .await
                .map_err(|_| DoHError::UpstreamIssue)?;
            let socket = match self.server_address {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }
            .map_err(DoHError::Io)?;
            let mut ext_socket = socket
                .connect(self.server_address)
                .await
                .map_err(DoHError::Io)?;
            ext_socket.set_nodelay(true).map_err(DoHError::Io)?;
            let mut binlen = [0u8, 0];
            BigEndian::write_u16(&mut binlen, query.len() as u16);
            ext_socket.write_all(&binlen).await.map_err(DoHError::Io)?;
            ext_socket.write_all(&query).await.map_err(DoHError::Io)?;
            ext_socket.flush().await.map_err(DoHError::Io)?;
            ext_socket
                .read_exact(&mut binlen)
                .await
                .map_err(DoHError::Io)?;
            let packet_len = BigEndian::read_u16(&binlen) as usize;
            if !(MIN_DNS_PACKET_LEN..=MAX_DNS_RESPONSE_LEN).contains(&packet_len) {
                return Err(DoHError::UpstreamIssue);
            }
            packet = vec![0u8; packet_len];
            ext_socket
                .read_exact(&mut packet)
                .await
                .map_err(DoHError::Io)?;
        }

        let ttl = if dns::is_recoverable_error(&packet) {
            self.err_ttl
        } else {
            match dns::min_ttl(&packet, self.min_ttl, self.max_ttl, self.err_ttl) {
                Err(_) => return Err(DoHError::UpstreamIssue),
                Ok(ttl) => ttl,
            }
        };
        dns::add_edns_padding(&mut packet)
            .map_err(|_| DoHError::TooLarge)
            .ok();
        let cache = CachePolicy {
            max_age: ttl,
            stale_if_error: Some(STALE_IF_ERROR_SECS),
            stale_while_revalidate: Some(STALE_WHILE_REVALIDATE_SECS),
            ..CachePolicy::default()
        };
        Ok(DnsResponse { packet, cache })
    }
}
