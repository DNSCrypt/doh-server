use anyhow::{ensure, Error};
use byteorder::{BigEndian, ByteOrder};
use std::net::IpAddr;

// EDNS0 option code for Client Subnet
const EDNS_CLIENT_SUBNET: u16 = 8;

// Address family constants
const FAMILY_IPV4: u16 = 1;
const FAMILY_IPV6: u16 = 2;

/// Extract client IP from HTTP headers
/// Checks X-Forwarded-For, X-Real-IP, and falls back to remote address
pub fn extract_client_ip(
    headers: &hyper::HeaderMap,
    remote_addr: Option<std::net::SocketAddr>,
) -> Option<IpAddr> {
    // Try X-Forwarded-For first (may contain multiple IPs)
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // Take the first IP in the list
            if let Some(first_ip) = xff_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Try X-Real-IP
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(xri_str) = xri.to_str() {
            if let Ok(ip) = xri_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    // Fall back to remote address
    remote_addr.map(|addr| addr.ip())
}

/// Build EDNS Client Subnet option data
pub fn build_ecs_option(client_ip: IpAddr, prefix_v4: u8, prefix_v6: u8) -> Vec<u8> {
    let mut option_data = Vec::new();

    match client_ip {
        IpAddr::V4(addr) => {
            // Family
            option_data.extend_from_slice(&FAMILY_IPV4.to_be_bytes());
            // Source prefix length
            option_data.push(prefix_v4);
            // Scope prefix length (0 = let resolver decide)
            option_data.push(0);
            // Address bytes (only send prefix bytes)
            let octets = addr.octets();
            let bytes_to_send = prefix_v4.div_ceil(8) as usize;
            option_data.extend_from_slice(&octets[..bytes_to_send.min(4)]);
        }
        IpAddr::V6(addr) => {
            // Family
            option_data.extend_from_slice(&FAMILY_IPV6.to_be_bytes());
            // Source prefix length
            option_data.push(prefix_v6);
            // Scope prefix length (0 = let resolver decide)
            option_data.push(0);
            // Address bytes (only send prefix bytes)
            let octets = addr.octets();
            let bytes_to_send = prefix_v6.div_ceil(8) as usize;
            option_data.extend_from_slice(&octets[..bytes_to_send.min(16)]);
        }
    }

    option_data
}

/// Add or update EDNS Client Subnet in a DNS packet
pub fn add_ecs_to_packet(
    packet: &mut Vec<u8>,
    client_ip: IpAddr,
    prefix_v4: u8,
    prefix_v6: u8,
) -> Result<(), Error> {
    use crate::dns;

    let packet_len = packet.len();
    ensure!(packet_len >= 12, "DNS packet too short");

    // Check if we already have EDNS
    let arcount = dns::arcount(packet);
    if arcount == 0 {
        // No additional records, need to add EDNS first
        dns::set_edns_max_payload_size(packet, 4096)?;
    }

    // Now find the OPT record and add ECS option
    let qdcount = dns::qdcount(packet);
    let ancount = dns::ancount(packet);
    let nscount = BigEndian::read_u16(&packet[8..10]);

    // Skip to additional section
    let mut offset = 12;

    // Skip question
    for _ in 0..qdcount {
        // Skip name
        while offset < packet_len && packet[offset] != 0 {
            if packet[offset] & 0xc0 == 0xc0 {
                offset += 2;
                break;
            }
            let len = packet[offset] as usize;
            offset += 1 + len;
        }
        if offset < packet_len && packet[offset] == 0 {
            offset += 1;
        }
        offset += 4; // type + class
    }

    // Skip answer and authority sections
    for _ in 0..(ancount + nscount) {
        offset = skip_rr(packet, offset)?;
    }

    // Find OPT record in additional section
    let mut opt_found = false;
    let _additional_start = offset;

    for _ in 0..arcount {
        let rr_start = offset;

        // Check if this is root domain (OPT record)
        if offset < packet_len && packet[offset] == 0 {
            // Check type
            if offset + 3 < packet_len {
                let rtype = BigEndian::read_u16(&packet[offset + 1..offset + 3]);
                if rtype == dns::DNS_TYPE_OPT {
                    opt_found = true;
                    // Found OPT record
                    offset += 1; // skip root domain
                    offset += 8; // skip type, class, ttl

                    if offset + 2 <= packet_len {
                        let rdlength = BigEndian::read_u16(&packet[offset..offset + 2]) as usize;
                        offset += 2;

                        // Build new ECS option
                        let ecs_data = build_ecs_option(client_ip, prefix_v4, prefix_v6);
                        let _ecs_option_len = 4 + ecs_data.len(); // 2 bytes code + 2 bytes length + data

                        // Check if we already have ECS option and remove it
                        let mut new_rdata = Vec::new();
                        let mut rdata_offset = 0;
                        while rdata_offset < rdlength {
                            if offset + rdata_offset + 4 <= packet_len {
                                let opt_code =
                                    BigEndian::read_u16(&packet[offset + rdata_offset..]);
                                let opt_len =
                                    BigEndian::read_u16(&packet[offset + rdata_offset + 2..])
                                        as usize;

                                if opt_code != EDNS_CLIENT_SUBNET {
                                    // Keep this option
                                    new_rdata.extend_from_slice(
                                        &packet[offset + rdata_offset
                                            ..offset + rdata_offset + 4 + opt_len],
                                    );
                                }
                                rdata_offset += 4 + opt_len;
                            } else {
                                break;
                            }
                        }

                        // Add our ECS option
                        new_rdata.extend_from_slice(&EDNS_CLIENT_SUBNET.to_be_bytes());
                        new_rdata.extend_from_slice(&(ecs_data.len() as u16).to_be_bytes());
                        new_rdata.extend_from_slice(&ecs_data);

                        // Update packet
                        let new_rdlength = new_rdata.len();
                        BigEndian::write_u16(&mut packet[offset - 2..], new_rdlength as u16);

                        // Save the data after the OPT record before modifying
                        let remaining_start = offset + rdlength;
                        let remaining_data = if remaining_start < packet_len {
                            packet[remaining_start..].to_vec()
                        } else {
                            Vec::new()
                        };

                        // Replace old rdata with new
                        packet.truncate(offset);
                        packet.extend_from_slice(&new_rdata);

                        // Add any remaining data after OPT record
                        if !remaining_data.is_empty() {
                            packet.extend_from_slice(&remaining_data);
                        }

                        return Ok(());
                    }
                }
            }
        }

        // Skip this RR
        offset = skip_rr(packet, rr_start)?;
    }

    if !opt_found {
        // Should have been added by set_edns_max_payload_size
        return Err(anyhow::anyhow!("Failed to find OPT record"));
    }

    Ok(())
}

fn skip_rr(packet: &[u8], mut offset: usize) -> Result<usize, Error> {
    let packet_len = packet.len();

    // Skip name
    while offset < packet_len {
        if packet[offset] & 0xc0 == 0xc0 {
            offset += 2;
            break;
        }
        if packet[offset] == 0 {
            offset += 1;
            break;
        }
        let len = packet[offset] as usize;
        offset += 1 + len;
    }

    // Skip type, class, ttl, rdlength
    ensure!(offset + 10 <= packet_len, "Incomplete RR");
    let rdlength = BigEndian::read_u16(&packet[offset + 8..offset + 10]) as usize;
    offset += 10;

    // Skip rdata
    ensure!(
        offset + rdlength <= packet_len,
        "RR data extends beyond packet"
    );
    offset += rdlength;

    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_extract_client_ip() {
        let mut headers = hyper::HeaderMap::new();

        // Test X-Forwarded-For
        headers.insert("x-forwarded-for", "192.168.1.1, 10.0.0.1".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, None),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );

        // Test X-Real-IP
        headers.clear();
        headers.insert("x-real-ip", "10.0.0.2".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, None),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
    }

    #[test]
    fn test_build_ecs_option() {
        // Test IPv4
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let data = build_ecs_option(ip, 24, 56);
        assert_eq!(data[0..2], [0, 1]); // IPv4 family
        assert_eq!(data[2], 24); // prefix length
        assert_eq!(data[3], 0); // scope
        assert_eq!(data[4..7], [192, 168, 1]); // first 3 octets

        // Test IPv6
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let data = build_ecs_option(ip, 24, 56);
        assert_eq!(data[0..2], [0, 2]); // IPv6 family
        assert_eq!(data[2], 56); // prefix length
        assert_eq!(data[3], 0); // scope
        assert_eq!(data.len(), 4 + 7); // header + 7 bytes for /56
    }
}
