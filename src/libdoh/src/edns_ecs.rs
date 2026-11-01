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
pub fn extract_client_ip(headers: &hyper::HeaderMap, remote_addr: std::net::SocketAddr) -> IpAddr {
    // Try X-Forwarded-For first (may contain multiple IPs)
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // Take the first IP in the list
            if let Some(first_ip) = xff_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // Try X-Real-IP
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(xri_str) = xri.to_str() {
            if let Ok(ip) = xri_str.parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // Fall back to remote address
    remote_addr.ip()
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
/// Note: This function assumes an EDNS OPT record is already present in the packet.
/// Call dns::set_edns_max_payload_size() first if the packet might not have one.
pub fn add_ecs_to_packet(
    packet: &mut Vec<u8>,
    client_ip: IpAddr,
    prefix_v4: u8,
    prefix_v6: u8,
) -> Result<(), Error> {
    use crate::dns;

    let packet_len = packet.len();
    ensure!(packet_len >= 12, "DNS packet too short");
    ensure!(packet_len <= 4096, "Packet too large");
    ensure!(dns::qdcount(packet) == 1, "No question");

    // Skip question section using dns.rs function
    let mut offset = dns::skip_name(packet, 12)?;
    ensure!(packet_len - offset >= 4, "Short packet");
    offset += 4; // Skip QTYPE and QCLASS

    // Get record counts
    let ancount = dns::ancount(packet);
    let nscount = BigEndian::read_u16(&packet[8..10]);
    let arcount = dns::arcount(packet);

    ensure!(arcount > 0, "No EDNS OPT record found");

    // Skip answer and authority sections using dns.rs traverse function
    offset = dns::traverse_rrs(packet, offset, ancount as usize + nscount as usize, |_| {
        Ok(())
    })?;

    // Find and update the OPT record in the additional section
    let mut opt_record_info: Option<(usize, usize, usize)> = None; // (start, rdlength_offset, rdlength)

    for _ in 0..arcount {
        let rr_start = offset;

        // Check if this is the root domain (OPT record has name = 0)
        if offset + 11 <= packet_len && packet[offset] == 0 {
            let rtype = BigEndian::read_u16(&packet[offset + 1..offset + 3]);
            if rtype == dns::DNS_TYPE_OPT {
                let rdlength_offset = offset + 9; // After name(1) + type(2) + class(2) + ttl(4)
                let rdlength =
                    BigEndian::read_u16(&packet[rdlength_offset..rdlength_offset + 2]) as usize;
                opt_record_info = Some((rr_start, rdlength_offset, rdlength));
                break;
            }
        }

        // Skip to next RR
        offset = dns::skip_name(packet, offset)?;
        ensure!(offset + 10 <= packet_len, "Incomplete RR");
        let rdlen = BigEndian::read_u16(&packet[offset + 8..offset + 10]) as usize;
        offset += 10 + rdlen;
    }

    let (_opt_start, rdlength_offset, rdlength) =
        opt_record_info.ok_or_else(|| anyhow::anyhow!("No EDNS OPT record found"))?;

    // Check if ECS already exists in the packet
    // If it does, DO NOT overwrite it - client-provided ECS has higher priority
    let rdata_start = rdlength_offset + 2;
    let mut rdata_offset = 0;
    let mut has_ecs = false;

    while rdata_offset < rdlength {
        if rdata_start + rdata_offset + 4 > packet_len {
            break;
        }
        let opt_code = BigEndian::read_u16(&packet[rdata_start + rdata_offset..]);
        let opt_len = BigEndian::read_u16(&packet[rdata_start + rdata_offset + 2..]) as usize;

        if rdata_start + rdata_offset + 4 + opt_len > packet_len {
            break;
        }

        if opt_code == EDNS_CLIENT_SUBNET {
            has_ecs = true;
            break;
        }
        rdata_offset += 4 + opt_len;
    }

    // If ECS already exists, don't modify it
    if has_ecs {
        return Ok(());
    }

    // Build new ECS option based on client IP
    let ecs_data = build_ecs_option(client_ip, prefix_v4, prefix_v6);

    // Append ECS option to existing RDATA
    let ecs_option = [
        &EDNS_CLIENT_SUBNET.to_be_bytes()[..],
        &(ecs_data.len() as u16).to_be_bytes()[..],
        &ecs_data[..],
    ]
    .concat();

    // Update the RDLENGTH field
    let new_rdlength = rdlength + ecs_option.len();
    BigEndian::write_u16(
        &mut packet[rdlength_offset..rdlength_offset + 2],
        new_rdlength as u16,
    );

    // Insert the new ECS option at the end of the current RDATA
    let old_rdata_end = rdata_start + rdlength;
    let remaining = if old_rdata_end < packet_len {
        packet[old_rdata_end..].to_vec()
    } else {
        Vec::new()
    };

    // Add the ECS option
    packet.truncate(old_rdata_end);
    packet.extend_from_slice(&ecs_option);
    packet.extend_from_slice(&remaining);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_extract_client_ip() {
        use std::net::SocketAddr;
        let mut headers = hyper::HeaderMap::new();
        let remote: SocketAddr = "203.0.113.45:12345".parse().unwrap();

        // Test X-Forwarded-For (highest priority)
        headers.insert("x-forwarded-for", "192.168.1.1, 10.0.0.1".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, remote),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );

        // Test X-Real-IP (second priority)
        headers.clear();
        headers.insert("x-real-ip", "10.0.0.2".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, remote),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );

        // Test remote_addr fallback (third priority)
        headers.clear();
        assert_eq!(
            extract_client_ip(&headers, remote),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 45))
        );

        // Test X-Forwarded-For takes precedence over remote_addr
        headers.insert("x-forwarded-for", "192.168.1.5".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, remote),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))
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

    #[test]
    fn test_add_ecs_to_packet() {
        use crate::dns;

        // Create a simple DNS query packet for example.com A record
        let mut packet = vec![
            0x00, 0x00, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT: 1 question
            0x00, 0x00, // ANCOUNT: 0 answers
            0x00, 0x00, // NSCOUNT: 0 authority records
            0x00, 0x00, // ARCOUNT: 0 additional records
            // Question section
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // null terminator
            0x00, 0x01, // QTYPE: A
            0x00, 0x01, // QCLASS: IN
        ];

        // First add EDNS (as the proxy function does)
        dns::set_edns_max_payload_size(&mut packet, 4096).unwrap();

        let original_len = packet.len();
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let result = add_ecs_to_packet(&mut packet, client_ip, 24, 56);

        assert!(
            result.is_ok(),
            "Failed to add ECS to packet: {:?}",
            result.err()
        );

        // Verify EDNS OPT record exists (arcount should be 1)
        assert_eq!(packet[10..12], [0x00, 0x01]); // ARCOUNT = 1

        // Packet should be longer after adding ECS
        assert!(
            packet.len() > original_len,
            "Packet should be longer after adding ECS"
        );
    }

    #[test]
    fn test_ecs_not_overwritten_if_exists() {
        use crate::dns;

        // Create a DNS query packet
        let mut packet = vec![
            0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        // Add EDNS
        dns::set_edns_max_payload_size(&mut packet, 4096).unwrap();

        // Manually add an ECS option with a specific client subnet
        let client_provided_ecs =
            build_ecs_option(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)), 24, 56);

        // Find the EDNS OPT record and add ECS to it
        let opt_rdlength_offset = packet.len() - 2; // RDLENGTH is at the end
        let rdlength = BigEndian::read_u16(&packet[opt_rdlength_offset..]) as usize;

        // Build ECS option
        let ecs_option = [
            &EDNS_CLIENT_SUBNET.to_be_bytes()[..],
            &(client_provided_ecs.len() as u16).to_be_bytes()[..],
            &client_provided_ecs[..],
        ]
        .concat();

        // Update RDLENGTH
        BigEndian::write_u16(
            &mut packet[opt_rdlength_offset..],
            (rdlength + ecs_option.len()) as u16,
        );

        // Append the ECS option
        packet.extend_from_slice(&ecs_option);

        let packet_before = packet.clone();

        // Now try to add ECS with a different IP - it should NOT modify the packet
        let server_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let result = add_ecs_to_packet(&mut packet, server_ip, 24, 56);

        assert!(result.is_ok(), "Should succeed but not modify packet");

        // Packet should be unchanged
        assert_eq!(
            packet, packet_before,
            "Packet should not be modified when ECS already exists"
        );
    }
}
