use anyhow::{ensure, Error};
use byteorder::{BigEndian, ByteOrder};
use serde::{Deserialize, Serialize};

use crate::dns;

// DNS record types
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const TYPE_CAA: u16 = 257;

// DNS classes
const CLASS_IN: u16 = 1;

// Google DNS JSON API response format
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DnsJsonResponse {
    pub status: u16,
    #[serde(rename = "TC")]
    pub tc: bool,
    #[serde(rename = "RD")]
    pub rd: bool,
    #[serde(rename = "RA")]
    pub ra: bool,
    #[serde(rename = "AD")]
    pub ad: bool,
    #[serde(rename = "CD")]
    pub cd: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub question: Option<Vec<DnsQuestion>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answer: Option<Vec<DnsAnswer>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<Vec<DnsAnswer>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional: Option<Vec<DnsAnswer>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    #[serde(rename = "type")]
    pub qtype: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: u16,
    #[serde(rename = "TTL")]
    pub ttl: u32,
    pub data: String,
}

pub fn parse_dns_to_json(packet: &[u8]) -> Result<DnsJsonResponse, Error> {
    ensure!(packet.len() >= 12, "DNS packet too short");

    // Parse header
    let flags = BigEndian::read_u16(&packet[2..4]);
    let qdcount = dns::qdcount(packet);
    let ancount = dns::ancount(packet);
    let nscount = BigEndian::read_u16(&packet[8..10]);
    let arcount = dns::arcount(packet);

    let mut response = DnsJsonResponse {
        status: dns::rcode(packet) as u16,
        tc: (flags & 0x0200) != 0,
        rd: (flags & 0x0100) != 0,
        ra: (flags & 0x0080) != 0,
        ad: (flags & 0x0020) != 0,
        cd: (flags & 0x0010) != 0,
        question: None,
        answer: None,
        authority: None,
        additional: None,
        comment: None,
    };

    let mut offset = 12;

    // Parse questions
    if qdcount > 0 {
        let mut questions = Vec::new();
        for _ in 0..qdcount {
            let (name, new_offset) = parse_name(packet, offset)?;
            offset = new_offset;
            ensure!(offset + 4 <= packet.len(), "Incomplete question");
            let qtype = BigEndian::read_u16(&packet[offset..offset + 2]);
            offset += 4; // Skip type and class
            questions.push(DnsQuestion { name, qtype });
        }
        response.question = Some(questions);
    }

    // Parse answers
    if ancount > 0 {
        let (answers, new_offset) = parse_rrs(packet, offset, ancount)?;
        offset = new_offset;
        if !answers.is_empty() {
            response.answer = Some(answers);
        }
    }

    // Parse authority section
    if nscount > 0 {
        let (authority, new_offset) = parse_rrs(packet, offset, nscount)?;
        offset = new_offset;
        if !authority.is_empty() {
            response.authority = Some(authority);
        }
    }

    // Parse additional section
    if arcount > 0 {
        let (additional, _) = parse_rrs(packet, offset, arcount)?;
        if !additional.is_empty() {
            response.additional = Some(additional);
        }
    }

    Ok(response)
}

fn parse_name(packet: &[u8], mut offset: usize) -> Result<(String, usize), Error> {
    let mut name = String::new();
    let mut jumped = false;
    let mut jump_offset = 0;
    let packet_len = packet.len();

    loop {
        ensure!(offset < packet_len, "Name extends beyond packet");
        let len = packet[offset];

        if len & 0xc0 == 0xc0 {
            // Compression pointer
            ensure!(offset + 1 < packet_len, "Incomplete compression pointer");
            if !jumped {
                jump_offset = offset + 2;
            }
            offset = (((len & 0x3f) as usize) << 8) | (packet[offset + 1] as usize);
            jumped = true;
            continue;
        }

        offset += 1;
        if len == 0 {
            break;
        }

        if !name.is_empty() {
            name.push('.');
        }

        ensure!(
            offset + len as usize <= packet_len,
            "Label extends beyond packet"
        );
        name.push_str(&String::from_utf8_lossy(
            &packet[offset..offset + len as usize],
        ));
        offset += len as usize;
    }

    if jumped {
        Ok((name, jump_offset))
    } else {
        Ok((name, offset))
    }
}

fn parse_rrs(
    packet: &[u8],
    mut offset: usize,
    count: u16,
) -> Result<(Vec<DnsAnswer>, usize), Error> {
    let mut records = Vec::new();
    let packet_len = packet.len();

    for _ in 0..count {
        let (name, new_offset) = parse_name(packet, offset)?;
        offset = new_offset;

        ensure!(offset + 10 <= packet_len, "Incomplete resource record");
        let rtype = BigEndian::read_u16(&packet[offset..offset + 2]);
        let class = BigEndian::read_u16(&packet[offset + 2..offset + 4]);
        let ttl = BigEndian::read_u32(&packet[offset + 4..offset + 8]);
        let rdlength = BigEndian::read_u16(&packet[offset + 8..offset + 10]) as usize;
        offset += 10;

        ensure!(
            offset + rdlength <= packet_len,
            "Resource data extends beyond packet"
        );

        // Skip non-IN class records and OPT records
        if class != CLASS_IN || rtype == dns::DNS_TYPE_OPT {
            offset += rdlength;
            continue;
        }

        let data = match rtype {
            TYPE_A if rdlength == 4 => {
                format!(
                    "{}.{}.{}.{}",
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3]
                )
            }
            TYPE_AAAA if rdlength == 16 => {
                let addr = &packet[offset..offset + 16];
                format!(
                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    BigEndian::read_u16(&addr[0..2]),
                    BigEndian::read_u16(&addr[2..4]),
                    BigEndian::read_u16(&addr[4..6]),
                    BigEndian::read_u16(&addr[6..8]),
                    BigEndian::read_u16(&addr[8..10]),
                    BigEndian::read_u16(&addr[10..12]),
                    BigEndian::read_u16(&addr[12..14]),
                    BigEndian::read_u16(&addr[14..16])
                )
            }
            TYPE_CNAME | TYPE_NS | TYPE_PTR => {
                let (domain, _) = parse_name(packet, offset)?;
                domain
            }
            TYPE_MX if rdlength >= 2 => {
                let preference = BigEndian::read_u16(&packet[offset..offset + 2]);
                let (exchange, _) = parse_name(packet, offset + 2)?;
                format!("{} {}", preference, exchange)
            }
            TYPE_TXT => {
                let mut txt_data = String::new();
                let mut txt_offset = offset;
                while txt_offset < offset + rdlength {
                    let txt_len = packet[txt_offset] as usize;
                    txt_offset += 1;
                    if txt_offset + txt_len <= offset + rdlength {
                        if !txt_data.is_empty() {
                            txt_data.push(' ');
                        }
                        txt_data.push_str(&String::from_utf8_lossy(
                            &packet[txt_offset..txt_offset + txt_len],
                        ));
                        txt_offset += txt_len;
                    } else {
                        break;
                    }
                }
                txt_data
            }
            TYPE_SOA => {
                // For SOA, we'll just return a simple representation
                format!("<SOA record, {} bytes>", rdlength)
            }
            TYPE_SRV if rdlength >= 6 => {
                let priority = BigEndian::read_u16(&packet[offset..offset + 2]);
                let weight = BigEndian::read_u16(&packet[offset + 2..offset + 4]);
                let port = BigEndian::read_u16(&packet[offset + 4..offset + 6]);
                let (target, _) = parse_name(packet, offset + 6)?;
                format!("{} {} {} {}", priority, weight, port, target)
            }
            TYPE_CAA => {
                // Basic CAA record parsing
                if rdlength >= 2 {
                    let flags = packet[offset];
                    let tag_len = packet[offset + 1] as usize;
                    if offset + 2 + tag_len <= offset + rdlength {
                        let tag =
                            String::from_utf8_lossy(&packet[offset + 2..offset + 2 + tag_len]);
                        let value = String::from_utf8_lossy(
                            &packet[offset + 2 + tag_len..offset + rdlength],
                        );
                        format!("{} {} \"{}\"", flags, tag, value)
                    } else {
                        BASE64_STD.encode(&packet[offset..offset + rdlength])
                    }
                } else {
                    BASE64_STD.encode(&packet[offset..offset + rdlength])
                }
            }
            _ => {
                // For unknown types, return base64 encoded data
                BASE64_STD.encode(&packet[offset..offset + rdlength])
            }
        };

        offset += rdlength;
        records.push(DnsAnswer {
            name,
            rtype,
            ttl,
            data,
        });
    }

    Ok((records, offset))
}

// Parse JSON API query parameters
#[derive(Debug, Deserialize)]
pub struct DnsJsonQuery {
    pub name: String,
    #[serde(rename = "type")]
    pub qtype: Option<u16>,
    pub cd: Option<bool>,
    pub ct: Option<String>,
    pub do_: Option<bool>,
    pub edns_client_subnet: Option<String>,
}

// Build DNS query packet from JSON parameters
pub fn build_dns_query(query: &DnsJsonQuery) -> Result<Vec<u8>, Error> {
    let qtype = query.qtype.unwrap_or(TYPE_A);
    let mut packet = vec![0; 12];

    // Transaction ID (random)
    packet[0] = rand::random();
    packet[1] = rand::random();

    // Flags: RD (recursion desired) set by default
    packet[2] = 0x01;
    packet[3] = 0x00;

    // Set CD flag if requested
    if query.cd.unwrap_or(false) {
        packet[3] |= 0x10;
    }

    // Question count = 1
    BigEndian::write_u16(&mut packet[4..6], 1);

    // Add question
    for label in query.name.split('.') {
        if !label.is_empty() {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
    }
    packet.push(0); // Root label

    // Query type and class
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());

    // Add EDNS if DO flag is set or if we need client subnet
    if query.do_.unwrap_or(false) || query.edns_client_subnet.is_some() {
        // Increment additional count
        BigEndian::write_u16(&mut packet[10..12], 1);

        // OPT record
        packet.push(0); // Root domain
        packet.extend_from_slice(&dns::DNS_TYPE_OPT.to_be_bytes());
        packet.extend_from_slice(&[0x10, 0x00]); // UDP payload size 4096
        packet.push(0); // Extended RCODE
        packet.push(0); // Version
        let mut flags = 0u16;
        if query.do_.unwrap_or(false) {
            flags |= 0x8000; // DO flag
        }
        packet.extend_from_slice(&flags.to_be_bytes());

        // RDLENGTH placeholder
        let rdlength_pos = packet.len();
        packet.extend_from_slice(&[0, 0]);

        let mut opt_data = Vec::new();

        // Add client subnet if provided
        if let Some(subnet) = &query.edns_client_subnet {
            // Parse subnet (simplified - assumes IPv4 /24)
            if let Ok(addr) = subnet.parse::<std::net::Ipv4Addr>() {
                opt_data.extend_from_slice(&[0x00, 0x08]); // Option code 8 (client subnet)
                opt_data.extend_from_slice(&[0x00, 0x07]); // Option length
                opt_data.extend_from_slice(&[0x00, 0x01]); // Family: IPv4
                opt_data.push(24); // Source prefix length
                opt_data.push(0); // Scope prefix length
                opt_data.extend_from_slice(&addr.octets()[..3]); // First 3 octets
            }
        }

        // Update RDLENGTH
        BigEndian::write_u16(
            &mut packet[rdlength_pos..rdlength_pos + 2],
            opt_data.len() as u16,
        );
        packet.extend_from_slice(&opt_data);
    }

    Ok(packet)
}

// Export base64 for reuse
use base64::Engine;
pub const BASE64_STD: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
