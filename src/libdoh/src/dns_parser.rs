use byteorder::{BigEndian, ByteOrder};

pub struct DnsQueryInfo {
    pub name: String,
    pub qtype: u16,
}

pub fn parse_query_info(packet: &[u8]) -> Option<DnsQueryInfo> {
    if packet.len() < 12 {
        return None;
    }

    // Check if there's at least one question
    let qdcount = BigEndian::read_u16(&packet[4..6]);
    if qdcount == 0 {
        return None;
    }

    // Parse the first question
    let mut offset = 12; // Start after DNS header
    let mut name_parts = Vec::new();

    // Parse domain name
    loop {
        if offset >= packet.len() {
            return None;
        }

        let label_len = packet[offset] as usize;
        if label_len == 0 {
            offset += 1;
            break;
        }

        // Handle compressed names (not fully supported, just skip)
        if label_len & 0xc0 == 0xc0 {
            offset += 2;
            break;
        }

        if label_len >= 64 || offset + 1 + label_len >= packet.len() {
            return None;
        }

        offset += 1;
        let label = &packet[offset..offset + label_len];
        if let Ok(s) = std::str::from_utf8(label) {
            name_parts.push(s.to_string());
        } else {
            name_parts.push(format!("\\x{:02x}", label_len));
        }
        offset += label_len;
    }

    // Check if we have space for qtype and qclass
    if offset + 4 > packet.len() {
        return None;
    }

    let qtype = BigEndian::read_u16(&packet[offset..offset + 2]);
    let name = if name_parts.is_empty() {
        ".".to_string()
    } else {
        name_parts.join(".")
    };

    Some(DnsQueryInfo { name, qtype })
}
