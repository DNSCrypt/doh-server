const DNS_CLASS_IN: u16 = 1;
const DNS_HEADER_SIZE: usize = 12;
const DNS_MAX_HOSTNAME_LEN: usize = 256;
const DNS_MAX_PACKET_SIZE: usize = 65_535;
const DNS_OFFSET_QUESTION: usize = DNS_HEADER_SIZE;
const DNS_TYPE_OPT: u16 = 41;

#[inline]
fn qdcount(packet: &[u8]) -> u16 {
    (u16::from(packet[4]) << 8) | u16::from(packet[5])
}

#[inline]
fn ancount(packet: &[u8]) -> u16 {
    (u16::from(packet[6]) << 8) | u16::from(packet[7])
}

#[inline]
fn nscount(packet: &[u8]) -> u16 {
    (u16::from(packet[8]) << 8) | u16::from(packet[9])
}

#[inline]
fn arcount(packet: &[u8]) -> u16 {
    (u16::from(packet[10]) << 8) | u16::from(packet[11])
}

fn skip_name(packet: &[u8], offset: usize) -> Result<(usize, u16), &'static str> {
    let packet_len = packet.len();
    if offset >= packet_len - 1 {
        return Err("Short packet");
    }
    let mut name_len: usize = 0;
    let mut offset = offset;
    let mut labels_count = 0u16;
    loop {
        let label_len = match packet[offset] {
            len if len & 0xc0 == 0xc0 => {
                if 2 > packet_len - offset {
                    return Err("Incomplete offset");
                }
                offset += 2;
                break;
            }
            len if len > 0x3f => return Err("Label too long"),
            len => len,
        } as usize;
        if label_len >= packet_len - offset - 1 {
            return Err("Malformed packet with an out-of-bounds name");
        }
        name_len += label_len + 1;
        if name_len > DNS_MAX_HOSTNAME_LEN {
            return Err("Name too long");
        }
        offset += label_len + 1;
        if label_len == 0 {
            break;
        }
        labels_count += 1;
    }
    Ok((offset, labels_count))
}

pub fn min_ttl(
    packet: &[u8],
    min_ttl: u32,
    max_ttl: u32,
    failure_ttl: u32,
) -> Result<u32, &'static str> {
    if qdcount(packet) != 1 {
        return Err("Unsupported number of questions");
    }
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err("Short packet");
    }
    if packet_len >= DNS_MAX_PACKET_SIZE {
        return Err("Large packet");
    }
    let mut offset = match skip_name(packet, DNS_OFFSET_QUESTION) {
        Ok(offset) => offset.0,
        Err(e) => return Err(e),
    };
    assert!(offset > DNS_OFFSET_QUESTION);
    if 4 > packet_len - offset {
        return Err("Short packet");
    }
    offset += 4;
    let ancount = ancount(packet);
    let nscount = nscount(packet);
    let arcount = arcount(packet);
    let rrcount = ancount + nscount + arcount;
    let mut found_min_ttl = if rrcount > 0 { max_ttl } else { failure_ttl };
    for _ in 0..rrcount {
        offset = match skip_name(packet, offset) {
            Ok(offset) => offset.0,
            Err(e) => return Err(e),
        };
        if 10 > packet_len - offset {
            return Err("Short packet");
        }
        let qtype = u16::from(packet[offset]) << 8 | u16::from(packet[offset + 1]);
        let qclass = u16::from(packet[offset + 2]) << 8 | u16::from(packet[offset + 3]);
        let ttl = u32::from(packet[offset + 4]) << 24 | u32::from(packet[offset + 5]) << 16
            | u32::from(packet[offset + 6]) << 8 | u32::from(packet[offset + 7]);
        let rdlen = (u16::from(packet[offset + 8]) << 8 | u16::from(packet[offset + 9])) as usize;
        offset += 10;
        if !(qtype == DNS_TYPE_OPT && qclass == DNS_CLASS_IN) {
            if ttl < found_min_ttl {
                found_min_ttl = ttl;
            }
        }
        if rdlen > packet_len - offset {
            return Err("Record length would exceed packet length");
        }
        offset += rdlen;
    }
    if found_min_ttl < min_ttl {
        found_min_ttl = min_ttl;
    }
    if offset != packet_len {
        return Err("Garbage after packet");
    }
    Ok(found_min_ttl)
}
