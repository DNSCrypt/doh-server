use anyhow::{ensure, Error};
use byteorder::{BigEndian, ByteOrder};

const DNS_HEADER_SIZE: usize = 12;
pub const DNS_OFFSET_FLAGS: usize = 2;
const DNS_MAX_HOSTNAME_SIZE: usize = 256;
const DNS_MAX_PACKET_SIZE: usize = 4096;
const DNS_OFFSET_QUESTION: usize = DNS_HEADER_SIZE;

const DNS_FLAGS_TC: u16 = 1u16 << 9;

const DNS_TYPE_OPT: u16 = 41;

const DNS_PTYPE_PADDING: u16 = 12;

const DNS_RCODE_SERVFAIL: u8 = 2;
const DNS_RCODE_REFUSED: u8 = 5;

#[inline]
pub fn rcode(packet: &[u8]) -> u8 {
    packet[3] & 0x0f
}

#[inline]
pub fn qdcount(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[4..])
}

#[inline]
pub fn ancount(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[6..])
}

#[inline]
pub fn arcount(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[10..])
}

fn arcount_inc(packet: &mut [u8]) -> Result<(), Error> {
    let mut arcount = arcount(packet);
    ensure!(arcount < 0xffff, "Too many additional records");
    arcount += 1;
    BigEndian::write_u16(&mut packet[10..], arcount);
    Ok(())
}

#[inline]
fn nscount(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[8..])
}

#[inline]
pub fn is_recoverable_error(packet: &[u8]) -> bool {
    let rcode = rcode(packet);
    rcode == DNS_RCODE_SERVFAIL || rcode == DNS_RCODE_REFUSED
}

#[inline]
pub fn is_truncated(packet: &[u8]) -> bool {
    BigEndian::read_u16(&packet[DNS_OFFSET_FLAGS..]) & DNS_FLAGS_TC == DNS_FLAGS_TC
}

fn skip_name(packet: &[u8], offset: usize) -> Result<usize, Error> {
    let packet_len = packet.len();
    ensure!(offset < packet_len - 1, "Short packet");
    let mut qname_len: usize = 0;
    let mut offset = offset;
    loop {
        let label_len = match packet[offset] as usize {
            label_len if label_len & 0xc0 == 0xc0 => {
                ensure!(packet_len - offset >= 2, "Incomplete offset");
                offset += 2;
                break;
            }
            label_len => label_len,
        } as usize;
        ensure!(label_len < 0x40, "Long label");
        ensure!(
            packet_len - offset - 1 > label_len,
            "Malformed packet with an out-of-bounds name"
        );
        qname_len += label_len + 1;
        ensure!(qname_len <= DNS_MAX_HOSTNAME_SIZE, "Name too long");
        offset += label_len + 1;
        if label_len == 0 {
            break;
        }
    }
    Ok(offset)
}

fn traverse_rrs<F: FnMut(usize) -> Result<(), Error>>(
    packet: &[u8],
    mut offset: usize,
    rrcount: usize,
    mut cb: F,
) -> Result<usize, Error> {
    let packet_len = packet.len();
    for _ in 0..rrcount {
        offset = skip_name(packet, offset)?;
        ensure!(packet_len - offset >= 10, "Short packet");
        cb(offset)?;
        let rdlen = BigEndian::read_u16(&packet[offset + 8..]) as usize;
        offset += 10;
        ensure!(
            packet_len - offset >= rdlen,
            "Record length would exceed packet length"
        );
        offset += rdlen;
    }
    Ok(offset)
}

fn traverse_rrs_mut<F: FnMut(&mut [u8], usize) -> Result<(), Error>>(
    packet: &mut [u8],
    mut offset: usize,
    rrcount: usize,
    mut cb: F,
) -> Result<usize, Error> {
    let packet_len = packet.len();
    for _ in 0..rrcount {
        offset = skip_name(packet, offset)?;
        ensure!(packet_len - offset >= 10, "Short packet");
        cb(packet, offset)?;
        let rdlen = BigEndian::read_u16(&packet[offset + 8..]) as usize;
        offset += 10;
        ensure!(
            packet_len - offset >= rdlen,
            "Record length would exceed packet length"
        );
        offset += rdlen;
    }
    Ok(offset)
}

pub fn min_ttl(packet: &[u8], min_ttl: u32, max_ttl: u32, failure_ttl: u32) -> Result<u32, Error> {
    let packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(packet_len <= DNS_MAX_PACKET_SIZE, "Large packet");
    ensure!(qdcount(packet) == 1, "No question");
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    assert!(offset > DNS_OFFSET_QUESTION);
    ensure!(packet_len - offset > 4, "Short packet");
    offset += 4;
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    let rrcount = ancount as usize + nscount as usize + arcount as usize;
    let mut found_min_ttl = if rrcount > 0 { max_ttl } else { failure_ttl };

    offset = traverse_rrs(packet, offset, rrcount, |offset| {
        let qtype = BigEndian::read_u16(&packet[offset..]);
        let ttl = BigEndian::read_u32(&packet[offset + 4..]);
        if qtype != DNS_TYPE_OPT && ttl < found_min_ttl {
            found_min_ttl = ttl;
        }
        Ok(())
    })?;
    if found_min_ttl < min_ttl {
        found_min_ttl = min_ttl;
    }
    ensure!(packet_len == offset, "Garbage after packet");
    Ok(found_min_ttl)
}

fn add_edns_section(packet: &mut Vec<u8>, max_payload_size: u16) -> Result<(), Error> {
    let opt_rr: [u8; 11] = [
        0,
        (DNS_TYPE_OPT >> 8) as u8,
        DNS_TYPE_OPT as u8,
        (max_payload_size >> 8) as u8,
        max_payload_size as u8,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    ensure!(
        DNS_MAX_PACKET_SIZE - packet.len() >= opt_rr.len(),
        "Packet would be too large to add a new record"
    );
    arcount_inc(packet)?;
    packet.extend(&opt_rr);
    Ok(())
}

pub fn set_edns_max_payload_size(packet: &mut Vec<u8>, max_payload_size: u16) -> Result<(), Error> {
    let packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(packet_len <= DNS_MAX_PACKET_SIZE, "Large packet");
    ensure!(qdcount(packet) == 1, "No question");
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    assert!(offset > DNS_OFFSET_QUESTION);
    ensure!(packet_len - offset >= 4, "Short packet");
    offset += 4;
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    offset = traverse_rrs(
        packet,
        offset,
        ancount as usize + nscount as usize,
        |_offset| Ok(()),
    )?;
    let mut edns_payload_set = false;
    traverse_rrs_mut(packet, offset, arcount as _, |packet, offset| {
        let qtype = BigEndian::read_u16(&packet[offset..]);
        if qtype == DNS_TYPE_OPT {
            ensure!(!edns_payload_set, "Duplicate OPT RR found");
            BigEndian::write_u16(&mut packet[offset + 2..], max_payload_size);
            edns_payload_set = true;
        }
        Ok(())
    })?;
    if edns_payload_set {
        return Ok(());
    }
    add_edns_section(packet, max_payload_size)?;
    Ok(())
}

fn padded_len(unpadded_len: usize) -> usize {
    const BOUNDARIES: [usize; 16] = [
        64, 128, 192, 256, 320, 384, 512, 704, 768, 896, 960, 1024, 1088, 1152, 2688, 4080,
    ];
    BOUNDARIES
        .iter()
        .find(|&&boundary| boundary >= unpadded_len)
        .copied()
        .unwrap_or(DNS_MAX_PACKET_SIZE)
}

pub fn add_edns_padding(packet: &mut Vec<u8>) -> Result<(), Error> {
    let mut packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(packet_len <= DNS_MAX_PACKET_SIZE, "Large packet");
    ensure!(qdcount(packet) == 1, "No question");
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    assert!(offset > DNS_OFFSET_QUESTION);
    ensure!(packet_len - offset >= 4, "Short packet");
    offset += 4;
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    offset = traverse_rrs(
        packet,
        offset,
        ancount as usize + nscount as usize,
        |_offset| Ok(()),
    )?;
    let mut edns_offset = None;
    traverse_rrs_mut(packet, offset, arcount as _, |packet, offset| {
        let qtype = BigEndian::read_u16(&packet[offset..]);
        if qtype == DNS_TYPE_OPT {
            ensure!(edns_offset.is_none(), "Duplicate OPT RR found");
            edns_offset = Some(offset)
        }
        Ok(())
    })?;
    let edns_offset = match edns_offset {
        Some(edns_offset) => edns_offset,
        None => {
            let edns_offset = packet.len() + 1;
            add_edns_section(packet, DNS_MAX_PACKET_SIZE as _)?;
            packet_len = packet.len();
            edns_offset
        }
    };
    let padding_len = padded_len(packet_len) - packet_len;
    let mut edns_padding_prr = vec![b'X'; 4 + padding_len];
    BigEndian::write_u16(&mut edns_padding_prr[0..], DNS_PTYPE_PADDING);
    BigEndian::write_u16(&mut edns_padding_prr[2..], padding_len as u16);
    let edns_padding_prr_len = edns_padding_prr.len();
    let edns_rdlen_offset: usize = edns_offset + 8;
    ensure!(packet_len - edns_rdlen_offset >= 2, "Short packet");
    let edns_rdlen = BigEndian::read_u16(&packet[edns_rdlen_offset..]);
    ensure!(
        edns_offset + edns_rdlen as usize <= packet_len,
        "Out of range EDNS size"
    );
    ensure!(
        0xffff - edns_rdlen as usize >= edns_padding_prr_len,
        "EDNS section too large for padding"
    );
    ensure!(
        DNS_MAX_PACKET_SIZE - packet_len >= edns_padding_prr_len,
        "Large packet"
    );
    BigEndian::write_u16(
        &mut packet[edns_rdlen_offset..],
        edns_rdlen + edns_padding_prr_len as u16,
    );
    packet.extend(&edns_padding_prr);
    Ok(())
}
