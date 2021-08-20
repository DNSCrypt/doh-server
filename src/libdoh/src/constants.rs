pub const DNS_QUERY_PARAM: &str = "dns";
pub const ODOH_TARGET_HOST_QUERY_PARAM: &str = "targethost";
pub const ODOH_TARGET_PATH_QUERY_PARAM: &str = "targetpath";
pub const MAX_DNS_QUESTION_LEN: usize = 512;
pub const MAX_DNS_RESPONSE_LEN: usize = 4096;
pub const MIN_DNS_PACKET_LEN: usize = 17;
pub const STALE_IF_ERROR_SECS: u32 = 86400;
pub const STALE_WHILE_REVALIDATE_SECS: u32 = 60;
pub const CERTS_WATCH_DELAY_SECS: u32 = 10;
pub const ODOH_KEY_ROTATION_SECS: u32 = 86400;
pub const UDP_TCP_RATIO: usize = 8;
