use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct RequestLogger {
    file: Arc<Mutex<File>>,
    path: PathBuf,
    max_size: u64,
    max_files: u32,
    current_size: Arc<Mutex<u64>>,
}

impl RequestLogger {
    pub async fn new(
        path: impl AsRef<Path>,
        max_size_mb: u64,
        max_files: u32,
    ) -> Result<Self, std::io::Error> {
        let path = path.as_ref().to_path_buf();

        // Open or create the log file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;

        // Get current file size
        let metadata = file.metadata().await?;
        let current_size = metadata.len();

        Ok(RequestLogger {
            file: Arc::new(Mutex::new(file)),
            path,
            max_size: max_size_mb * 1024 * 1024, // Convert MB to bytes
            max_files,
            current_size: Arc::new(Mutex::new(current_size)),
        })
    }

    pub async fn log_request(
        &self,
        client_ip: Option<IpAddr>,
        query_name: &str,
        query_type: u16,
        user_agent: Option<&str>,
    ) -> Result<(), std::io::Error> {
        // Format timestamp
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let timestamp_str = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Format client IP
        let client_ip_str = client_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".to_string());

        // Format query type as string
        let query_type_str = dns_type_to_string(query_type);

        // Format user agent
        let user_agent_str = user_agent.unwrap_or("-");

        // Create log entry
        let log_entry = format!(
            "{} {} {} {} {}\n",
            timestamp_str, client_ip_str, query_name, query_type_str, user_agent_str
        );

        // Write to file
        let mut file = self.file.lock().await;
        file.write_all(log_entry.as_bytes()).await?;
        file.flush().await?;

        // Update current size
        let entry_size = log_entry.len() as u64;
        let mut current_size = self.current_size.lock().await;
        *current_size += entry_size;

        // Check if rotation is needed
        if *current_size >= self.max_size {
            drop(file);
            drop(current_size);
            self.rotate_logs().await?;
        }

        Ok(())
    }

    async fn rotate_logs(&self) -> Result<(), std::io::Error> {
        use tokio::fs;

        // Close current file by dropping the lock
        {
            let mut file = self.file.lock().await;
            file.flush().await?;
        }

        // Rotate existing log files
        for i in (1..self.max_files).rev() {
            let old_name = if i == 1 {
                self.path.clone()
            } else {
                PathBuf::from(format!("{}.{}", self.path.display(), i - 1))
            };
            let new_name = PathBuf::from(format!("{}.{}", self.path.display(), i));

            if old_name.exists() {
                fs::rename(&old_name, &new_name).await?;
            }
        }

        // Delete the oldest file if it exists
        let oldest = PathBuf::from(format!("{}.{}", self.path.display(), self.max_files));
        if oldest.exists() {
            fs::remove_file(oldest).await?;
        }

        // Create new log file
        let new_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&self.path)
            .await?;

        // Update the file handle and reset size
        let mut file = self.file.lock().await;
        *file = new_file;

        let mut current_size = self.current_size.lock().await;
        *current_size = 0;

        Ok(())
    }
}

fn dns_type_to_string(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        52 => "TLSA",
        65 => "HTTPS",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        _ => "UNKNOWN",
    }
}
