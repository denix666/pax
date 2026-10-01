use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

pub struct PaxLogger {
    file: Option<File>,
}

impl PaxLogger {
    pub fn open(log_path: &Path) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .ok();
        Self { file }
    }

    pub fn none() -> Self {
        Self { file: None }
    }

    fn write_entry(&mut self, tag: &str, message: &str) {
        let Some(ref mut file) = self.file else {
            return;
        };
        let ts = format_local_timestamp();
        let _ = writeln!(file, "[{ts}] [{tag}] {message}");
    }

    pub fn log_command(&mut self, args: &[String]) {
        let cmd = args.join(" ");
        self.write_entry("PAX", &format!("Running 'pax {cmd}'"));
    }

    pub fn log_sync(&mut self) {
        self.write_entry("PAX", "synchronizing package lists");
    }

    pub fn log_transaction_start(&mut self) {
        self.write_entry("PAX", "transaction started");
    }

    pub fn log_transaction_completed(&mut self) {
        self.write_entry("PAX", "transaction completed");
    }

    pub fn log_installed(&mut self, name: &str, version: &str) {
        self.write_entry("PAX", &format!("installed {name} ({version})"));
    }

    pub fn log_upgraded(&mut self, name: &str, old_ver: &str, new_ver: &str) {
        self.write_entry("PAX", &format!("upgraded {name} ({old_ver} -> {new_ver})"));
    }

    pub fn log_removed(&mut self, name: &str, version: &str) {
        self.write_entry("PAX", &format!("removed {name} ({version})"));
    }

    pub fn log_hook(&mut self, hook_name: &str) {
        self.write_entry("PAX", &format!("running '{hook_name}'..."));
    }

    pub fn log_warning(&mut self, message: &str) {
        self.write_entry("PAX", &format!("warning: {message}"));
    }
}

fn format_local_timestamp() -> String {
    let now = unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        tm
    };

    let offset_sec = now.tm_gmtoff;
    let offset_h = offset_sec / 3600;
    let offset_m = (offset_sec.abs() % 3600) / 60;
    let sign = if offset_sec >= 0 { '+' } else { '-' };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}{:02}{:02}",
        now.tm_year + 1900,
        now.tm_mon + 1,
        now.tm_mday,
        now.tm_hour,
        now.tm_min,
        now.tm_sec,
        sign,
        offset_h.abs(),
        offset_m,
    )
}
