//! Node-level resource metrics read from /proc and statvfs.

use std::path::PathBuf;

/// Samples node metrics. CPU usage is measured between consecutive
/// samples, so the first sample has none.
pub struct NodeSampler {
    /// Filesystem whose usage is reported (the agent data directory).
    disk_path: PathBuf,
    previous_cpu: Option<CpuTimes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuTimes {
    busy: u64,
    total: u64,
}

impl NodeSampler {
    pub fn new(disk_path: PathBuf) -> Self {
        Self {
            disk_path,
            previous_cpu: None,
        }
    }

    /// Current node metrics, by name.
    pub fn sample(&mut self) -> Vec<(String, f64)> {
        let mut out = Vec::new();
        let mut push = |name: &str, value: f64| {
            if value.is_finite() {
                out.push((name.to_string(), value));
            }
        };

        if let Some(cpu) = std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|s| parse_cpu(&s))
        {
            if let Some(ratio) = self.previous_cpu.and_then(|prev| cpu_ratio(prev, cpu)) {
                push("node_cpu_usage_ratio", ratio);
            }
            self.previous_cpu = Some(cpu);
        }

        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo")
            && let Some((total, available)) = parse_meminfo(&meminfo)
        {
            push("node_memory_total_bytes", total);
            push("node_memory_available_bytes", available);
            push("node_memory_usage_ratio", (total - available) / total);
        }

        if let Some((total, available)) = disk_usage(&self.disk_path) {
            push("node_disk_total_bytes", total);
            push("node_disk_available_bytes", available);
            push("node_disk_usage_ratio", (total - available) / total);
        }

        if let Ok(loadavg) = std::fs::read_to_string("/proc/loadavg") {
            let mut fields = loadavg.split_whitespace();
            for name in ["node_load1", "node_load5", "node_load15"] {
                if let Some(value) = fields.next().and_then(|v| v.parse().ok()) {
                    push(name, value);
                }
            }
        }
        out
    }
}

/// Aggregate CPU times from the first line of /proc/stat.
fn parse_cpu(stat: &str) -> Option<CpuTimes> {
    let line = stat.lines().next()?;
    let mut fields = line.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    // user nice system idle iowait irq softirq steal (guest time is
    // already counted in user).
    let values: Vec<u64> = fields.take(8).filter_map(|v| v.parse().ok()).collect();
    if values.len() < 4 {
        return None;
    }
    let total: u64 = values.iter().sum();
    let idle = values[3] + values.get(4).copied().unwrap_or(0);
    Some(CpuTimes {
        busy: total - idle,
        total,
    })
}

fn cpu_ratio(previous: CpuTimes, current: CpuTimes) -> Option<f64> {
    let total = current.total.checked_sub(previous.total)?;
    let busy = current.busy.checked_sub(previous.busy)?;
    (total > 0).then(|| busy as f64 / total as f64)
}

/// Total and available memory in bytes.
fn parse_meminfo(meminfo: &str) -> Option<(f64, f64)> {
    let field = |key: &str| {
        meminfo.lines().find_map(|line| {
            let kb: f64 = line
                .strip_prefix(key)?
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .ok()?;
            Some(kb * 1024.0)
        })
    };
    let total = field("MemTotal:")?;
    let available = field("MemAvailable:")?;
    (total > 0.0).then_some((total, available))
}

/// Total and available bytes of the filesystem holding `path`.
fn disk_usage(path: &std::path::Path) -> Option<(f64, f64)> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs fills the zeroed struct; `path` is NUL-terminated
    // and outlives the call.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let block = stat.f_frsize as f64;
    let total = stat.f_blocks as f64 * block;
    let available = stat.f_bavail as f64 * block;
    (total > 0.0).then_some((total, available))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_usage_is_measured_between_samples() {
        let a = parse_cpu("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4\n").unwrap();
        let b = parse_cpu("cpu  150 0 150 750 150 0 0 0 0 0\n").unwrap();
        assert_eq!(a.total, 1000);
        assert_eq!(a.busy, 200);
        assert_eq!(cpu_ratio(a, b), Some(0.5));
        assert_eq!(cpu_ratio(a, a), None);
        assert!(parse_cpu("intr 1 2 3").is_none());
    }

    #[test]
    fn memory_comes_from_meminfo() {
        let (total, available) =
            parse_meminfo("MemTotal:       2048 kB\nMemFree: 1 kB\nMemAvailable:    512 kB\n")
                .unwrap();
        assert_eq!(total, 2048.0 * 1024.0);
        assert_eq!(available, 512.0 * 1024.0);
    }

    #[test]
    fn samples_this_host() {
        let dir = tempfile::tempdir().unwrap();
        let mut sampler = NodeSampler::new(dir.path().to_path_buf());
        let names: Vec<_> = sampler.sample().into_iter().map(|(n, _)| n).collect();
        assert!(
            names.contains(&"node_disk_usage_ratio".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"node_memory_usage_ratio".to_string()));
        assert!(!names.contains(&"node_cpu_usage_ratio".to_string()));
    }
}
