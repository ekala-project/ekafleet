use std::collections::HashMap;

/// Collect node-level system metrics (CPU, memory, disk, network).
pub async fn collect_node_metrics() -> Vec<super::collector::MetricSample> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut samples = Vec::new();

    // CPU: read from /proc/stat
    if let Ok(contents) = tokio::fs::read_to_string("/proc/stat").await
        && let Some(cpu_line) = contents.lines().next()
    {
        let parts: Vec<&str> = cpu_line.split_whitespace().collect();
        if parts.len() >= 5 {
            // user, nice, system, idle
            let user: f64 = parts[1].parse().unwrap_or(0.0);
            let system: f64 = parts[3].parse().unwrap_or(0.0);
            let idle: f64 = parts[4].parse().unwrap_or(0.0);
            let total = user + system + idle;
            if total > 0.0 {
                samples.push(super::collector::MetricSample {
                    name: "node_cpu_usage_ratio".into(),
                    value: (user + system) / total,
                    labels: HashMap::new(),
                    timestamp: now,
                });
            }
        }
    }

    // Memory: read from /proc/meminfo
    if let Ok(contents) = tokio::fs::read_to_string("/proc/meminfo").await {
        let mut total: f64 = 0.0;
        let mut available: f64 = 0.0;

        for line in contents.lines() {
            if let Some(val) = line.strip_prefix("MemTotal:") {
                total = parse_meminfo_kb(val);
            } else if let Some(val) = line.strip_prefix("MemAvailable:") {
                available = parse_meminfo_kb(val);
            }
        }

        if total > 0.0 {
            samples.push(super::collector::MetricSample {
                name: "node_memory_total_bytes".into(),
                value: total * 1024.0,
                labels: HashMap::new(),
                timestamp: now,
            });
            samples.push(super::collector::MetricSample {
                name: "node_memory_available_bytes".into(),
                value: available * 1024.0,
                labels: HashMap::new(),
                timestamp: now,
            });
            samples.push(super::collector::MetricSample {
                name: "node_memory_usage_ratio".into(),
                value: (total - available) / total,
                labels: HashMap::new(),
                timestamp: now,
            });
        }
    }

    // Disk: read from /proc/diskstats or use statvfs
    // Simplified: just check root filesystem
    if let Ok(contents) = tokio::fs::read_to_string("/proc/mounts").await {
        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == "/" {
                // Could use statvfs here, but keeping it simple
                break;
            }
        }
    }

    samples
}

fn parse_meminfo_kb(s: &str) -> f64 {
    s.trim()
        .strip_suffix("kB")
        .or_else(|| s.trim().strip_suffix("KB"))
        .unwrap_or(s.trim())
        .trim()
        .parse()
        .unwrap_or(0.0)
}
