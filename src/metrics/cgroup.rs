//! Per-service resource use, read from each service unit's cgroup.
//!
//! `service_cpu_millicores` is the CPU the unit used since the previous
//! sample (so it appears from the second sample on), and
//! `service_memory_bytes` its current memory use.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const CPU_METRIC: &str = "service_cpu_millicores";
pub const MEMORY_METRIC: &str = "service_memory_bytes";

/// Where a unit's cgroup may be: units with cgroup controls run in
/// `system-ekafleet.slice`, others directly in `system.slice`.
const SLICES: [&str; 2] = ["system.slice", "system.slice/system-ekafleet.slice"];

pub struct CgroupSampler {
    root: PathBuf,
    /// CPU usage (µs) of each service at its previous sample.
    previous: HashMap<String, (Instant, u64)>,
}

impl Default for CgroupSampler {
    fn default() -> Self {
        Self::new(PathBuf::from("/sys/fs/cgroup"))
    }
}

impl CgroupSampler {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            previous: HashMap::new(),
        }
    }

    fn unit_dir(&self, service: &str) -> Option<PathBuf> {
        SLICES
            .iter()
            .map(|slice| {
                self.root
                    .join(slice)
                    .join(format!("ekafleet-{service}.service"))
            })
            .find(|dir| dir.is_dir())
    }

    /// `(service, metric, value)` for each running service.
    pub fn sample(&mut self, services: &[String]) -> Vec<(String, &'static str, f64)> {
        let now = Instant::now();
        let mut out = Vec::new();
        let mut seen = HashMap::new();
        for service in services {
            let Some(dir) = self.unit_dir(service) else {
                continue;
            };
            if let Some(bytes) = read_u64(&dir.join("memory.current")) {
                out.push((service.clone(), MEMORY_METRIC, bytes as f64));
            }
            if let Some(usage) = std::fs::read_to_string(dir.join("cpu.stat"))
                .ok()
                .and_then(|s| usage_usec(&s))
            {
                if let Some(&(then, before)) = self.previous.get(service) {
                    let elapsed = now.duration_since(then).as_micros() as f64;
                    // A restarted unit's counter starts over: skip that round.
                    if elapsed > 0.0 && usage >= before {
                        let millicores = (usage - before) as f64 / elapsed * 1000.0;
                        out.push((service.clone(), CPU_METRIC, millicores));
                    }
                }
                seen.insert(service.clone(), (now, usage));
            }
        }
        // Forget services that stopped.
        self.previous = seen;
        out
    }
}

fn read_u64(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn usage_usec(cpu_stat: &str) -> Option<u64> {
    cpu_stat
        .lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .and_then(|v| v.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_cpu_deltas_and_memory_from_unit_cgroups() {
        let root = tempfile::tempdir().unwrap();
        let unit = root
            .path()
            .join("system.slice/system-ekafleet.slice/ekafleet-api.service");
        std::fs::create_dir_all(&unit).unwrap();
        std::fs::write(unit.join("memory.current"), "1048576\n").unwrap();
        std::fs::write(
            unit.join("cpu.stat"),
            "usage_usec 1000\nuser_usec 800\nsystem_usec 200\n",
        )
        .unwrap();
        let services = vec!["api".to_string(), "gone".to_string()];

        let mut sampler = CgroupSampler::new(root.path().to_path_buf());
        let first = sampler.sample(&services);
        assert_eq!(first, vec![("api".to_string(), MEMORY_METRIC, 1048576.0)]);

        std::thread::sleep(std::time::Duration::from_millis(20));
        // 10ms of CPU over ≥20ms: at most 500 millicores.
        std::fs::write(unit.join("cpu.stat"), "usage_usec 11000\n").unwrap();
        let second = sampler.sample(&services);
        let cpu = second
            .iter()
            .find(|(_, m, _)| *m == CPU_METRIC)
            .map(|(_, _, v)| *v)
            .unwrap();
        assert!(cpu > 0.0 && cpu <= 500.0, "{cpu}");

        // A restarted unit (counter reset) yields no CPU point that round.
        std::fs::write(unit.join("cpu.stat"), "usage_usec 5\n").unwrap();
        assert!(
            sampler
                .sample(&services)
                .iter()
                .all(|(_, m, _)| *m != CPU_METRIC)
        );
    }
}
