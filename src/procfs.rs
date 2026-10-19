// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Linux `/proc/<pid>/stat` and `/proc/<pid>/status` sampling for CPU
//! and memory utilization.
//!
//! CPU % is computed as the delta of utime+stime (clock ticks) between two
//! samples, divided by the elapsed wall time, normalised to 0-100.
//!
//! Memory % is `rss / total_system_memory * 100`.
//!
//! On non-Linux platforms these return 0.0 (Captain is a Linux-only
//! supervisor in production; on dev macOS the metrics are best-effort).

/// Sampled CPU and memory for a pid.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcSample {
    /// CPU utilisation 0-100.
    pub cpu_pct: f32,
    /// Memory utilisation 0-100 (rss / memtotal).
    pub mem_pct: f32,
    /// Resident set size in MiB (rss pages × page size / 1 MiB).
    pub rss_mb: f32,
}

/// Read jiffies (utime + stime) and rss (pages) for `pid` from
/// `/proc/<pid>/stat`. Returns `None` if the process is gone.
fn read_proc_stat(pid: u32) -> Option<(u64, u64)> {
    let path = format!("/proc/{pid}/stat");
    let content = std::fs::read_to_string(&path).ok()?;
    // /proc/<pid>/stat is space-separated; the comm field may contain
    // spaces and is wrapped in parens, so parse from the last ')' onward.
    let after_comm = content
        .rsplit_once(')')
        .map(|(_, rest)| rest.trim_start())
        .unwrap_or(&content);
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // After comm (field 2), fields are 0-indexed here as:
    // [0]=state [1]=ppid... [11]=utime [12]=stime... [20]=vsize [21]=rss
    if fields.len() < 22 {
        return None;
    }
    let utime: u64 = fields[11].parse().ok()?;
    let stime: u64 = fields[12].parse().ok()?;
    let rss: u64 = fields[21].parse().ok()?;
    Some((utime + stime, rss))
}

/// Total system memory in pages (from `/proc/meminfo`).
fn total_system_pages() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            // "MemTotal: 16384000 kB"
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            // Convert kB → pages (page size 4096 = 4 kB).
            return Some(kb / 4);
        }
    }
    None
}

#[cfg(target_os = "linux")]
const CLK_TCK: i64 = 100; // sysconf(_SC_CLK_TCK) on Linux is virtually always 100.

// ── Tick-based CPU sampling (no sleep) ──────────────────────────────────

/// Per-PID previous jiffies snapshot for tick-based CPU sampling.
/// Keyed by PID; cleared when a process is gone.
#[cfg(target_os = "linux")]
static PREV_JIFFIES: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<u32, (u64, std::time::Instant)>>,
> = std::sync::OnceLock::new();

/// Sample CPU and memory for `pid` using the **tick-based** method.
///
/// Diffs `/proc/<pid>/stat` jiffies between consecutive calls (one per
/// monitor tick, ~10s apart). The first call for a given PID returns
/// `cpu_pct = 0.0` (no previous sample to diff against). Memory (rss)
/// is read fresh each call - no sleep needed.
///
/// This replaces `sample` in the monitor loop, eliminating the 100ms
/// × N services blocking sleep. The CPU% window now matches the host
/// CPU% window (both are 10s deltas), and both are normalised to the
/// whole machine (divided by the number of CPU cores), so
/// `sum(services CPU%) + other processes + free CPU ≈ 100`.
pub fn sample_tick(pid: u32) -> ProcSample {
    let (jiffies, rss_pages) = match read_proc_stat(pid) {
        Some(v) => v,
        None => {
            // Process gone - clean up its entry.
            #[cfg(target_os = "linux")]
            {
                if let Some(mutex) = PREV_JIFFIES.get() {
                    if let Ok(mut map) = mutex.lock() {
                        map.remove(&pid);
                    }
                }
            }
            return ProcSample::default();
        }
    };

    // Memory - read fresh each call, no sleep needed.
    let mem_pct = total_system_pages()
        .filter(|t| *t > 0)
        .map(|t| (rss_pages as f32 / t as f32) * 100.0)
        .unwrap_or(0.0)
        .clamp(0.0, 100.0);
    let rss_mb = (rss_pages as f32 * 4.0) / 1024.0;

    #[cfg(not(target_os = "linux"))]
    {
        let _ = jiffies;
        ProcSample {
            cpu_pct: 0.0,
            mem_pct,
            rss_mb,
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mutex =
            PREV_JIFFIES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
        let cpu_pct = {
            let mut map = mutex.lock().unwrap();
            let now = std::time::Instant::now();
            let cpu_pct = if let Some((prev_jif, prev_time)) = map.get(&pid) {
                let djif = jiffies.saturating_sub(*prev_jif) as f32;
                let elapsed = now.duration_since(*prev_time).as_secs_f32();
                if elapsed > 0.0 {
                    // djif jiffies over `elapsed` seconds.
                    // 100% CPU (one core) = CLK_TCK jiffies/sec.
                    // Divide by num_cores so 100% = the whole machine
                    // (matches /proc/stat host CPU% scale).
                    let per_core = (djif / CLK_TCK as f32) / elapsed * 100.0;
                    (per_core / num_cpus() as f32).clamp(0.0, 100.0)
                } else {
                    0.0
                }
            } else {
                0.0 // first sample - no delta yet
            };
            map.insert(pid, (jiffies, now));
            cpu_pct
        };
        ProcSample {
            cpu_pct,
            mem_pct,
            rss_mb,
        }
    }
}

/// Check whether a pid is alive (sends no signal; kill -0).
pub fn pid_alive(pid: u32) -> bool {
    // Check if the process exists AND is not a zombie.
    // kill(pid, 0) returns 0 for zombies too (they still exist in the
    // process table), so we also check /proc/<pid>/stat for state 'Z'.
    let r = unsafe { libc_kill(pid, 0) };
    if r != 0 {
        return false;
    }
    // On Linux, check for zombie state. On other platforms, trust kill.
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            // The state field is the first char after the comm field's
            // closing paren. Find the last ')' and check the next char.
            if let Some((_, rest)) = content.rsplit_once(')') {
                let state = rest.trim_start().chars().next().unwrap_or(' ');
                if state == 'Z' {
                    return false; // zombie - process is dead
                }
            }
        }
    }
    true
}

#[cfg(not(target_os = "linux"))]
fn read_proc_stat(_pid: u32) -> Option<(u64, u64)> {
    None
}
#[cfg(not(target_os = "linux"))]
fn total_system_pages() -> Option<u64> {
    None
}
#[cfg(not(target_os = "linux"))]
const CLK_TCK: i64 = 100;

// Minimal `kill` binding to avoid pulling in the `nix`/`libc` crates just
// for this one call. We declare the extern ourselves.
extern "C" {
    fn kill(pid: u32, sig: i32) -> i32;
}
#[allow(non_snake_case)]
unsafe fn libc_kill(pid: u32, sig: i32) -> i32 {
    kill(pid, sig)
}

// ── Whole-host sampling ────────────────────────────────────────────────

/// Whole-host CPU and memory snapshot.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostSample {
    /// Total CPU utilisation 0-100 (all cores combined).
    pub cpu_pct: f32,
    /// Total memory utilisation 0-100 (used / memtotal).
    pub mem_pct: f32,
    /// Used memory in MiB.
    pub used_mb: f32,
}

#[cfg(target_os = "linux")]
static PREV_CPU: std::sync::OnceLock<std::sync::Mutex<(u64, u64, u64, u64)>> =
    std::sync::OnceLock::new();

/// Telemetry mode (FLEET-5, DESIGN §11.6): `procfs` (default - whole-host
/// `/proc` reads, correct for bare-metal/cloud) or `cgroup` (the
/// container's OWN cgroup v2 namespace - `/proc/stat` is NOT namespaced,
/// so every docker-backend sibling reports host-level saturation in
/// lockstep; the cgroup read reflects the container). Unrecognized values
/// fail safe to `procfs`.
/// Handle telemetry mode.
pub fn telemetry_mode() -> &'static str {
    match std::env::var("SENTIN8_CAPTAIN_TELEMETRY").as_deref() {
        Ok("cgroup") => "cgroup",
        _ => "procfs",
    }
}

/// Sample whole-host CPU and memory. The mode is selected by
/// [`telemetry_mode`] - see its doc for the cgroup rationale.
///
/// CPU% is computed as the delta of (busy vs total) ticks between two
/// calls - the first call returns 0.0 because there's no previous sample
/// to diff against. Memory is read fresh each call.
pub fn sample_host() -> HostSample {
    #[cfg(not(target_os = "linux"))]
    {
        HostSample::default()
    }
    #[cfg(target_os = "linux")]
    {
        if telemetry_mode() == "cgroup" {
            return sample_host_cgroup();
        }
        sample_host_procfs()
    }
}

/// The `procfs` mode (DESIGN §11.6): whole-host `/proc/stat` +
/// `/proc/meminfo` - the pre-cgroup behavior, default for bare-metal and
/// cloud machines.
#[cfg(target_os = "linux")]
fn sample_host_procfs() -> HostSample {
    let mem_total_kb = read_meminfo_kb("MemTotal").unwrap_or(0);
    let mem_avail_kb = read_meminfo_kb("MemAvailable").unwrap_or(mem_total_kb);
    let used_kb = mem_total_kb.saturating_sub(mem_avail_kb);
    let mem_pct = if mem_total_kb > 0 {
        (used_kb as f32 / mem_total_kb as f32) * 100.0
    } else {
        0.0
    };
    let used_mb = used_kb as f32 / 1024.0;

    // Read /proc/stat line 1: "cpu user nice system idle..."
    let cpu_line = match std::fs::read_to_string("/proc/stat") {
        Ok(content) => content.lines().next().unwrap_or("").to_string(),
        Err(_) => {
            return HostSample {
                cpu_pct: 0.0,
                mem_pct,
                used_mb,
            }
        }
    };
    let fields: Vec<&str> = cpu_line.split_whitespace().collect();
    if fields.len() < 5 {
        return HostSample {
            cpu_pct: 0.0,
            mem_pct,
            used_mb,
        };
    }
    let user: u64 = fields[1].parse().unwrap_or(0);
    let nice: u64 = fields[2].parse().unwrap_or(0);
    let system: u64 = fields[3].parse().unwrap_or(0);
    let idle: u64 = fields[4].parse().unwrap_or(0);
    let busy = user + nice + system;
    let total = busy + idle;

    let mutex = PREV_CPU.get_or_init(|| std::sync::Mutex::new((0u64, 0u64, 0u64, 0u64)));
    let cpu_pct = {
        let mut prev = mutex.lock().unwrap();
        let (p_busy, p_total, _, _) = *prev;
        *prev = (busy, total, 0, 0);
        let d_busy = busy.saturating_sub(p_busy) as f32;
        let d_total = total.saturating_sub(p_total) as f32;
        if d_total > 0.0 {
            (d_busy / d_total * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        }
    };

    HostSample {
        cpu_pct,
        mem_pct,
        used_mb,
    }
}

/// The `cgroup` mode (FLEET-5, DESIGN §11.6): read the container's OWN
/// cgroup v2 accounting - `cpu.stat` (usec) for CPU%, `memory.current` +
/// `memory.max` for memory. In a container namespace `/proc/stat` reports
/// the HOST, so sibling containers saturate in lockstep and the
/// autoscaler's signal is garbage; the cgroup read is the container's
/// truth. Falls back to the procfs sample when the cgroup files are
/// absent (bare host running without a container runtime).
#[cfg(target_os = "linux")]
fn sample_host_cgroup() -> HostSample {
    let base = std::path::Path::new("/sys/fs/cgroup");
    // cgroup v2: memory.current / memory.max are at the namespace root.
    let mem_current: u64 = std::fs::read_to_string(base.join("memory.current"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let mem_max: u64 = std::fs::read_to_string(base.join("memory.max"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let cpu_stat = std::fs::read_to_string(base.join("cpu.stat")).ok();
    let Some(cpu_stat) = cpu_stat else {
        return sample_host_procfs();
    };
    let mut usec: u64 = 0;
    for line in cpu_stat.lines() {
        if let Some(rest) = line.strip_prefix("usage_usec") {
            usec = rest.trim().parse().unwrap_or(0);
            break;
        }
    }
    if usec == 0 || mem_max == 0 {
        return sample_host_procfs();
    }
    let used_mb = mem_current as f32 / (1024.0 * 1024.0);
    let mem_pct = ((mem_current as f32 / mem_max as f32) * 100.0).clamp(0.0, 100.0);
    let cpu_pct = {
        let mutex = PREV_CPU.get_or_init(|| std::sync::Mutex::new((0u64, 0u64, 0u64, 0u64)));
        let mut prev = mutex.lock().unwrap();
        let (p_usec, _, _, _) = *prev;
        *prev = (usec, 0, 0, 0);
        // Delta µs of CPU over delta wall-clock µs since the last sample,
        // scaled by the core count (100% = one full core per core).
        static PREV_WALL: std::sync::OnceLock<std::sync::Mutex<Option<std::time::Instant>>> =
            std::sync::OnceLock::new();
        let cell = PREV_WALL.get_or_init(|| std::sync::Mutex::new(None));
        let mut guard = cell.lock().unwrap();
        let Some(before) = *guard else {
            // First call: no previous wall anchor → report 0 (the same
            // contract as the procfs mode's first call).
            *guard = Some(std::time::Instant::now());
            return HostSample {
                cpu_pct: 0.0,
                mem_pct,
                used_mb,
            };
        };
        let now = std::time::Instant::now();
        *guard = Some(now);
        let wall = now.duration_since(before).as_micros() as u64;
        let d_cpu = usec.saturating_sub(p_usec) as f64;
        let cores = num_cpus() as f64;
        let pct = if wall > 0 {
            (d_cpu / wall as f64 / cores) * 100.0
        } else {
            0.0
        };
        (pct as f32).clamp(0.0, 100.0)
    };
    HostSample {
        cpu_pct,
        mem_pct,
        used_mb,
    }
}

#[cfg(target_os = "linux")]
fn read_meminfo_kb(key: &str) -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}:")) {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb);
        }
    }
    None
}

/// Number of CPU cores (from `/proc/cpuinfo` on Linux, fallback 1).
fn num_cpus() -> usize {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            let count = content
                .lines()
                .filter(|l| l.starts_with("processor"))
                .count();
            if count > 0 {
                return count;
            }
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
