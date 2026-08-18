//! Small measurement helpers shared by the binaries.

/// Peak resident set size of this process in bytes (Linux `VmHWM`), or 0 if
/// unavailable.
pub fn peak_rss_bytes() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

/// Serialized (compressed) size in bytes of an ark type.
pub fn compressed_size<T: ark_serialize::CanonicalSerialize>(t: &T) -> usize {
    t.compressed_size()
}

// ────────────────────── Per-step protocol timing ──────────────────────

use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Wall-clock of every protocol step, in the order the session crosses
/// them. The labels match the numbered steps in
/// `docs/settlement_protocol.md` §2.2, so a benchmark table lines up with
/// the protocol walkthrough one row per step.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StepTimings {
    /// `(step label, milliseconds spent in that step)`, in protocol order.
    pub steps: Vec<(String, f64)>,
}

impl StepTimings {
    /// Milliseconds recorded for `label`, or 0.0 when the step did not run
    /// (for example the reveal when the two quantities are equal).
    pub fn get(&self, label: &str) -> f64 {
        self.steps
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, ms)| *ms)
            .unwrap_or(0.0)
    }
}

/// Stopwatch that records the time between consecutive `lap` calls.
/// Construct it when the session starts; call `lap` at every step
/// boundary with that step's label.
pub struct StepTimer {
    last: Instant,
    steps: Vec<(String, f64)>,
}

impl Default for StepTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl StepTimer {
    pub fn new() -> Self {
        Self {
            last: Instant::now(),
            steps: Vec::new(),
        }
    }

    /// Close the step that ends here and start the next one.
    pub fn lap(&mut self, label: &str) {
        let now = Instant::now();
        let ms = now.duration_since(self.last).as_secs_f64() * 1e3;
        self.steps.push((label.to_string(), ms));
        self.last = now;
    }

    /// Consume the timer and return everything it recorded.
    pub fn finish(self) -> StepTimings {
        StepTimings { steps: self.steps }
    }
}
