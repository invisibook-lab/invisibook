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
