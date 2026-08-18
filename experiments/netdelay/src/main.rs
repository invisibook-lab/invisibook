//! UDP relay that adds a fixed one-way delay and a bandwidth cap between
//! the two traders. It emulates a wide-area link WITHOUT root rights, so
//! the RQ2 sweep needs no `tc`/netem and no `sudo`.
//!
//! Topology — trader A dials the relay, the relay dials trader B:
//!
//! ```text
//!   A ──▶ front socket ──[delay + rate]──▶ back socket ──▶ B
//!   A ◀── front socket ◀─[delay + rate]─── back socket ◀── B
//! ```
//!
//! Every datagram waits `--delay-ms` before it leaves, so the round-trip
//! time between the traders is 2 × `--delay-ms`. A token bucket caps each
//! direction at `--rate-mbit`.
//!
//! Usage:
//!
//! ```text
//! netdelay --listen 127.0.0.1:23500 --peer 127.0.0.1:23412 \
//!          --delay-ms 15 --rate-mbit 1000
//! ```
//!
//! The relay carries ONE flow (one trader pair). It learns trader A's
//! address from A's first datagram and keeps it for the whole session.
//!
//! With `--stats-out <path>` the relay keeps a JSON file up to date with
//! the bytes and datagrams it carried in each direction. That file is the
//! only exact measurement of what the two traders send each other: the
//! Linux per-process I/O counters do not count socket traffic.

use std::{
    collections::VecDeque,
    env, fs,
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    process::exit,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, Sender, channel},
    },
    thread,
    time::{Duration, Instant},
};

/// Largest datagram the relay copies. The loopback MTU is 64 KiB and QUIC
/// may use it, so the buffer takes the largest datagram Linux can deliver.
/// A short buffer would truncate packets without an error.
const MAX_DATAGRAM: usize = 65535;

/// One queued datagram: its payload and the instant it may leave.
struct Delayed {
    at: Instant,
    bytes: Vec<u8>,
}

/// Command-line options.
struct Args {
    listen: SocketAddr,
    peer: SocketAddr,
    delay: Duration,
    rate_bytes_per_sec: f64,
    stats_out: Option<PathBuf>,
}

/// Bytes and datagrams the relay carried, one counter pair per direction.
#[derive(Default)]
struct Counters {
    a_to_b_bytes: AtomicU64,
    a_to_b_datagrams: AtomicU64,
    b_to_a_bytes: AtomicU64,
    b_to_a_datagrams: AtomicU64,
}

impl Counters {
    /// Render the counters as JSON.
    fn to_json(&self) -> String {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        format!(
            "{{\n  \"a_to_b_bytes\": {},\n  \"a_to_b_datagrams\": {},\n  \
             \"b_to_a_bytes\": {},\n  \"b_to_a_datagrams\": {}\n}}\n",
            get(&self.a_to_b_bytes),
            get(&self.a_to_b_datagrams),
            get(&self.b_to_a_bytes),
            get(&self.b_to_a_datagrams),
        )
    }
}

/// Write the counters to `path` through a temporary file, so a reader
/// never sees half a record.
fn write_stats(path: &Path, counters: &Counters) {
    let tmp = path.with_extension("tmp");
    if fs::write(&tmp, counters.to_json()).is_ok() {
        let _ = fs::rename(&tmp, path);
    }
}

/// Parse `--listen`, `--peer`, `--delay-ms` and `--rate-mbit`. All values
/// must be present except `--rate-mbit`, which defaults to 1000 (1 Gbit/s).
fn parse_args() -> Args {
    let mut listen = None;
    let mut peer = None;
    let mut delay_ms = 0f64;
    let mut rate_mbit = 1000f64;
    let mut stats_out = None;
    let argv: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        let need = |i: usize| -> String {
            argv.get(i + 1)
                .unwrap_or_else(|| {
                    eprintln!("netdelay: {} needs a value", argv[i]);
                    exit(2);
                })
                .clone()
        };
        match argv[i].as_str() {
            "--listen" => listen = Some(parse_addr(&need(i))),
            "--peer" => peer = Some(parse_addr(&need(i))),
            "--delay-ms" => delay_ms = parse_f64(&need(i)),
            "--rate-mbit" => rate_mbit = parse_f64(&need(i)),
            "--stats-out" => stats_out = Some(PathBuf::from(need(i))),
            "--help" | "-h" => {
                eprintln!(
                    "usage: netdelay --listen <addr> --peer <addr> \
                     [--delay-ms <ms>] [--rate-mbit <mbit>] [--stats-out <path>]"
                );
                exit(0);
            }
            other => {
                eprintln!("netdelay: unknown option {other}");
                exit(2);
            }
        }
        i += 2;
    }
    let (Some(listen), Some(peer)) = (listen, peer) else {
        eprintln!("netdelay: --listen and --peer are required");
        exit(2);
    };
    Args {
        listen,
        peer,
        delay: Duration::from_secs_f64(delay_ms / 1e3),
        rate_bytes_per_sec: rate_mbit * 1e6 / 8.0,
        stats_out,
    }
}

/// Parse a `host:port` string, or exit with a message.
fn parse_addr(s: &str) -> SocketAddr {
    s.parse().unwrap_or_else(|_| {
        eprintln!("netdelay: {s} is not a host:port address");
        exit(2);
    })
}

/// Parse a decimal number, or exit with a message.
fn parse_f64(s: &str) -> f64 {
    s.parse().unwrap_or_else(|_| {
        eprintln!("netdelay: {s} is not a number");
        exit(2);
    })
}

/// Send queued datagrams when their delay expires. `send` does the actual
/// transmission; the queue is in arrival order, and a constant delay keeps
/// that order equal to release order.
fn sender_loop(rx: Receiver<Delayed>, rate: f64, mut send: impl FnMut(&[u8])) {
    // Token bucket: `tokens` bytes may leave immediately, and the bucket
    // refills at `rate` bytes per second.
    let mut tokens = 0f64;
    let mut last = Instant::now();
    let mut queue: VecDeque<Delayed> = VecDeque::new();
    loop {
        let head = match queue.pop_front() {
            Some(d) => d,
            None => match rx.recv() {
                Ok(d) => d,
                Err(_) => return, // every producer is gone
            },
        };
        let now = Instant::now();
        if head.at > now {
            thread::sleep(head.at - now);
        }
        let now = Instant::now();
        tokens = (tokens + now.duration_since(last).as_secs_f64() * rate).min(rate);
        last = now;
        let need = head.bytes.len() as f64;
        if tokens < need {
            thread::sleep(Duration::from_secs_f64((need - tokens) / rate));
            tokens = need;
            last = Instant::now();
        }
        tokens -= need;
        send(&head.bytes);
        // Drain anything that arrived while this datagram waited.
        while let Ok(d) = rx.try_recv() {
            queue.push_back(d);
        }
    }
}

fn main() {
    let args = parse_args();
    let front = UdpSocket::bind(args.listen).unwrap_or_else(|e| {
        eprintln!("netdelay: cannot bind {}: {e}", args.listen);
        exit(1);
    });
    // The back socket talks to trader B; the OS picks its port.
    let back = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| {
        eprintln!("netdelay: cannot bind the back socket: {e}");
        exit(1);
    });
    eprintln!(
        "netdelay: {} → {} | one-way delay {:.1} ms | rate {:.0} Mbit/s",
        args.listen,
        args.peer,
        args.delay.as_secs_f64() * 1e3,
        args.rate_bytes_per_sec * 8.0 / 1e6
    );

    // Traffic counters, published to --stats-out twice a second.
    let counters = Arc::new(Counters::default());
    if let Some(path) = args.stats_out.clone() {
        let counters = Arc::clone(&counters);
        thread::spawn(move || {
            loop {
                write_stats(&path, &counters);
                thread::sleep(Duration::from_millis(500));
            }
        });
    }

    // Trader A's address, learned from its first datagram.
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let client_seen = Arc::new(AtomicBool::new(false));

    let (to_b_tx, to_b_rx): (Sender<Delayed>, Receiver<Delayed>) = channel();
    let (to_a_tx, to_a_rx): (Sender<Delayed>, Receiver<Delayed>) = channel();

    // A → B sender.
    let back_send = back.try_clone().expect("clone back socket");
    let peer = args.peer;
    let rate = args.rate_bytes_per_sec;
    let t_to_b = thread::spawn(move || {
        sender_loop(to_b_rx, rate, |bytes| {
            let _ = back_send.send_to(bytes, peer);
        })
    });

    // B → A sender.
    let front_send = front.try_clone().expect("clone front socket");
    let client_for_send = Arc::clone(&client);
    let t_to_a = thread::spawn(move || {
        sender_loop(to_a_rx, rate, |bytes| {
            if let Some(addr) = *client_for_send.lock().expect("client address") {
                let _ = front_send.send_to(bytes, addr);
            }
        })
    });

    // B → A receiver.
    let back_recv = back.try_clone().expect("clone back socket");
    let delay = args.delay;
    let counters_b = Arc::clone(&counters);
    let t_from_b = thread::spawn(move || {
        let mut buf = [0u8; MAX_DATAGRAM];
        while let Ok((n, _from)) = back_recv.recv_from(&mut buf) {
            counters_b
                .b_to_a_bytes
                .fetch_add(n as u64, Ordering::Relaxed);
            counters_b.b_to_a_datagrams.fetch_add(1, Ordering::Relaxed);
            let d = Delayed {
                at: Instant::now() + delay,
                bytes: buf[..n].to_vec(),
            };
            if to_a_tx.send(d).is_err() {
                return;
            }
        }
    });

    // A → B receiver, on this thread.
    let mut buf = [0u8; MAX_DATAGRAM];
    while let Ok((n, from)) = front.recv_from(&mut buf) {
        if !client_seen.swap(true, Ordering::SeqCst) {
            *client.lock().expect("client address") = Some(from);
            eprintln!("netdelay: trader A is {from}");
        }
        counters.a_to_b_bytes.fetch_add(n as u64, Ordering::Relaxed);
        counters.a_to_b_datagrams.fetch_add(1, Ordering::Relaxed);
        let d = Delayed {
            at: Instant::now() + delay,
            bytes: buf[..n].to_vec(),
        };
        if to_b_tx.send(d).is_err() {
            break;
        }
    }
    let _ = t_from_b.join();
    let _ = t_to_a.join();
    let _ = t_to_b.join();
    if let Some(path) = args.stats_out {
        write_stats(&path, &counters);
    }
}
