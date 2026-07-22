//! Support harness for the privileged network-namespace conformance tier
//! (`tests/netns_conformance.rs`). Linux only — every item here is compiled
//! out on other platforms by the `#![cfg(target_os = "linux")]` on the parent
//! test target.
//!
//! Design (see `doc/testing-netns.md` and the Phase 2 section of
//! `docs/superpowers/specs/2026-07-07-rfc-compatibility-design.md`):
//!
//! * A [`NetnsFixture`] is an RAII object that creates a pair of network
//!   namespaces joined by a veth link, assigns unique v4/v6 addresses, and
//!   deletes both namespaces on `Drop` (panic-safe). Names embed the process
//!   id and a monotonic counter so concurrent fixtures never collide.
//! * The Session-Reflector under test runs via `ip netns exec` in one
//!   namespace; the Session-Sender is driven from the other, either as the
//!   real binary (`ip netns exec … stamp-suite`) or — for scenarios that need
//!   a packet no CLI can emit — as a crafted UDP datagram sent from a socket
//!   created *inside* the sender namespace via `setns()`.
//! * On-wire behaviour (TOS/ECN, TTL/Hop-Limit, IPv6 extension headers,
//!   Type-12 pacing/count, BER padding) is observed by capturing on the
//!   reflector-side veth with `tcpdump -w` and parsing the classic pcap file
//!   with the tiny in-crate parser below (no pcap crate).
//!
//! Nothing in this module runs privileged code at collection time: the
//! namespace/veth calls happen only inside [`NetnsFixture::new`], which the
//! `#[ignore]`d, root-gated scenarios call explicitly.

#![cfg(target_os = "linux")]

use std::{
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    thread,
    time::{Duration, Instant},
};

/// Absolute path to the compiled `stamp-suite` binary, injected by Cargo for
/// integration tests (the binary target name equals the package name).
pub const BIN: &str = env!("CARGO_BIN_EXE_stamp-suite");

/// Environment variable that opts a run into the privileged tier.
pub const ENABLE_ENV: &str = "STAMP_NETNS_TESTS";

/// Optional path to a reflector binary built with the `ttl-pnet` feature, used
/// by scenario 4b (real extension-header capture). Absent ⇒ 4b skips cleanly.
pub const PNET_BIN_ENV: &str = "STAMP_NETNS_PNET_BIN";

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Prints a uniform SKIP line and returns `()`, so a scenario can early-return
/// with `return netns::emit_skip("name", &reason);`.
pub fn emit_skip(scenario: &str, reason: &str) {
    eprintln!("[netns] SKIP {scenario}: {reason}");
}

/// Prints a uniform PASS line.
pub fn emit_pass(scenario: &str, detail: &str) {
    eprintln!("[netns] PASS {scenario}: {detail}");
}

fn have_cmd(name: &str) -> bool {
    Command::new(name)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.code().is_some())
        .unwrap_or(false)
}

/// True when the effective UID is 0 (root or mapped-root in a user namespace).
pub fn is_root() -> bool {
    // SAFETY: geteuid() is always safe; it only reads the calling process's
    // effective UID and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Common gate for every scenario: opt-in env var, root, and the external
/// tools the harness shells out to. Returns the reason to skip, or `Ok(())`.
pub fn require_env() -> Result<(), String> {
    match std::env::var(ENABLE_ENV) {
        Ok(v) if v == "1" => {}
        _ => return Err(format!("{ENABLE_ENV} != 1 (privileged tier opt-in)")),
    }
    if !is_root() {
        return Err("must run as root / CAP_NET_ADMIN (namespaces + veth)".into());
    }
    if !have_cmd("ip") {
        return Err("`ip` (iproute2) not found in PATH".into());
    }
    if !have_cmd("tcpdump") {
        return Err("`tcpdump` not found in PATH".into());
    }
    Ok(())
}

/// True when SRv6 header insertion is plausibly available (scenario 3 gate).
pub fn seg6_enabled() -> bool {
    read_sysctl("/proc/sys/net/ipv6/conf/all/seg6_enabled")
        .map(|v| v.trim() != "0")
        .unwrap_or(false)
}

fn read_sysctl(path: &str) -> Option<String> {
    let mut s = String::new();
    File::open(path).ok()?.read_to_string(&mut s).ok()?;
    Some(s)
}

/// Runs `ip <args>` and maps a non-zero exit to a descriptive error.
fn ip(args: &[&str]) -> Result<(), String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("spawn `ip {}`: {e}", args.join(" ")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "`ip {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// A reflector child running under `ip netns exec`. Killed on drop.
pub struct Reflector {
    child: Child,
}

impl Drop for Reflector {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A running `tcpdump -w` capture. Consume with [`Capture::stop`].
pub struct Capture {
    child: Child,
    path: PathBuf,
}

impl Drop for Capture {
    fn drop(&mut self) {
        // If the caller didn't call stop() (e.g. a panic), make sure the
        // tcpdump child does not outlive the fixture. Also remove the temp
        // savefile (stop() parses it before this runs).
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Capture {
    /// Signals tcpdump to finish, waits, and returns the parsed packets.
    pub fn stop(mut self) -> Vec<CapturedPacket> {
        // SIGINT lets tcpdump flush and exit cleanly. `-U` already flushes
        // per packet, so even a hard kill would not lose captured frames.
        // SAFETY: kill() with a valid pid and signal only delivers a signal.
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGINT);
        }
        let _ = self.child.wait();
        parse_pcap(&self.path).unwrap_or_default()
    }
}

/// Result of running the real sender binary to completion. `packets_received`
/// is parsed from the sender's JSON summary; `stderr` is kept for diagnostics
/// in assertion messages.
pub struct SenderRun {
    pub packets_received: Option<u32>,
    pub stderr: String,
}

/// A pair of network namespaces joined by a veth link with unique addressing.
pub struct NetnsFixture {
    id: u32,
    ns_refl: String,
    ns_send: String,
    veth_refl: String,
    veth_send: String,
    refl_v4: Ipv4Addr,
    send_v4: Ipv4Addr,
    refl_v6: Ipv6Addr,
    send_v6: Ipv6Addr,
    port: u16,
}

impl Drop for NetnsFixture {
    fn drop(&mut self) {
        // Deleting a namespace also removes any veth end living in it, so this
        // is sufficient teardown even if setup failed partway.
        let _ = ip(&["netns", "del", &self.ns_refl]);
        let _ = ip(&["netns", "del", &self.ns_send]);
    }
}

impl NetnsFixture {
    /// Creates both namespaces, the veth link, and assigns addresses. Any
    /// failure returns `Err` (the caller should treat that as SKIP — it means
    /// the environment can't host the tier, not that the product is wrong).
    pub fn new() -> Result<Self, String> {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let n = (std::process::id().wrapping_mul(131)).wrapping_add(counter);
        let oct2 = ((n >> 8) & 0xff) as u8;
        let oct3 = (n & 0xff) as u8;
        // Interface names must stay <= 15 chars; a 24-bit hex suffix keeps
        // `stvr…`/`stvs…` at most 10 characters and unique per fixture.
        let hex = n & 0x00ff_ffff;
        // IPv6 hextets are 16 bits: split `n` into two valid groups so the
        // ULA `fd00:<h1>:<h2>::/64` prefix always parses.
        let h1 = (n >> 16) & 0xffff;
        let h2 = n & 0xffff;

        let fx = Self {
            id: n,
            ns_refl: format!("stnsr{n}"),
            ns_send: format!("stnss{n}"),
            veth_refl: format!("stvr{hex:x}"),
            veth_send: format!("stvs{hex:x}"),
            refl_v4: Ipv4Addr::new(10, oct2, oct3, 2),
            send_v4: Ipv4Addr::new(10, oct2, oct3, 1),
            refl_v6: format!("fd00:{h1:x}:{h2:x}::2").parse().unwrap(),
            send_v6: format!("fd00:{h1:x}:{h2:x}::1").parse().unwrap(),
            port: 20000 + (n % 20000) as u16,
        };

        fx.setup().map(|()| fx)
    }

    fn setup(&self) -> Result<(), String> {
        ip(&["netns", "add", &self.ns_refl])?;
        ip(&["netns", "add", &self.ns_send])?;
        ip(&[
            "link",
            "add",
            &self.veth_refl,
            "type",
            "veth",
            "peer",
            "name",
            &self.veth_send,
        ])?;
        ip(&["link", "set", &self.veth_refl, "netns", &self.ns_refl])?;
        ip(&["link", "set", &self.veth_send, "netns", &self.ns_send])?;

        self.addr_setup(&self.ns_refl, &self.veth_refl, self.refl_v4, self.refl_v6)?;
        self.addr_setup(&self.ns_send, &self.veth_send, self.send_v4, self.send_v6)?;
        Ok(())
    }

    fn addr_setup(&self, ns: &str, dev: &str, v4: Ipv4Addr, v6: Ipv6Addr) -> Result<(), String> {
        let v4s = format!("{v4}/24");
        let v6s = format!("{v6}/64");
        ip(&["-n", ns, "addr", "add", &v4s, "dev", dev])?;
        // `nodad` makes the v6 address immediately usable (no Duplicate Address
        // Detection wait) — the link is point-to-point and private.
        ip(&["-n", ns, "addr", "add", &v6s, "dev", dev, "nodad"])?;
        ip(&["-n", ns, "link", "set", dev, "up"])?;
        ip(&["-n", ns, "link", "set", "lo", "up"])?;
        Ok(())
    }

    pub fn reflector_v4(&self) -> Ipv4Addr {
        self.refl_v4
    }
    pub fn reflector_v6(&self) -> Ipv6Addr {
        self.refl_v6
    }
    pub fn sender_v4(&self) -> Ipv4Addr {
        self.send_v4
    }
    pub fn sender_v6(&self) -> Ipv6Addr {
        self.send_v6
    }
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Reads the reflector veth's hardware (MAC) address.
    pub fn reflector_mac(&self) -> Result<[u8; 6], String> {
        let out = Command::new("ip")
            .args(["-n", &self.ns_refl, "link", "show", &self.veth_refl])
            .output()
            .map_err(|e| format!("spawn ip link show: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let idx = text
            .find("link/ether ")
            .ok_or_else(|| "no link/ether in `ip link show`".to_string())?;
        let mac_str: String = text[idx + "link/ether ".len()..]
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        parse_mac(&mac_str).ok_or_else(|| format!("unparseable MAC {mac_str:?}"))
    }

    /// Spawns the reflector binary in the reflector namespace, bound to `bind`
    /// on the fixture port, with `extra_args` appended. Waits until its socket
    /// is accepting before returning.
    pub fn spawn_reflector(
        &self,
        bind: IpAddr,
        extra_args: &[&str],
        bin: &str,
    ) -> Result<Reflector, String> {
        let port = self.port.to_string();
        let bind_s = bind.to_string();
        let mut args: Vec<String> = vec![
            "netns".into(),
            "exec".into(),
            self.ns_refl.clone(),
            bin.into(),
            "-i".into(),
            "--local-addr".into(),
            bind_s,
            "--local-port".into(),
            port,
        ];
        args.extend(extra_args.iter().map(|s| (*s).to_string()));

        let child = Command::new("ip")
            .args(&args)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn reflector: {e}"))?;

        let reflector = Reflector { child };
        // Poll until the reflector's UDP port shows up as a listener (or the
        // budget elapses — the caller's traffic then simply retries/times out).
        wait_until(Duration::from_secs(3), || self.reflector_bound());
        Ok(reflector)
    }

    fn reflector_bound(&self) -> bool {
        // Check for the bound UDP port via `ss` inside the reflector namespace.
        // If `ss` is absent, report "not confirmable" and let the fixed poll
        // budget elapse before the caller proceeds.
        match Command::new("ip")
            .args(["netns", "exec", &self.ns_refl, "ss", "-uln"])
            .output()
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains(&format!(":{}", self.port)),
            Err(_) => false,
        }
    }

    /// Runs the real sender binary in the sender namespace to completion,
    /// returning parsed stats.
    pub fn run_sender(&self, remote: IpAddr, local: IpAddr, extra_args: &[&str]) -> SenderRun {
        let sport = (self.port.wrapping_add(1)).to_string();
        let port = self.port.to_string();
        let mut args: Vec<String> = vec![
            "netns".into(),
            "exec".into(),
            self.ns_send.clone(),
            BIN.into(),
            "--remote-addr".into(),
            remote.to_string(),
            "--remote-port".into(),
            port,
            "--local-addr".into(),
            local.to_string(),
            "--local-port".into(),
            sport,
            "--output-format".into(),
            "json".into(),
        ];
        args.extend(extra_args.iter().map(|s| (*s).to_string()));

        let child = Command::new("ip")
            .args(&args)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let child = match child {
            Ok(c) => c,
            Err(e) => {
                return SenderRun {
                    packets_received: None,
                    stderr: format!("spawn sender: {e}"),
                }
            }
        };

        let out = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                return SenderRun {
                    packets_received: None,
                    stderr: format!("wait sender: {e}"),
                }
            }
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        SenderRun {
            packets_received: parse_json_u32(&stdout, "packets_received"),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Starts a tcpdump capture on the reflector-side veth (sees both the
    /// arriving test packets and the departing reflected packets).
    pub fn start_capture(&self) -> Result<Capture, String> {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("stamp-netns-{}.pcap", self.id));
        let path_s = path.to_string_lossy().into_owned();
        let child = Command::new("ip")
            .args([
                "netns",
                "exec",
                &self.ns_refl,
                "tcpdump",
                "-i",
                &self.veth_refl,
                "-n",
                "-p",
                "-U",
                "-s",
                "0",
                // Stay root rather than dropping to the unprivileged `tcpdump`
                // user: privilege-drop chowns the savefile, which fails in a
                // mapped-root user namespace (and is pointless for a temp
                // capture under sudo). Without this tcpdump exits immediately
                // with "Couldn't change ownership of savefile".
                "-Z",
                "root",
                "-w",
                &path_s,
                "udp",
            ])
            .stdout(Stdio::null())
            // Discard stderr entirely: consuming it and closing the pipe early
            // (e.g. after matching "listening on") can SIGPIPE tcpdump and lose
            // the capture, so we don't parse readiness from it — we simply wait.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn tcpdump: {e}"))?;

        // tcpdump writes the 24-byte pcap header immediately, then attaches to
        // the interface. There is no race-free readiness signal we can consume
        // without risking its stderr pipe, so wait a conservative window before
        // any traffic is generated.
        thread::sleep(Duration::from_millis(800));
        Ok(Capture { child, path })
    }

    /// Sends a raw UDP payload to the reflector from a socket created *inside*
    /// the sender namespace, returning the reply bytes (or `None` on timeout).
    ///
    /// Used by scenarios that must originate a packet the sender CLI cannot
    /// build (Address Group sub-TLVs). `dstopts`, when present, installs a
    /// sticky IPv6 Destination Options extension header on the socket so the
    /// kernel prepends it to the datagram (best-effort ext-header injection).
    pub fn udp_exchange_from_sender(
        &self,
        dst: SocketAddr,
        payload: &[u8],
        dstopts: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Option<Vec<u8>>, String> {
        let bind: IpAddr = match dst {
            SocketAddr::V4(_) => IpAddr::V4(self.send_v4),
            SocketAddr::V6(_) => IpAddr::V6(self.send_v6),
        };
        let _guard = NsGuard::enter(&self.ns_send)?;
        let sock = std::net::UdpSocket::bind(SocketAddr::new(bind, 0))
            .map_err(|e| format!("bind in {}: {e}", self.ns_send))?;
        if let Some(opts) = dstopts {
            set_ipv6_dstopts(sock.as_raw_fd(), opts)?;
        }
        sock.set_read_timeout(Some(timeout))
            .map_err(|e| format!("set_read_timeout: {e}"))?;
        sock.send_to(payload, dst)
            .map_err(|e| format!("send_to: {e}"))?;
        let mut buf = [0u8; 4096];
        match sock.recv_from(&mut buf) {
            Ok((len, _)) => Ok(Some(buf[..len].to_vec())),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(format!("recv_from: {e}")),
        }
        // _guard drops here → the calling thread's netns is restored.
    }
}

/// Restores the calling thread's network namespace when dropped.
struct NsGuard {
    original: File,
}

impl NsGuard {
    fn enter(ns: &str) -> Result<Self, String> {
        let original =
            File::open("/proc/self/ns/net").map_err(|e| format!("open /proc/self/ns/net: {e}"))?;
        let target = File::open(format!("/run/netns/{ns}"))
            .or_else(|_| File::open(format!("/var/run/netns/{ns}")))
            .map_err(|e| format!("open netns {ns}: {e}"))?;
        // SAFETY: setns() with a valid namespace fd and CLONE_NEWNET only
        // changes the calling thread's network namespace.
        let rc = unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) };
        if rc != 0 {
            return Err(format!("setns({ns}): {}", std::io::Error::last_os_error()));
        }
        Ok(Self { original })
    }
}

impl Drop for NsGuard {
    fn drop(&mut self) {
        // SAFETY: restoring to the fd captured on entry; failure here would
        // leak the thread into the test namespace, but there is no safe
        // recovery inside Drop, so we best-effort it.
        unsafe {
            libc::setns(self.original.as_raw_fd(), libc::CLONE_NEWNET);
        }
    }
}

fn set_ipv6_dstopts(fd: std::os::fd::RawFd, opts: &[u8]) -> Result<(), String> {
    // SAFETY: setsockopt with a byte buffer of the given length; the kernel
    // validates the extension-header contents and rejects a malformed buffer.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_DSTOPTS,
            opts.as_ptr().cast(),
            opts.len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        Err(format!(
            "setsockopt(IPV6_DSTOPTS): {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

/// Builds a minimal 8-octet IPv6 Destination Options header carrying a single
/// PadN option (used by scenario 4b). Byte 0 (Next Header) is filled by the
/// kernel; byte 1 is HdrExtLen (0 ⇒ 8 octets); the remaining 6 octets are a
/// PadN option (type 1, len 4, four zero bytes).
pub fn build_destopts_padn() -> Vec<u8> {
    vec![0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

fn wait_until(budget: Duration, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn parse_json_u32(s: &str, key: &str) -> Option<u32> {
    let needle = format!("\"{key}\":");
    let start = s.find(&needle)? + needle.len();
    let rest = &s[start..];
    let digits: String = rest
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

// ===========================================================================
// Minimal classic-pcap parser (no external crate).
// ===========================================================================

/// A single captured frame, decoded down to the STAMP UDP payload.
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    /// Capture timestamp in nanoseconds since the pcap epoch.
    pub ts_ns: u128,
    pub is_v6: bool,
    /// IPv4 TOS byte or IPv6 Traffic Class byte (DSCP<<2 | ECN).
    pub tos: u8,
    /// IPv4 TTL or IPv6 Hop Limit.
    pub ttl: u8,
    pub src_port: u16,
    pub dst_port: u16,
    /// IPv6 extension headers in order, each `(header_type, raw_on_wire_bytes)`
    /// where `header_type` is the IP protocol number naming the header
    /// (0 = Hop-by-Hop, 43 = Routing/SRH, 44 = Fragment, 60 = Destination
    /// Options) and the bytes are that header verbatim from the wire (its own
    /// Next Header octet first). Empty for IPv4 or a header-less IPv6 packet.
    pub ext_headers: Vec<(u8, Vec<u8>)>,
    /// The UDP payload (the STAMP packet + any TLVs).
    pub payload: Vec<u8>,
}

impl CapturedPacket {
    pub fn dscp(&self) -> u8 {
        self.tos >> 2
    }
    pub fn ecn(&self) -> u8 {
        self.tos & 0x03
    }
}

fn parse_pcap(path: &PathBuf) -> Option<Vec<CapturedPacket>> {
    let mut data = Vec::new();
    File::open(path).ok()?.read_to_end(&mut data).ok()?;
    if data.len() < 24 {
        return Some(Vec::new());
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (little, nanos) = match magic {
        0xa1b2_c3d4 => (true, false),
        0xa1b2_3c4d => (true, true),
        0xd4c3_b2a1 => (false, false),
        0x4d3c_b2a1 => (false, true),
        _ => return Some(Vec::new()),
    };
    let rd_u32 = |b: &[u8]| -> u32 {
        if little {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let linktype = rd_u32(&data[20..24]);
    // Ethernet (1) is what veth capture yields; Linux SLL (113) as a fallback.
    let (l2_len, ethertype_off) = match linktype {
        1 => (14usize, 12usize),
        113 => (16usize, 14usize),
        _ => return Some(Vec::new()),
    };

    let mut out = Vec::new();
    let mut off = 24usize;
    while off + 16 <= data.len() {
        let ts_sec = rd_u32(&data[off..off + 4]) as u128;
        let ts_frac = rd_u32(&data[off + 4..off + 8]) as u128;
        let incl = rd_u32(&data[off + 8..off + 12]) as usize;
        off += 16;
        if off + incl > data.len() {
            break;
        }
        let frame = &data[off..off + incl];
        off += incl;
        let ts_ns = ts_sec * 1_000_000_000 + if nanos { ts_frac } else { ts_frac * 1000 };
        if let Some(pkt) = decode_frame(frame, l2_len, ethertype_off, ts_ns) {
            out.push(pkt);
        }
    }
    Some(out)
}

fn decode_frame(
    frame: &[u8],
    l2_len: usize,
    ethertype_off: usize,
    ts_ns: u128,
) -> Option<CapturedPacket> {
    if frame.len() < ethertype_off + 2 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[ethertype_off], frame[ethertype_off + 1]]);
    let ip = &frame.get(l2_len..)?;
    match ethertype {
        0x0800 => decode_ipv4(ip, ts_ns),
        0x86DD => decode_ipv6(ip, ts_ns),
        _ => None,
    }
}

fn decode_ipv4(ip: &[u8], ts_ns: u128) -> Option<CapturedPacket> {
    if ip.len() < 20 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let tos = ip[1];
    let ttl = ip[8];
    let proto = ip[9];
    if proto != 17 || ip.len() < ihl + 8 {
        return None;
    }
    let udp = &ip[ihl..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let payload = udp.get(8..).unwrap_or(&[]).to_vec();
    Some(CapturedPacket {
        ts_ns,
        is_v6: false,
        tos,
        ttl,
        src_port,
        dst_port,
        ext_headers: Vec::new(),
        payload,
    })
}

fn decode_ipv6(ip: &[u8], ts_ns: u128) -> Option<CapturedPacket> {
    if ip.len() < 40 {
        return None;
    }
    let tclass = ((ip[0] & 0x0f) << 4) | ((ip[1] & 0xf0) >> 4);
    let hop = ip[7];
    let mut next = ip[6];
    let mut cur = 40usize;
    let mut ext_headers = Vec::new();

    // Extension headers that use the (NextHdr, HdrExtLen, …) shape.
    loop {
        match next {
            // Hop-by-Hop (0), Routing (43), Destination Options (60): length in
            // 8-octet units, +1, excluding the first 8.
            0 | 43 | 60 => {
                if cur + 2 > ip.len() {
                    return None;
                }
                let hdr_next = ip[cur];
                let len = (ip[cur + 1] as usize + 1) * 8;
                if cur + len > ip.len() {
                    return None;
                }
                ext_headers.push((next, ip[cur..cur + len].to_vec()));
                next = hdr_next;
                cur += len;
            }
            // Fragment header is a fixed 8 octets.
            44 => {
                if cur + 8 > ip.len() {
                    return None;
                }
                let hdr_next = ip[cur];
                ext_headers.push((next, ip[cur..cur + 8].to_vec()));
                next = hdr_next;
                cur += 8;
            }
            _ => break,
        }
    }

    if next != 17 || cur + 8 > ip.len() {
        return None;
    }
    let udp = &ip[cur..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let payload = udp.get(8..).unwrap_or(&[]).to_vec();
    Some(CapturedPacket {
        ts_ns,
        is_v6: true,
        tos: tclass,
        ttl: hop,
        src_port,
        dst_port,
        ext_headers,
        payload,
    })
}
