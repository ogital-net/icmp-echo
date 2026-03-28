use std::cell::Cell;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

static SEQUENCE: AtomicU16 = AtomicU16::new(1);
static ID_COUNTER: AtomicU16 = AtomicU16::new(1);

thread_local! {
    static THREAD_ID: Cell<u16> = const { Cell::new(0) };
}

/// Get a machine-unique identifier for this thread.
/// Combines process ID with a per-thread counter via XOR to ensure uniqueness
/// across both threads and processes on the same machine.
fn get_echo_id() -> u16 {
    THREAD_ID.with(|id| {
        let current = id.get();
        if current == 0 {
            let thread_num = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
            #[allow(clippy::cast_possible_truncation)]
            let process_id = std::process::id() as u16;
            // XOR thread number with process ID for machine-wide uniqueness
            let unique_id = thread_num ^ process_id;
            id.set(unique_id);
            unique_id
        } else {
            current
        }
    })
}

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP6_ECHO_REQUEST: u8 = 128;
const ICMP6_ECHO_REPLY: u8 = 129;
const IPPROTO_ICMP: libc::c_int = 1;
const IPPROTO_ICMPV6: libc::c_int = 58;

struct Socket(i32);

impl Socket {
    fn as_fd(&self) -> i32 {
        self.0
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

enum Domain {
    Ipv4,
    Ipv6,
}

fn create_socket(domain: Domain, timeout: Duration) -> io::Result<Socket> {
    let (af, protocol) = match domain {
        Domain::Ipv4 => (libc::AF_INET, IPPROTO_ICMP),
        Domain::Ipv6 => (libc::AF_INET6, IPPROTO_ICMPV6),
    };

    let sock = unsafe {
        let fd = libc::socket(af, libc::SOCK_RAW, protocol);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Socket(fd)
    };

    // Set receive timeout
    #[allow(clippy::cast_possible_wrap)]
    let timeval = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };

    unsafe {
        if libc::setsockopt(
            sock.as_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeval).cast::<libc::c_void>(),
            #[allow(clippy::cast_possible_truncation)]
            {
                mem::size_of::<libc::timeval>() as libc::socklen_t
            },
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }

    match domain {
        Domain::Ipv4 => {
            // Set Do Not Fragment bit
            unsafe {
                #[cfg(target_os = "linux")]
                {
                    let val: libc::c_int = libc::IP_PMTUDISC_DO;
                    if libc::setsockopt(
                        sock.as_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_MTU_DISCOVER,
                        (&raw const val).cast::<libc::c_void>(),
                        #[allow(clippy::cast_possible_truncation)]
                        {
                            mem::size_of::<libc::c_int>() as libc::socklen_t
                        },
                    ) < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let val: libc::c_int = 1;
                    if libc::setsockopt(
                        sock.as_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_DONTFRAG,
                        (&raw const val).cast::<libc::c_void>(),
                        #[allow(clippy::cast_possible_truncation)]
                        {
                            mem::size_of::<libc::c_int>() as libc::socklen_t
                        },
                    ) < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
        }
        Domain::Ipv6 => {
            // Tell kernel to calculate ICMPv6 checksum (Linux only)
            // Note: On macOS/BSD, the kernel automatically calculates ICMPv6 checksums
            // and the IPV6_CHECKSUM socket option is not supported
            #[cfg(target_os = "linux")]
            unsafe {
                let offset: libc::c_int = 2;
                if libc::setsockopt(
                    sock.as_fd(),
                    IPPROTO_ICMPV6,
                    libc::IPV6_CHECKSUM,
                    (&raw const offset).cast::<libc::c_void>(),
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        mem::size_of::<libc::c_int>() as libc::socklen_t
                    },
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }

            // Set Do Not Fragment bit for IPv6
            unsafe {
                #[cfg(target_os = "linux")]
                let (level, optname, val) = (
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    libc::IPV6_PMTUDISC_DO,
                );
                #[cfg(not(target_os = "linux"))]
                let (level, optname, val) =
                    (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1 as libc::c_int);

                if libc::setsockopt(
                    sock.as_fd(),
                    level,
                    optname,
                    (&raw const val).cast::<libc::c_void>(),
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        mem::size_of::<libc::c_int>() as libc::socklen_t
                    },
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
        }
    }

    Ok(sock)
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct IcmpHeader {
    typ: u8,
    code: u8,
    checksum: u16,
    id: u16,
    sequence: u16,
}

impl IcmpHeader {
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((self as *const IcmpHeader).cast::<u8>(), IcmpHeader::len())
        }
    }

    fn len() -> usize {
        mem::size_of::<IcmpHeader>()
    }
}

impl TryFrom<&[u8]> for IcmpHeader {
    type Error = io::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != IcmpHeader::len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid ICMP header size: expected {}, got {}",
                    IcmpHeader::len(),
                    bytes.len()
                ),
            ));
        }

        unsafe {
            let mut header = mem::MaybeUninit::<IcmpHeader>::uninit();
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                header.as_mut_ptr().cast::<u8>(),
                IcmpHeader::len(),
            );
            Ok(header.assume_init())
        }
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Timestamp {
    sec: u32,
    nsec: u32,
}

impl Timestamp {
    /// Get the current monotonic time as a Timestamp.
    /// Uses `CLOCK_MONOTONIC` which is not affected by system clock adjustments.
    fn now() -> Self {
        let mut ts = mem::MaybeUninit::<libc::timespec>::uninit();

        let result = unsafe {
            #[cfg(target_vendor = "apple")]
            let clock_id = libc::CLOCK_UPTIME_RAW;
            #[cfg(not(target_vendor = "apple"))]
            let clock_id = libc::CLOCK_MONOTONIC;

            libc::clock_gettime(clock_id, ts.as_mut_ptr())
        };

        assert_eq!(
            result,
            0,
            "clock_gettime failed: {}",
            io::Error::last_os_error()
        );

        let ts = unsafe { ts.assume_init() };

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Timestamp {
            sec: ts.tv_sec as u32,
            nsec: ts.tv_nsec as u32,
        }
    }

    /// Convert the timestamp to a byte slice.
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((self as *const Timestamp).cast::<u8>(), Timestamp::len())
        }
    }

    /// Return the size of the Timestamp struct in bytes.
    fn len() -> usize {
        mem::size_of::<Timestamp>()
    }
}

impl TryFrom<&[u8]> for Timestamp {
    type Error = io::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != Timestamp::len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid timestamp size: expected {}, got {}",
                    Timestamp::len(),
                    bytes.len()
                ),
            ));
        }

        unsafe {
            let mut ts = mem::MaybeUninit::<Timestamp>::uninit();
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                ts.as_mut_ptr().cast::<u8>(),
                Timestamp::len(),
            );
            Ok(ts.assume_init())
        }
    }
}

impl std::ops::Sub for Timestamp {
    type Output = Duration;

    fn sub(self, rhs: Timestamp) -> Duration {
        let self_total_nsec = u64::from(self.sec) * 1_000_000_000 + u64::from(self.nsec);
        let rhs_total_nsec = u64::from(rhs.sec) * 1_000_000_000 + u64::from(rhs.nsec);

        if self_total_nsec >= rhs_total_nsec {
            Duration::from_nanos(self_total_nsec - rhs_total_nsec)
        } else {
            Duration::from_secs(0)
        }
    }
}

/// Generate a ping payload
#[allow(clippy::cast_possible_truncation)]
pub fn generate_payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Send multiple ICMP echo requests and return the average round-trip time and packet loss.
///
/// This is a convenience function that sends multiple ICMP echo requests to the specified
/// destination and calculates statistics including average RTT and packet loss percentage.
///
/// # Arguments
/// * `dest` - Destination IP address (IPv4 or IPv6)
/// * `payload_size` - Total payload size in bytes, including 8 bytes for timestamp (minimum 8)
/// * `count` - Number of echo requests to send
///
/// # Returns
/// * `Ok((f64, f64))` - Tuple of (average RTT in milliseconds, packet loss percentage)
/// * `Err(io::Error)` - If all requests fail or socket operations fail
///
/// # Errors
/// Returns an error if:
/// - All echo requests fail or time out (100% packet loss)
/// - Socket operations fail (requires raw socket permissions)
/// - Payload size is less than 8 bytes
///
/// # Notes
/// This function requires raw socket permissions (typically root/admin).
/// The payload is filled with a sequential byte pattern similar to standard ping implementations.
/// Partial failures are handled gracefully - only successful responses are averaged.
/// Packet loss is calculated as: (failed_count / total_count) * 100.0
///
/// # Examples
/// ```no_run
/// use icmp_echo::ping;
/// use std::net::IpAddr;
///
/// // Ping localhost 4 times with 56 byte payload
/// let dest = "127.0.0.1".parse::<IpAddr>().unwrap();
/// let (avg_rtt, packet_loss) = ping(dest, 56, 4).expect("Ping failed");
/// println!("Average RTT: {:.2} ms, Packet Loss: {:.1}%", avg_rtt, packet_loss);
/// ```
pub fn ping(dest: IpAddr, payload_size: usize, count: usize) -> io::Result<(f64, f64)> {
    // Validate payload size
    if payload_size < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Payload size must be at least 8 bytes (for timestamp)",
        ));
    }

    let payload = generate_payload(payload_size - 8);

    // Send echo requests and collect successful RTTs
    let timeout = Duration::from_secs(5);
    let mut rtts = Vec::new();
    let mut failed_count = 0;

    for i in 0..count {
        match send_icmp_echo(dest, &payload, timeout) {
            Ok(rtt) => rtts.push(rtt.as_secs_f64() * 1000.0), // Convert to milliseconds
            Err(_) => failed_count += 1,
        }

        // Sleep between sends (except after the last one)
        if i < count - 1 {
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    // Check if all requests failed
    if rtts.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "All requests failed (100% packet loss)",
        ));
    }

    // Calculate average RTT
    let sum: f64 = rtts.iter().sum();
    #[allow(clippy::cast_precision_loss)]
    let avg = sum / rtts.len() as f64;

    // Calculate packet loss percentage
    #[allow(clippy::cast_precision_loss)]
    let packet_loss = (failed_count as f64 / count as f64) * 100.0;

    Ok((avg, packet_loss))
}

/// Send an ICMP echo request with the given payload and return the round-trip time.
///
/// # Arguments
/// * `dest` - Destination IPv4 or IPv6 address
/// * `payload` - Arbitrary payload data to include in the ICMP packet
/// * `timeout` - Maximum time to wait for a reply
///
/// # Returns
/// * `Ok(Duration)` - Round-trip time if reply received
/// * `Err(io::Error)` - If socket operations fail or timeout occurs
///
/// # Errors
/// Returns an error if socket operations fail, timeout occurs, or reply validation fails.
///
/// # Notes
/// This function requires raw socket permissions (typically root/admin).
/// For `IPv6` destinations, sends `ICMPv6` echo requests.
/// For `IPv4` destinations, sends ICMP echo requests.
pub fn send_icmp_echo(dest: IpAddr, payload: &[u8], timeout: Duration) -> io::Result<Duration> {
    match dest {
        IpAddr::V4(addr) => send_icmp_echo_v4(addr, payload, timeout),
        IpAddr::V6(addr) => send_icmp_echo_v6(addr, payload, timeout),
    }
}

fn sendto(sock: &Socket, packet: &[u8], dest: IpAddr) -> io::Result<()> {
    let sent = match dest {
        IpAddr::V4(addr) => {
            #[allow(clippy::cast_possible_truncation)]
            let dest_addr = libc::sockaddr_in {
                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd"
                ))]
                sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from(addr).to_be(),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::sendto(
                    sock.as_fd(),
                    packet.as_ptr().cast::<libc::c_void>(),
                    packet.len(),
                    0,
                    (&raw const dest_addr).cast::<libc::sockaddr>(),
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
                    },
                )
            }
        }
        IpAddr::V6(addr) => {
            #[allow(clippy::cast_possible_truncation)]
            let dest_addr = libc::sockaddr_in6 {
                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd"
                ))]
                sin6_len: mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.octets(),
                },
                sin6_scope_id: 0,
            };
            unsafe {
                libc::sendto(
                    sock.as_fd(),
                    packet.as_ptr().cast::<libc::c_void>(),
                    packet.len(),
                    0,
                    (&raw const dest_addr).cast::<libc::sockaddr>(),
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
                    },
                )
            }
        }
    };

    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Send an `ICMPv4` echo request with the given payload and return the round-trip time.
#[allow(clippy::too_many_lines)]
fn send_icmp_echo_v4(dest: Ipv4Addr, payload: &[u8], timeout: Duration) -> io::Result<Duration> {
    let sock = create_socket(Domain::Ipv4, timeout)?;

    // Build ICMP packet with timestamp
    let mut packet = Vec::with_capacity(8 + Timestamp::len() + payload.len());
    let our_id = get_echo_id();

    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let header = IcmpHeader {
        typ: ICMP_ECHO_REQUEST,
        code: 0,
        checksum: 0,
        id: our_id.to_be(),
        sequence: seq.to_be(),
    };

    // Add header to packet
    packet.extend_from_slice(header.as_bytes());

    // Encode current monotonic time as timestamp (before user payload)
    let timestamp = Timestamp::now();

    packet.extend_from_slice(timestamp.as_bytes());

    // Add user payload after timestamp
    packet.extend_from_slice(payload);

    // Calculate checksum
    let checksum = calculate_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;

    // Send packet
    sendto(&sock, &packet, IpAddr::V4(dest))?;

    // Receive response - loop to skip packets that aren't our echo reply
    // (raw sockets receive all ICMP packets, including our own echo request on loopback)
    let recv_time;
    let mut recv_buf = vec![0u8; 1024];
    let icmp_start;

    loop {
        let mut src_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
        #[allow(clippy::cast_possible_truncation)]
        let mut src_addr_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let received = unsafe {
            libc::recvfrom(
                sock.as_fd(),
                recv_buf.as_mut_ptr().cast::<libc::c_void>(),
                recv_buf.len(),
                0,
                (&raw mut src_addr).cast::<libc::sockaddr>(),
                &raw mut src_addr_len,
            )
        };

        if received < 0 {
            return Err(io::Error::last_os_error());
        }

        // IP header is 20 bytes, ICMP follows
        #[allow(clippy::cast_sign_loss)]
        if (received as usize) < 28 {
            continue; // Too short, wait for next packet
        }

        // Extract IP header length (lower 4 bits of first byte * 4)
        let ip_hlen = ((recv_buf[0] & 0x0f) * 4) as usize;

        #[allow(clippy::cast_sign_loss)]
        if (received as usize) < ip_hlen + 8 {
            continue; // Truncated header, wait for next packet
        }

        let reply_type = recv_buf[ip_hlen];
        let reply_id = u16::from_be_bytes([recv_buf[ip_hlen + 4], recv_buf[ip_hlen + 5]]);

        if reply_type != ICMP_ECHO_REPLY {
            continue; // Not an echo reply, wait for next packet
        }

        if reply_id != our_id {
            continue; // Not our packet, wait for next packet
        }

        // Found our echo reply
        recv_time = Timestamp::now();
        icmp_start = ip_hlen;
        break;
    }

    // Decode timestamp from reply data to calculate actual RTT
    let timestamp_offset = icmp_start + 8; // After ICMP header
    let timestamp_size = Timestamp::len();

    if recv_buf.len() >= timestamp_offset + timestamp_size {
        let ts =
            Timestamp::try_from(&recv_buf[timestamp_offset..timestamp_offset + timestamp_size])?;

        // Calculate RTT from monotonic timestamps
        let rtt = recv_time - ts;

        Ok(rtt)
    } else {
        // Fallback: no timestamp in packet (shouldn't happen with our packets)
        Ok(Duration::from_secs(0))
    }
}

/// Send an `ICMPv6` echo request with the given payload and return the round-trip time.
#[allow(clippy::too_many_lines)]
fn send_icmp_echo_v6(dest: Ipv6Addr, payload: &[u8], timeout: Duration) -> io::Result<Duration> {
    let sock = create_socket(Domain::Ipv6, timeout)?;

    // Build ICMPv6 packet with timestamp
    let mut packet = Vec::with_capacity(8 + Timestamp::len() + payload.len());
    let our_id = get_echo_id();

    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let header = IcmpHeader {
        typ: ICMP6_ECHO_REQUEST,
        code: 0,
        checksum: 0, // Kernel calculates checksum for ICMPv6
        id: our_id.to_be(),
        sequence: seq.to_be(),
    };

    // Add header to packet
    packet.extend_from_slice(header.as_bytes());

    // Encode current monotonic time as timestamp (before user payload)
    let timestamp = Timestamp::now();

    packet.extend_from_slice(timestamp.as_bytes());

    // Add user payload after timestamp
    packet.extend_from_slice(payload);

    // Note: For IPv6, the kernel automatically calculates the ICMPv6 checksum
    // so we don't need to calculate it ourselves

    // Send packet
    sendto(&sock, &packet, IpAddr::V6(dest))?;

    // Receive response - loop to handle IPv6 raw sockets receiving own packets
    let recv_time;
    let mut recv_buf = vec![0u8; 1024];

    loop {
        let mut src_addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        #[allow(clippy::cast_possible_truncation)]
        let mut src_addr_len = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

        let received = unsafe {
            libc::recvfrom(
                sock.as_fd(),
                recv_buf.as_mut_ptr().cast::<libc::c_void>(),
                recv_buf.len(),
                0,
                (&raw mut src_addr).cast::<libc::sockaddr>(),
                &raw mut src_addr_len,
            )
        };

        if received < 0 {
            return Err(io::Error::last_os_error());
        }

        // Parse ICMPv6 response (no IP header for ICMPv6 raw sockets)
        #[allow(clippy::cast_sign_loss)]
        if (received as usize) < 8 {
            continue; // Too short, wait for next packet
        }

        // Parse ICMPv6 header from response
        let reply_type = recv_buf[0];
        let reply_id = u16::from_be_bytes([recv_buf[4], recv_buf[5]]);

        // Skip packets that aren't echo replies or aren't for us
        if reply_type != ICMP6_ECHO_REPLY {
            continue; // Not an echo reply, wait for next packet
        }

        if reply_id != our_id {
            continue; // Not our packet, wait for next packet
        }

        // Found our echo reply!
        recv_time = Timestamp::now();
        break;
    }

    // Decode timestamp from reply data to calculate actual RTT
    let timestamp_offset = 8; // After ICMPv6 header (no IP header for IPv6)
    let timestamp_size = Timestamp::len();

    // Extract timestamp from packet
    if recv_buf.len() >= timestamp_offset + timestamp_size {
        let ts =
            Timestamp::try_from(&recv_buf[timestamp_offset..timestamp_offset + timestamp_size])?;

        // Calculate RTT from monotonic timestamps
        let rtt = recv_time - ts;

        Ok(rtt)
    } else {
        // Fallback: no timestamp in packet (shouldn't happen with our packets)
        Ok(Duration::from_secs(0))
    }
}

/// Calculate Internet Checksum (RFC 1071)
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum up 16-bit words
    while i < data.len() - 1 {
        let word = u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        sum += word;
        i += 2;
    }

    // Add remaining byte if data length is odd
    if data.len() % 2 == 1 {
        sum += u32::from(data[data.len() - 1]) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Return one's complement
    #[allow(clippy::cast_possible_truncation)]
    {
        !sum as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Check if the current process has permission to create raw sockets.
    /// Returns true if running as root (UID 0), false otherwise.
    fn has_raw_socket_permission() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn test_checksum() {
        // Test with known ICMP echo request header (checksum field zeroed)
        // Type=8, Code=0, Checksum=0, ID=0, Sequence=0
        let data = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let checksum = calculate_checksum(&data);
        // Expected: ~(0x0800) = 0xf7ff
        assert_eq!(checksum, 0xf7ff);

        // Test with odd length data
        let data = vec![0x00, 0x01, 0x02];
        let checksum = calculate_checksum(&data);
        // Sum: 0x0001 + 0x0200 = 0x0201, ~0x0201 = 0xfdfe
        assert_eq!(checksum, 0xfdfe);
    }

    #[test]
    fn test_thread_id_uniqueness() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        // Collect IDs from multiple threads
        let ids = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];

        for _ in 0..5 {
            let ids_clone = Arc::clone(&ids);
            let handle = thread::spawn(move || {
                let id = get_echo_id();
                ids_clone.lock().unwrap().push(id);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let ids = ids.lock().unwrap();
        // All thread IDs should be unique
        let mut sorted_ids = ids.clone();
        sorted_ids.sort();
        sorted_ids.dedup();
        assert_eq!(ids.len(), sorted_ids.len(), "Thread IDs should be unique");

        // Main thread should also have a consistent ID
        let main_id1 = get_echo_id();
        let main_id2 = get_echo_id();
        assert_eq!(main_id1, main_id2, "Same thread should return same ID");
    }

    #[test]
    fn test_timestamp_now() {
        // Test that we can get a monotonic timestamp
        let ts1 = Timestamp::now();

        // Verify fields are reasonable (not zero and not maxed out)
        assert!(ts1.sec > 0, "Seconds should be non-zero");
        assert!(
            ts1.nsec < 1_000_000_000,
            "Nanoseconds should be less than 1 billion"
        );

        // Get another timestamp and verify time moves forward
        std::thread::sleep(Duration::from_millis(10));
        let ts2 = Timestamp::now();

        // Second timestamp should be greater than first
        let total1 = (ts1.sec as u64) * 1_000_000_000 + (ts1.nsec as u64);
        let total2 = (ts2.sec as u64) * 1_000_000_000 + (ts2.nsec as u64);
        assert!(total2 > total1, "Monotonic time should increase");
    }

    #[test]
    fn test_sub_timestamp() {
        // Test basic duration calculation
        let start = Timestamp {
            sec: 10,
            nsec: 500_000_000,
        };
        let end = Timestamp {
            sec: 12,
            nsec: 250_000_000,
        };

        let duration = end - start;

        // Should be 1.75 seconds (12.25 - 10.5)
        assert_eq!(duration.as_secs(), 1);
        assert_eq!(duration.subsec_nanos(), 750_000_000);
    }

    #[test]
    fn test_sub_timestamp_same_second() {
        // Test duration within same second
        let start = Timestamp {
            sec: 5,
            nsec: 100_000_000,
        };
        let end = Timestamp {
            sec: 5,
            nsec: 300_000_000,
        };

        let duration = end - start;

        // Should be 200ms
        assert_eq!(duration.as_millis(), 200);
    }

    #[test]
    fn test_sub_timestamp_zero() {
        // Test zero duration
        let ts = Timestamp {
            sec: 10,
            nsec: 500_000_000,
        };

        let duration = ts - ts;

        assert_eq!(duration.as_nanos(), 0);
    }

    #[test]
    fn test_sub_timestamp_backwards() {
        // Test that backwards time gives zero (shouldn't happen with monotonic clock)
        let start = Timestamp {
            sec: 12,
            nsec: 500_000_000,
        };
        let end = Timestamp {
            sec: 10,
            nsec: 250_000_000,
        };

        let duration = end - start;

        assert_eq!(duration.as_nanos(), 0);
    }

    #[test]
    fn test_sub_timestamp_microsecond_precision() {
        // Test microsecond-level precision
        let start = Timestamp {
            sec: 0,
            nsec: 1_000,
        };
        let end = Timestamp {
            sec: 0,
            nsec: 2_000,
        };

        let duration = end - start;

        assert_eq!(duration.as_nanos(), 1_000);
    }

    #[test]
    fn test_ping_localhost_v4() {
        // Skip test if not running as root
        if !has_raw_socket_permission() {
            println!("Skipping test_ping_localhost_v4: requires root privileges");
            return;
        }

        let dest = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let payload = b"test payload";
        let timeout = Duration::from_secs(5);

        match send_icmp_echo(dest, payload, timeout) {
            Ok(rtt) => {
                println!("IPv4 RTT: {:?}", rtt);
                assert!(rtt < timeout);
            }
            Err(e) => {
                panic!("IPv4 Ping failed: {}", e);
            }
        }
    }

    #[test]
    fn test_ping_localhost_v6() {
        // Skip test if not running as root
        if !has_raw_socket_permission() {
            println!("Skipping test_ping_localhost_v6: requires root privileges");
            return;
        }

        let dest = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let payload = b"test payload";
        let timeout = Duration::from_secs(5);

        match send_icmp_echo(dest, payload, timeout) {
            Ok(rtt) => {
                println!("IPv6 RTT: {:?}", rtt);
                assert!(rtt < timeout);
            }
            Err(e) => {
                panic!("IPv6 Ping failed: {}", e);
            }
        }
    }

    #[test]
    fn test_ping_invalid_payload_size() {
        // Test with payload size less than 8 bytes
        let dest = "127.0.0.1".parse().unwrap();
        let result = ping(dest, 7, 4);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_ping_localhost() {
        // Skip test if not running as root
        if !has_raw_socket_permission() {
            println!("Skipping test_ping_localhost: requires root privileges");
            return;
        }

        // Test the ping helper function with localhost
        let dest = "127.0.0.1".parse().unwrap();
        match ping(dest, 56, 3) {
            Ok((avg_rtt, packet_loss)) => {
                println!(
                    "Average RTT: {:.3} ms, Packet Loss: {:.1}%",
                    avg_rtt, packet_loss
                );
                assert!(avg_rtt > 0.0);
                assert!(avg_rtt < 1000.0); // Should be less than 1 second
                assert!((0.0..=100.0).contains(&packet_loss));
            }
            Err(e) => {
                panic!("Ping failed: {}", e);
            }
        }
    }

    #[test]
    fn test_ping_localhost_v4_large_payload() {
        if !has_raw_socket_permission() {
            println!("Skipping test_ping_localhost_v4_large_payload: requires root privileges");
            return;
        }

        let dest = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let payload = vec![0u8; 2048 - 8]; // 2K total, minus 8 bytes for timestamp
        let timeout = Duration::from_secs(5);

        match send_icmp_echo(dest, &payload, timeout) {
            Ok(rtt) => {
                println!("IPv4 2K payload RTT: {:?}", rtt);
                assert!(rtt < timeout);
            }
            Err(e) => panic!("IPv4 2K ping failed: {}", e),
        }
    }

    #[test]
    fn test_ping_localhost_v6_large_payload() {
        if !has_raw_socket_permission() {
            println!("Skipping test_ping_localhost_v6_large_payload: requires root privileges");
            return;
        }

        let dest = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let payload = vec![0u8; 2048 - 8]; // 2K total, minus 8 bytes for timestamp
        let timeout = Duration::from_secs(5);

        match send_icmp_echo(dest, &payload, timeout) {
            Ok(rtt) => {
                println!("IPv6 2K payload RTT: {:?}", rtt);
                assert!(rtt < timeout);
            }
            Err(e) => panic!("IPv6 2K ping failed: {}", e),
        }
    }

    #[test]
    fn test_ping_concurrent_threads() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        if !has_raw_socket_permission() {
            println!("Skipping test_ping_concurrent_threads: requires root privileges");
            return;
        }

        const THREAD_COUNT: usize = 4;
        let barrier = Arc::new(Barrier::new(THREAD_COUNT));
        let mut handles = vec![];

        for _ in 0..THREAD_COUNT {
            let barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                // All threads start sending at the same time
                barrier.wait();

                let dest = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
                let payload = b"threaded ping";
                let timeout = Duration::from_secs(5);

                send_icmp_echo(dest, payload, timeout)
            });
            handles.push(handle);
        }

        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .collect();

        // Every thread should receive a valid reply
        for (i, result) in results.iter().enumerate() {
            match result {
                Ok(rtt) => {
                    println!("Thread {} RTT: {:?}", i, rtt);
                    assert!(*rtt < Duration::from_secs(5), "RTT should be under timeout");
                }
                Err(e) => panic!("Thread {} ping failed: {}", i, e),
            }
        }
    }

    #[test]
    fn test_ping_concurrent_threads_v6() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        if !has_raw_socket_permission() {
            println!("Skipping test_ping_concurrent_threads_v6: requires root privileges");
            return;
        }

        const THREAD_COUNT: usize = 4;
        let barrier = Arc::new(Barrier::new(THREAD_COUNT));
        let mut handles = vec![];

        for _ in 0..THREAD_COUNT {
            let barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                // All threads start sending at the same time
                barrier.wait();

                let dest = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
                let payload = b"threaded ping";
                let timeout = Duration::from_secs(5);

                send_icmp_echo(dest, payload, timeout)
            });
            handles.push(handle);
        }

        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .collect();

        // Every thread should receive a valid reply
        for (i, result) in results.iter().enumerate() {
            match result {
                Ok(rtt) => {
                    println!("Thread {} RTT: {:?}", i, rtt);
                    assert!(*rtt < Duration::from_secs(5), "RTT should be under timeout");
                }
                Err(e) => panic!("Thread {} ping failed: {}", i, e),
            }
        }
    }
}
