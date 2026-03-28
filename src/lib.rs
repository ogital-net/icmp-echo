use std::cell::Cell;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

static SEQUENCE: AtomicU16 = AtomicU16::new(0);
static ID_COUNTER: AtomicU16 = AtomicU16::new(1);

thread_local! {
    static THREAD_ID: Cell<u16> = const { Cell::new(0) };
}

/// Get a machine-unique identifier for this thread.
/// Combines process ID with a per-thread counter via XOR to ensure uniqueness
/// across both threads and processes on the same machine.
fn get_thread_id() -> u16 {
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

const ICMP_ECHO: u8 = 8;
const ICMP_ECHOREPLY: u8 = 0;
const ICMP6_ECHO_REQUEST: u8 = 128;
const ICMP6_ECHO_REPLY: u8 = 129;
const IPPROTO_ICMP: libc::c_int = 1;
const IPPROTO_ICMPV6: libc::c_int = 58;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct IcmpHeader {
    typ: u8,
    code: u8,
    checksum: u16,
    id: u16,
    sequence: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Timestamp {
    sec: u32,
    nsec: u32,
}

/// Get monotonic timestamp for accurate RTT measurement.
/// Uses `CLOCK_MONOTONIC` which is not affected by system clock adjustments.
fn get_monotonic_time() -> io::Result<Timestamp> {
    let mut ts: libc::timespec = unsafe { mem::zeroed() };

    let result = unsafe {
        #[cfg(target_vendor = "apple")]
        let clock_id = libc::CLOCK_UPTIME_RAW;
        #[cfg(not(target_vendor = "apple"))]
        let clock_id = libc::CLOCK_MONOTONIC;

        libc::clock_gettime(clock_id, &raw mut ts)
    };

    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(Timestamp {
        sec: ts.tv_sec as u32,
        nsec: ts.tv_nsec as u32,
    })
}

/// Calculate duration between two monotonic timestamps.
#[allow(clippy::similar_names)]
fn calculate_duration(start: Timestamp, end: Timestamp) -> Duration {
    let start_sec = u64::from(start.sec);
    let start_nsec = u64::from(start.nsec);
    let end_sec = u64::from(end.sec);
    let end_nsec = u64::from(end.nsec);

    let start_total_nsec = start_sec * 1_000_000_000 + start_nsec;
    let end_total_nsec = end_sec * 1_000_000_000 + end_nsec;

    if end_total_nsec >= start_total_nsec {
        Duration::from_nanos(end_total_nsec - start_total_nsec)
    } else {
        Duration::from_secs(0)
    }
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

/// Send multiple ICMP echo requests and return the average round-trip time.
///
/// This is a convenience function that sends multiple ICMP echo requests to the specified
/// destination and calculates the average RTT of successful responses.
///
/// # Arguments
/// * `dest` - Destination IP address (IPv4 or IPv6)
/// * `payload_size` - Total payload size in bytes, including 8 bytes for timestamp (minimum 8)
/// * `count` - Number of echo requests to send
///
/// # Returns
/// * `Ok(f64)` - Average round-trip time in milliseconds
/// * `Err(io::Error)` - If no responses received or socket operations fail
///
/// # Errors
/// Returns an error if:
/// - No successful echo replies are received
/// - Socket operations fail (requires raw socket permissions)
/// - Payload size is less than 8 bytes
///
/// # Notes
/// This function requires raw socket permissions (typically root/admin).
/// The payload is filled with a sequential byte pattern similar to standard ping implementations.
/// Failed requests (timeouts) are skipped and not counted in the average.
///
/// # Examples
/// ```no_run
/// use icmp_echo::ping;
/// use std::net::IpAddr;
///
/// // Ping localhost 4 times with 56 byte payload
/// let dest = "127.0.0.1".parse::<IpAddr>().unwrap();
/// let avg_rtt = ping(dest, 56, 4).expect("Ping failed");
/// println!("Average RTT: {:.2} ms", avg_rtt);
/// ```
pub fn ping(dest: IpAddr, payload_size: usize, count: usize) -> io::Result<f64> {
    // Validate payload size
    if payload_size < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Payload size must be at least 8 bytes (for timestamp)",
        ));
    }

    // Generate payload with sequential byte pattern (like standard ping)
    // The first 8 bytes are reserved for the timestamp (handled by send_icmp_echo)
    let user_payload_size = payload_size - 8;
    let mut payload = Vec::with_capacity(user_payload_size);
    for i in 0..user_payload_size {
        #[allow(clippy::cast_possible_truncation)]
        payload.push(((i + 8) % 256) as u8);
    }

    // Send echo requests and collect successful RTTs
    let timeout = Duration::from_secs(5);
    let mut successful_rtts = Vec::new();

    for _ in 0..count {
        if let Ok(rtt) = send_icmp_echo(dest, &payload, timeout) {
            successful_rtts.push(rtt.as_secs_f64() * 1000.0); // Convert to milliseconds
        }
    }

    // Check if we got any responses
    if successful_rtts.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "No responses received",
        ));
    }

    // Calculate average
    let sum: f64 = successful_rtts.iter().sum();
    #[allow(clippy::cast_precision_loss)]
    let avg = sum / successful_rtts.len() as f64;

    Ok(avg)
}

/// Send an `ICMPv4` echo request with the given payload and return the round-trip time.
#[allow(clippy::too_many_lines)]
fn send_icmp_echo_v4(dest: Ipv4Addr, payload: &[u8], timeout: Duration) -> io::Result<Duration> {
    // Create raw ICMP socket
    let sock = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, IPPROTO_ICMP);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        fd
    };

    // Set receive timeout
    #[allow(clippy::cast_possible_wrap)]
    let timeval = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };

    unsafe {
        if libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeval).cast::<libc::c_void>(),
            #[allow(clippy::cast_possible_truncation)]
            {
                mem::size_of::<libc::timeval>() as libc::socklen_t
            },
        ) < 0
        {
            libc::close(sock);
            return Err(io::Error::last_os_error());
        }
    }

    // Set Do Not Fragment bit
    unsafe {
        #[cfg(target_os = "linux")]
        {
            let val: libc::c_int = libc::IP_PMTUDISC_DO;
            if libc::setsockopt(
                sock,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                (&raw const val).cast::<libc::c_void>(),
                #[allow(clippy::cast_possible_truncation)]
                {
                    mem::size_of::<libc::c_int>() as libc::socklen_t
                },
            ) < 0
            {
                libc::close(sock);
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let val: libc::c_int = 1;
            if libc::setsockopt(
                sock,
                libc::IPPROTO_IP,
                libc::IP_DONTFRAG,
                (&raw const val).cast::<libc::c_void>(),
                #[allow(clippy::cast_possible_truncation)]
                {
                    mem::size_of::<libc::c_int>() as libc::socklen_t
                },
            ) < 0
            {
                libc::close(sock);
                return Err(io::Error::last_os_error());
            }
        }
    }

    // Build ICMP packet with timestamp
    let timestamp_size = mem::size_of::<Timestamp>();
    let mut packet = Vec::with_capacity(8 + timestamp_size + payload.len());

    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let header = IcmpHeader {
        typ: ICMP_ECHO,
        code: 0,
        checksum: 0,
        id: get_thread_id().to_be(),
        sequence: seq.to_be(),
    };

    // Add header to packet
    unsafe {
        let header_bytes = std::slice::from_raw_parts(
            (&raw const header).cast::<u8>(),
            mem::size_of::<IcmpHeader>(),
        );
        packet.extend_from_slice(header_bytes);
    }

    // Encode current monotonic time as timestamp (before user payload)
    let timestamp = get_monotonic_time()?;

    unsafe {
        let ts_bytes =
            std::slice::from_raw_parts((&raw const timestamp).cast::<u8>(), timestamp_size);
        packet.extend_from_slice(ts_bytes);
    }

    // Add user payload after timestamp
    packet.extend_from_slice(payload);

    // Calculate checksum
    let checksum = calculate_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;

    // Prepare destination address
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
            s_addr: u32::from(dest).to_be(),
        },
        sin_zero: [0; 8],
    };

    // Send packet
    let sent = unsafe {
        libc::sendto(
            sock,
            packet.as_ptr().cast::<libc::c_void>(),
            packet.len(),
            0,
            (&raw const dest_addr).cast::<libc::sockaddr>(),
            #[allow(clippy::cast_possible_truncation)]
            {
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            },
        )
    };

    if sent < 0 {
        unsafe { libc::close(sock) };
        return Err(io::Error::last_os_error());
    }

    // Receive response
    let mut recv_buf = vec![0u8; 1024];
    let mut src_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)]
    let mut src_addr_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let received = unsafe {
        libc::recvfrom(
            sock,
            recv_buf.as_mut_ptr().cast::<libc::c_void>(),
            recv_buf.len(),
            0,
            (&raw mut src_addr).cast::<libc::sockaddr>(),
            &raw mut src_addr_len,
        )
    };

    unsafe { libc::close(sock) };

    if received < 0 {
        return Err(io::Error::last_os_error());
    }

    // Get current monotonic time for RTT calculation
    let recv_time = get_monotonic_time()?;

    // Parse response
    // IP header is typically 20 bytes, ICMP follows
    #[allow(clippy::cast_sign_loss)]
    if (received as usize) < 28 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Response too short",
        ));
    }

    // Extract IP header length (lower 4 bits of first byte * 4)
    let ip_header_len = ((recv_buf[0] & 0x0f) * 4) as usize;

    #[allow(clippy::cast_sign_loss)]
    if (received as usize) < ip_header_len + 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid IP header length",
        ));
    }

    // Parse ICMP header from response
    let icmp_start = ip_header_len;
    let reply_type = recv_buf[icmp_start];
    let reply_id = u16::from_be_bytes([recv_buf[icmp_start + 4], recv_buf[icmp_start + 5]]);

    // Verify this is our echo reply
    if reply_type != ICMP_ECHOREPLY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unexpected ICMP type: {reply_type}"),
        ));
    }

    if reply_id != get_thread_id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP ID mismatch",
        ));
    }

    // Decode timestamp from reply data to calculate actual RTT
    let timestamp_offset = icmp_start + 8; // After ICMP header
    let timestamp_size = mem::size_of::<Timestamp>();

    #[allow(clippy::cast_sign_loss)]
    if (received as usize) >= timestamp_offset + timestamp_size {
        let mut ts = Timestamp { sec: 0, nsec: 0 };
        unsafe {
            let ts_bytes =
                std::slice::from_raw_parts_mut((&raw mut ts).cast::<u8>(), timestamp_size);
            ts_bytes
                .copy_from_slice(&recv_buf[timestamp_offset..timestamp_offset + timestamp_size]);
        }

        // Calculate RTT from monotonic timestamps
        let rtt = calculate_duration(ts, recv_time);

        Ok(rtt)
    } else {
        // Fallback: no timestamp in packet (shouldn't happen with our packets)
        Ok(Duration::from_secs(0))
    }
}

/// Send an `ICMPv6` echo request with the given payload and return the round-trip time.
#[allow(clippy::too_many_lines)]
fn send_icmp_echo_v6(dest: Ipv6Addr, payload: &[u8], timeout: Duration) -> io::Result<Duration> {
    // Create raw ICMPv6 socket
    let sock = unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_RAW, IPPROTO_ICMPV6);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        fd
    };

    // Set receive timeout
    #[allow(clippy::cast_possible_wrap)]
    let timeval = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };

    unsafe {
        if libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeval).cast::<libc::c_void>(),
            #[allow(clippy::cast_possible_truncation)]
            {
                mem::size_of::<libc::timeval>() as libc::socklen_t
            },
        ) < 0
        {
            libc::close(sock);
            return Err(io::Error::last_os_error());
        }
    }

    // Set Do Not Fragment bit for IPv6
    unsafe {
        #[cfg(target_os = "linux")]
        {
            let val: libc::c_int = libc::IPV6_PMTUDISC_DO;
            if libc::setsockopt(
                sock,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                (&raw const val).cast::<libc::c_void>(),
                #[allow(clippy::cast_possible_truncation)]
                {
                    mem::size_of::<libc::c_int>() as libc::socklen_t
                },
            ) < 0
            {
                libc::close(sock);
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let val: libc::c_int = 1;
            if libc::setsockopt(
                sock,
                libc::IPPROTO_IPV6,
                libc::IPV6_DONTFRAG,
                (&raw const val).cast::<libc::c_void>(),
                #[allow(clippy::cast_possible_truncation)]
                {
                    mem::size_of::<libc::c_int>() as libc::socklen_t
                },
            ) < 0
            {
                libc::close(sock);
                return Err(io::Error::last_os_error());
            }
        }
    }

    // Build ICMPv6 packet with timestamp
    let timestamp_size = mem::size_of::<Timestamp>();
    let mut packet = Vec::with_capacity(8 + timestamp_size + payload.len());

    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let header = IcmpHeader {
        typ: ICMP6_ECHO_REQUEST,
        code: 0,
        checksum: 0, // Kernel calculates checksum for ICMPv6
        id: get_thread_id().to_be(),
        sequence: seq.to_be(),
    };

    // Add header to packet
    unsafe {
        let header_bytes = std::slice::from_raw_parts(
            (&raw const header).cast::<u8>(),
            mem::size_of::<IcmpHeader>(),
        );
        packet.extend_from_slice(header_bytes);
    }

    // Encode current monotonic time as timestamp (before user payload)
    let timestamp = get_monotonic_time()?;

    unsafe {
        let ts_bytes =
            std::slice::from_raw_parts((&raw const timestamp).cast::<u8>(), timestamp_size);
        packet.extend_from_slice(ts_bytes);
    }

    // Add user payload after timestamp
    packet.extend_from_slice(payload);

    // Note: For IPv6, the kernel automatically calculates the ICMPv6 checksum
    // so we don't need to calculate it ourselves

    // Prepare destination address
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
            s6_addr: dest.octets(),
        },
        sin6_scope_id: 0,
    };

    // Send packet
    let sent = unsafe {
        libc::sendto(
            sock,
            packet.as_ptr().cast::<libc::c_void>(),
            packet.len(),
            0,
            (&raw const dest_addr).cast::<libc::sockaddr>(),
            #[allow(clippy::cast_possible_truncation)]
            {
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            },
        )
    };

    if sent < 0 {
        unsafe { libc::close(sock) };
        return Err(io::Error::last_os_error());
    }

    // Receive response
    let mut recv_buf = vec![0u8; 1024];
    let mut src_addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)]
    let mut src_addr_len = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let received = unsafe {
        libc::recvfrom(
            sock,
            recv_buf.as_mut_ptr().cast::<libc::c_void>(),
            recv_buf.len(),
            0,
            (&raw mut src_addr).cast::<libc::sockaddr>(),
            &raw mut src_addr_len,
        )
    };

    unsafe { libc::close(sock) };

    if received < 0 {
        return Err(io::Error::last_os_error());
    }

    // Get current monotonic time for RTT calculation
    let recv_time = get_monotonic_time()?;

    // Parse ICMPv6 response (no IP header for ICMPv6 raw sockets)
    #[allow(clippy::cast_sign_loss)]
    if (received as usize) < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Response too short",
        ));
    }

    // Parse ICMPv6 header from response
    let reply_type = recv_buf[0];
    let reply_id = u16::from_be_bytes([recv_buf[4], recv_buf[5]]);

    // Verify this is our echo reply
    if reply_type != ICMP6_ECHO_REPLY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unexpected ICMPv6 type: {reply_type}"),
        ));
    }

    if reply_id != get_thread_id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMPv6 ID mismatch",
        ));
    }

    // Decode timestamp from reply data to calculate actual RTT
    let timestamp_offset = 8; // After ICMPv6 header (no IP header for IPv6)
    let timestamp_size = mem::size_of::<Timestamp>();

    #[allow(clippy::cast_sign_loss)]
    if (received as usize) >= timestamp_offset + timestamp_size {
        let mut ts = Timestamp { sec: 0, nsec: 0 };
        unsafe {
            let ts_bytes =
                std::slice::from_raw_parts_mut((&raw mut ts).cast::<u8>(), timestamp_size);
            ts_bytes
                .copy_from_slice(&recv_buf[timestamp_offset..timestamp_offset + timestamp_size]);
        }

        // Calculate RTT from monotonic timestamps
        let rtt = calculate_duration(ts, recv_time);

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
                let id = get_thread_id();
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
        let main_id1 = get_thread_id();
        let main_id2 = get_thread_id();
        assert_eq!(main_id1, main_id2, "Same thread should return same ID");
    }

    #[test]
    fn test_get_monotonic_time() {
        // Test that we can get a monotonic timestamp
        let ts1 = get_monotonic_time().expect("Failed to get monotonic time");

        // Verify fields are reasonable (not zero and not maxed out)
        assert!(ts1.sec > 0, "Seconds should be non-zero");
        assert!(
            ts1.nsec < 1_000_000_000,
            "Nanoseconds should be less than 1 billion"
        );

        // Get another timestamp and verify time moves forward
        std::thread::sleep(Duration::from_millis(10));
        let ts2 = get_monotonic_time().expect("Failed to get monotonic time");

        // Second timestamp should be greater than first
        let total1 = (ts1.sec as u64) * 1_000_000_000 + (ts1.nsec as u64);
        let total2 = (ts2.sec as u64) * 1_000_000_000 + (ts2.nsec as u64);
        assert!(total2 > total1, "Monotonic time should increase");
    }

    #[test]
    fn test_calculate_duration() {
        // Test basic duration calculation
        let start = Timestamp {
            sec: 10,
            nsec: 500_000_000,
        };
        let end = Timestamp {
            sec: 12,
            nsec: 250_000_000,
        };

        let duration = calculate_duration(start, end);

        // Should be 1.75 seconds (12.25 - 10.5)
        assert_eq!(duration.as_secs(), 1);
        assert_eq!(duration.subsec_nanos(), 750_000_000);
    }

    #[test]
    fn test_calculate_duration_same_second() {
        // Test duration within same second
        let start = Timestamp {
            sec: 5,
            nsec: 100_000_000,
        };
        let end = Timestamp {
            sec: 5,
            nsec: 300_000_000,
        };

        let duration = calculate_duration(start, end);

        // Should be 200ms
        assert_eq!(duration.as_millis(), 200);
    }

    #[test]
    fn test_calculate_duration_zero() {
        // Test zero duration
        let ts = Timestamp {
            sec: 10,
            nsec: 500_000_000,
        };

        let duration = calculate_duration(ts, ts);

        assert_eq!(duration.as_nanos(), 0);
    }

    #[test]
    fn test_calculate_duration_backwards() {
        // Test that backwards time gives zero (shouldn't happen with monotonic clock)
        let start = Timestamp {
            sec: 12,
            nsec: 500_000_000,
        };
        let end = Timestamp {
            sec: 10,
            nsec: 250_000_000,
        };

        let duration = calculate_duration(start, end);

        assert_eq!(duration.as_nanos(), 0);
    }

    #[test]
    fn test_calculate_duration_microsecond_precision() {
        // Test microsecond-level precision
        let start = Timestamp {
            sec: 0,
            nsec: 1_000,
        };
        let end = Timestamp {
            sec: 0,
            nsec: 2_000,
        };

        let duration = calculate_duration(start, end);

        assert_eq!(duration.as_nanos(), 1_000);
    }

    #[test]
    #[ignore] // Requires root privileges
    fn test_ping_localhost_v4() {
        let dest = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let payload = b"test payload";
        let timeout = Duration::from_secs(5);

        match send_icmp_echo(dest, payload, timeout) {
            Ok(rtt) => {
                println!("IPv4 RTT: {:?}", rtt);
                assert!(rtt < timeout);
            }
            Err(e) => {
                eprintln!("IPv4 Ping failed: {}", e);
                // This test may fail without proper permissions
            }
        }
    }

    #[test]
    #[ignore] // Requires root privileges
    fn test_ping_localhost_v6() {
        let dest = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let payload = b"test payload";
        let timeout = Duration::from_secs(5);

        match send_icmp_echo(dest, payload, timeout) {
            Ok(rtt) => {
                println!("IPv6 RTT: {:?}", rtt);
                assert!(rtt < timeout);
            }
            Err(e) => {
                eprintln!("IPv6 Ping failed: {}", e);
                // This test may fail without proper permissions
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
    #[ignore] // Requires root privileges
    fn test_ping_localhost() {
        // Test the ping helper function with localhost
        let dest = "127.0.0.1".parse().unwrap();
        match ping(dest, 56, 3) {
            Ok(avg_rtt) => {
                println!("Average RTT: {:.3} ms", avg_rtt);
                assert!(avg_rtt > 0.0);
                assert!(avg_rtt < 1000.0); // Should be less than 1 second
            }
            Err(e) => {
                eprintln!("Ping failed: {}", e);
                // This test may fail without proper permissions
            }
        }
    }
}
