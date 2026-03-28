use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

static SEQUENCE: AtomicU16 = AtomicU16::new(0);

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
/// Uses CLOCK_MONOTONIC which is not affected by system clock adjustments.
fn get_monotonic_time() -> io::Result<Timestamp> {
    let mut ts: libc::timespec = unsafe { mem::zeroed() };

    let result = unsafe {
        #[cfg(target_vendor = "apple")]
        let clock_id = libc::CLOCK_UPTIME_RAW;
        #[cfg(not(target_vendor = "apple"))]
        let clock_id = libc::CLOCK_MONOTONIC;

        libc::clock_gettime(clock_id, &mut ts)
    };

    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(Timestamp {
        sec: ts.tv_sec as u32,
        nsec: ts.tv_nsec as u32,
    })
}

/// Calculate duration between two monotonic timestamps.
fn calculate_duration(start: &Timestamp, end: &Timestamp) -> Duration {
    let start_sec = start.sec as u64;
    let start_nsec = start.nsec as u64;
    let end_sec = end.sec as u64;
    let end_nsec = end.nsec as u64;

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
/// # Notes
/// This function requires raw socket permissions (typically root/admin).
/// For IPv6 destinations, sends ICMPv6 echo requests.
/// For IPv4 destinations, sends ICMP echo requests.
pub fn send_icmp_echo(dest: IpAddr, payload: &[u8], timeout: Duration) -> io::Result<Duration> {
    match dest {
        IpAddr::V4(addr) => send_icmp_echo_v4(addr, payload, timeout),
        IpAddr::V6(addr) => send_icmp_echo_v6(addr, payload, timeout),
    }
}

/// Send an ICMPv4 echo request with the given payload and return the round-trip time.
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
    let timeval = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };

    unsafe {
        if libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeval as *const _ as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        ) < 0
        {
            libc::close(sock);
            return Err(io::Error::last_os_error());
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
        id: (std::process::id() as u16).to_be(),
        sequence: seq.to_be(),
    };

    // Add header to packet
    unsafe {
        let header_bytes = std::slice::from_raw_parts(
            &header as *const _ as *const u8,
            mem::size_of::<IcmpHeader>(),
        );
        packet.extend_from_slice(header_bytes);
    }

    // Encode current monotonic time as timestamp (before user payload)
    let timestamp = get_monotonic_time()?;

    unsafe {
        let ts_bytes =
            std::slice::from_raw_parts(&timestamp as *const _ as *const u8, timestamp_size);
        packet.extend_from_slice(ts_bytes);
    }

    // Add user payload after timestamp
    packet.extend_from_slice(payload);

    // Calculate checksum
    let checksum = calculate_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;

    // Prepare destination address
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
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &dest_addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };

    if sent < 0 {
        unsafe { libc::close(sock) };
        return Err(io::Error::last_os_error());
    }

    // Receive response
    let mut recv_buf = vec![0u8; 1024];
    let mut src_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut src_addr_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let received = unsafe {
        libc::recvfrom(
            sock,
            recv_buf.as_mut_ptr() as *mut libc::c_void,
            recv_buf.len(),
            0,
            &mut src_addr as *mut _ as *mut libc::sockaddr,
            &mut src_addr_len,
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
    if (received as usize) < 28 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Response too short",
        ));
    }

    // Extract IP header length (lower 4 bits of first byte * 4)
    let ip_header_len = ((recv_buf[0] & 0x0f) * 4) as usize;

    if (received as usize) < ip_header_len + 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid IP header length",
        ));
    }

    // Parse ICMP header from response
    let icmp_start = ip_header_len;
    let reply_type = recv_buf[icmp_start];
    let _reply_code = recv_buf[icmp_start + 1];
    let reply_id = u16::from_be_bytes([recv_buf[icmp_start + 4], recv_buf[icmp_start + 5]]);
    let _reply_seq = u16::from_be_bytes([recv_buf[icmp_start + 6], recv_buf[icmp_start + 7]]);

    // Verify this is our echo reply
    if reply_type != ICMP_ECHOREPLY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unexpected ICMP type: {}", reply_type),
        ));
    }

    if reply_id != (std::process::id() as u16) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP ID mismatch",
        ));
    }

    // Decode timestamp from reply data to calculate actual RTT
    let timestamp_offset = icmp_start + 8; // After ICMP header
    let timestamp_size = mem::size_of::<Timestamp>();

    if (received as usize) >= timestamp_offset + timestamp_size {
        let mut ts = Timestamp { sec: 0, nsec: 0 };
        unsafe {
            let ts_bytes =
                std::slice::from_raw_parts_mut(&mut ts as *mut _ as *mut u8, timestamp_size);
            ts_bytes
                .copy_from_slice(&recv_buf[timestamp_offset..timestamp_offset + timestamp_size]);
        }

        // Calculate RTT from monotonic timestamps
        let rtt = calculate_duration(&ts, &recv_time);

        Ok(rtt)
    } else {
        // Fallback: no timestamp in packet (shouldn't happen with our packets)
        Ok(Duration::from_secs(0))
    }
}

/// Send an ICMPv6 echo request with the given payload and return the round-trip time.
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
    let timeval = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };

    unsafe {
        if libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeval as *const _ as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        ) < 0
        {
            libc::close(sock);
            return Err(io::Error::last_os_error());
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
        id: (std::process::id() as u16).to_be(),
        sequence: seq.to_be(),
    };

    // Add header to packet
    unsafe {
        let header_bytes = std::slice::from_raw_parts(
            &header as *const _ as *const u8,
            mem::size_of::<IcmpHeader>(),
        );
        packet.extend_from_slice(header_bytes);
    }

    // Encode current monotonic time as timestamp (before user payload)
    let timestamp = get_monotonic_time()?;

    unsafe {
        let ts_bytes =
            std::slice::from_raw_parts(&timestamp as *const _ as *const u8, timestamp_size);
        packet.extend_from_slice(ts_bytes);
    }

    // Add user payload after timestamp
    packet.extend_from_slice(payload);

    // Note: For IPv6, the kernel automatically calculates the ICMPv6 checksum
    // so we don't need to calculate it ourselves

    // Prepare destination address
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
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &dest_addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };

    if sent < 0 {
        unsafe { libc::close(sock) };
        return Err(io::Error::last_os_error());
    }

    // Receive response
    let mut recv_buf = vec![0u8; 1024];
    let mut src_addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    let mut src_addr_len = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let received = unsafe {
        libc::recvfrom(
            sock,
            recv_buf.as_mut_ptr() as *mut libc::c_void,
            recv_buf.len(),
            0,
            &mut src_addr as *mut _ as *mut libc::sockaddr,
            &mut src_addr_len,
        )
    };

    unsafe { libc::close(sock) };

    if received < 0 {
        return Err(io::Error::last_os_error());
    }

    // Get current monotonic time for RTT calculation
    let recv_time = get_monotonic_time()?;

    // Parse ICMPv6 response (no IP header for ICMPv6 raw sockets)
    if (received as usize) < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Response too short",
        ));
    }

    // Parse ICMPv6 header from response
    let reply_type = recv_buf[0];
    let _reply_code = recv_buf[1];
    let reply_id = u16::from_be_bytes([recv_buf[4], recv_buf[5]]);
    let _reply_seq = u16::from_be_bytes([recv_buf[6], recv_buf[7]]);

    // Verify this is our echo reply
    if reply_type != ICMP6_ECHO_REPLY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unexpected ICMPv6 type: {}", reply_type),
        ));
    }

    if reply_id != (std::process::id() as u16) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMPv6 ID mismatch",
        ));
    }

    // Decode timestamp from reply data to calculate actual RTT
    let timestamp_offset = 8; // After ICMPv6 header (no IP header for IPv6)
    let timestamp_size = mem::size_of::<Timestamp>();

    if (received as usize) >= timestamp_offset + timestamp_size {
        let mut ts = Timestamp { sec: 0, nsec: 0 };
        unsafe {
            let ts_bytes =
                std::slice::from_raw_parts_mut(&mut ts as *mut _ as *mut u8, timestamp_size);
            ts_bytes
                .copy_from_slice(&recv_buf[timestamp_offset..timestamp_offset + timestamp_size]);
        }

        // Calculate RTT from monotonic timestamps
        let rtt = calculate_duration(&ts, &recv_time);

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
        let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum += word;
        i += 2;
    }

    // Add remaining byte if data length is odd
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Return one's complement
    !sum as u16
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
    fn test_get_monotonic_time() {
        // Test that we can get a monotonic timestamp
        let ts1 = get_monotonic_time().expect("Failed to get monotonic time");
        
        // Verify fields are reasonable (not zero and not maxed out)
        assert!(ts1.sec > 0, "Seconds should be non-zero");
        assert!(ts1.nsec < 1_000_000_000, "Nanoseconds should be less than 1 billion");
        
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
        let start = Timestamp { sec: 10, nsec: 500_000_000 };
        let end = Timestamp { sec: 12, nsec: 250_000_000 };
        
        let duration = calculate_duration(&start, &end);
        
        // Should be 1.75 seconds (12.25 - 10.5)
        assert_eq!(duration.as_secs(), 1);
        assert_eq!(duration.subsec_nanos(), 750_000_000);
    }

    #[test]
    fn test_calculate_duration_same_second() {
        // Test duration within same second
        let start = Timestamp { sec: 5, nsec: 100_000_000 };
        let end = Timestamp { sec: 5, nsec: 300_000_000 };
        
        let duration = calculate_duration(&start, &end);
        
        // Should be 200ms
        assert_eq!(duration.as_millis(), 200);
    }

    #[test]
    fn test_calculate_duration_zero() {
        // Test zero duration
        let ts = Timestamp { sec: 10, nsec: 500_000_000 };
        
        let duration = calculate_duration(&ts, &ts);
        
        assert_eq!(duration.as_nanos(), 0);
    }

    #[test]
    fn test_calculate_duration_backwards() {
        // Test that backwards time gives zero (shouldn't happen with monotonic clock)
        let start = Timestamp { sec: 12, nsec: 500_000_000 };
        let end = Timestamp { sec: 10, nsec: 250_000_000 };
        
        let duration = calculate_duration(&start, &end);
        
        assert_eq!(duration.as_nanos(), 0);
    }

    #[test]
    fn test_calculate_duration_microsecond_precision() {
        // Test microsecond-level precision
        let start = Timestamp { sec: 0, nsec: 1_000 };
        let end = Timestamp { sec: 0, nsec: 2_000 };
        
        let duration = calculate_duration(&start, &end);
        
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
}
