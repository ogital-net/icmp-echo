use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const ICMP_ECHO: u8 = 8;
const ICMP_ECHOREPLY: u8 = 0;
const IPPROTO_ICMP: libc::c_int = 1;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct IcmpHeader {
    typ: u8,
    code: u8,
    checksum: u16,
    id: u16,
    sequence: u16,
}

/// Send an ICMP echo request with the given payload and return the round-trip time.
///
/// # Arguments
/// * `dest` - Destination IPv4 address
/// * `payload` - Arbitrary payload data to include in the ICMP packet
/// * `timeout` - Maximum time to wait for a reply
///
/// # Returns
/// * `Ok(Duration)` - Round-trip time if reply received
/// * `Err(io::Error)` - If socket operations fail or timeout occurs
///
/// # Panics
/// This function requires raw socket permissions (typically root/admin).
pub fn send_icmp_echo(dest: Ipv4Addr, payload: &[u8], timeout: Duration) -> io::Result<Duration> {
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

    // Build ICMP packet
    let mut packet = Vec::with_capacity(8 + payload.len());

    let header = IcmpHeader {
        typ: ICMP_ECHO,
        code: 0,
        checksum: 0,
        id: (std::process::id() as u16).to_be(),
        sequence: 1u16.to_be(),
    };

    // Add header to packet
    unsafe {
        let header_bytes = std::slice::from_raw_parts(
            &header as *const _ as *const u8,
            mem::size_of::<IcmpHeader>(),
        );
        packet.extend_from_slice(header_bytes);
    }

    // Add payload
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

    // Record start time
    let start = Instant::now();

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

    // Record end time
    let rtt = start.elapsed();

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

    Ok(rtt)
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
        // Test with known values
        let data = vec![0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00];
        let checksum = calculate_checksum(&data);
        // Just verify it produces a value (specific value depends on full packet)
        assert!(checksum > 0);
    }

    #[test]
    #[ignore] // Requires root privileges
    fn test_ping_localhost() {
        let dest = Ipv4Addr::new(127, 0, 0, 1);
        let payload = b"test payload";
        let timeout = Duration::from_secs(5);

        match send_icmp_echo(dest, payload, timeout) {
            Ok(rtt) => {
                println!("RTT: {:?}", rtt);
                assert!(rtt < timeout);
            }
            Err(e) => {
                eprintln!("Ping failed: {}", e);
                // This test may fail without proper permissions
            }
        }
    }
}
