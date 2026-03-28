# icmp-echo

A Rust library for sending ICMP echo requests (ping) and measuring round-trip time.

## Features

- Send ICMP echo requests with custom payloads
- Support for both IPv4 and IPv6
- Measure round-trip time (RTT) for replies
- High-level convenience function for simple pinging
- Simple, straightforward API
- Do Not Fragment (DF) bit always set for Path MTU Discovery
- Thread-safe with machine-unique identifiers
- Low-level socket implementation using libc

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
icmp-echo = "0.1.0"
```

### Quick Start with ping()

The easiest way to ping a host:

```rust
use icmp_echo::ping;
use std::net::IpAddr;

fn main() {
    let dest = "8.8.8.8".parse::<IpAddr>().unwrap();
    match ping(dest, 56, 4) {
        Ok(avg_rtt) => {
            println!("Average RTT: {:.3} ms", avg_rtt);
        }
        Err(e) => {
            eprintln!("Ping failed: {}", e);
        }
    }
}
```

### Basic Example with send_icmp_echo()

For more control, use the lower-level API:

```rust
use icmp_echo::send_icmp_echo;
use std::net::IpAddr;
use std::time::Duration;

fn main() {
    let dest = "8.8.8.8".parse::<IpAddr>().unwrap();
    let payload = b"Hello, ICMP!";
    let timeout = Duration::from_secs(5);

    match send_icmp_echo(dest, payload, timeout) {
        Ok(rtt) => {
            println!("Reply received in {:.3} ms", rtt.as_secs_f64() * 1000.0);
        }
        Err(e) => {
            eprintln!("Ping failed: {}", e);
        }
    }
}
```

### Running the Examples

```bash
# Build the examples
cargo build --examples

# Simple ping helper (recommended for most use cases)
sudo target/debug/examples/simple_ping 8.8.8.8
sudo target/debug/examples/simple_ping 8.8.8.8 10 64  # 10 pings, 64 byte payload

# Lower-level API example
sudo target/debug/examples/ping 8.8.8.8
sudo target/debug/examples/ping 2001:4860:4860::8888  # IPv6
```

## Requirements

**Important:** This library requires raw socket permissions, which typically means:
- On Linux/macOS: Run as root or use `sudo`
- On macOS: May require additional security permissions
- On Windows: Run as Administrator

## API

### `ping`

```rust
pub fn ping(
    dest: IpAddr,
    payload_size: usize,
    count: usize
) -> io::Result<f64>
```

High-level convenience function that sends multiple ICMP echo requests and returns the average RTT.

**Parameters:**
- `dest`: Destination IP address (IPv4 or IPv6)
- `payload_size`: Total payload size in bytes, including 8 bytes for timestamp (minimum 8)
- `count`: Number of echo requests to send

**Returns:**
- `Ok(f64)`: Average round-trip time in milliseconds
- `Err(io::Error)`: If no responses received or socket operations fail

### `send_icmp_echo`

```rust
pub fn send_icmp_echo(
    dest: IpAddr,
    payload: &[u8],
    timeout: Duration
) -> io::Result<Duration>
```

Low-level function that sends a single ICMP echo request and returns the RTT.

**Parameters:**
- `dest`: Destination IP address (IPv4 or IPv6)
- `payload`: Arbitrary payload data to include in the ICMP packet
- `timeout`: Maximum time to wait for a reply

**Returns:**
- `Ok(Duration)`: Round-trip time if a reply is received
- `Err(io::Error)`: If the operation fails or times out

## Implementation Details

This library uses raw ICMP sockets to send echo requests and receive replies. The implementation:

1. Creates a raw socket with `SOCK_RAW` and `IPPROTO_ICMP` (or `IPPROTO_ICMPV6`)
2. Sets the Do Not Fragment (DF) bit for Path MTU Discovery
3. Uses monotonic clock timestamps for accurate RTT measurement
4. Generates thread-unique identifiers by XORing thread counter with process ID
5. Constructs ICMP echo request packets with proper checksumming
6. Sends packets to the destination
7. Waits for echo replies with matching ID
8. Calculates round-trip time from embedded timestamps

The payload generation follows the pattern used in standard ping implementations (sequential byte values).

The C reference implementations in the repository (from FreeBSD, GNU, and Solaris) were used as guidance for the protocol implementation.

## License

See LICENSE file for details.

