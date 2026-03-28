# icmp-echo

A Rust library for sending ICMP echo requests (ping) and measuring round-trip time.

## Features

- Send ICMP echo requests with custom payloads
- Measure round-trip time (RTT) for replies
- Simple, straightforward API
- Low-level socket implementation using libc

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
icmp-echo = "0.1.0"
```

### Basic Example

```rust
use icmp_echo::send_icmp_echo;
use std::net::Ipv4Addr;
use std::time::Duration;

fn main() {
    let dest = Ipv4Addr::new(8, 8, 8, 8);
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

### Running the Example

```bash
# Build the example
cargo build --example ping

# Run with sudo (required for raw sockets)
sudo target/debug/examples/ping 8.8.8.8
```

## Requirements

**Important:** This library requires raw socket permissions, which typically means:
- On Linux/macOS: Run as root or use `sudo`
- On macOS: May require additional security permissions
- On Windows: Run as Administrator

## API

### `send_icmp_echo`

```rust
pub fn send_icmp_echo(
    dest: Ipv4Addr,
    payload: &[u8],
    timeout: Duration
) -> io::Result<Duration>
```

Sends an ICMP echo request to the specified destination and returns the round-trip time.

**Parameters:**
- `dest`: Destination IPv4 address
- `payload`: Arbitrary payload data to include in the ICMP packet
- `timeout`: Maximum time to wait for a reply

**Returns:**
- `Ok(Duration)`: Round-trip time if a reply is received
- `Err(io::Error)`: If the operation fails or times out

## Implementation Details

This library uses raw ICMP sockets to send echo requests and receive replies. The implementation:

1. Creates a raw socket with `SOCK_RAW` and `IPPROTO_ICMP`
2. Constructs an ICMP echo request packet with proper checksumming
3. Sends the packet to the destination
4. Waits for an echo reply with matching ID
5. Calculates the round-trip time

The C reference implementations in the repository (from FreeBSD, GNU, and Solaris) were used as guidance for the protocol implementation.

## License

See LICENSE file for details.

