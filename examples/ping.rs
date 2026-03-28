use icmp_echo::send_icmp_echo;
use std::env;
use std::net::IpAddr;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <ip_address>", args[0]);
        eprintln!("Example: {} 8.8.8.8", args[0]);
        eprintln!("Example: {} 2001:4860:4860::8888", args[0]);
        std::process::exit(1);
    }

    let dest: IpAddr = args[1].parse().unwrap_or_else(|_| {
        eprintln!("Invalid IP address: {}", args[1]);
        std::process::exit(1);
    });

    let ip_version = match dest {
        IpAddr::V4(_) => "IPv4",
        IpAddr::V6(_) => "IPv6",
    };

    println!("Sending {} ICMP echo request to {}...", ip_version, dest);

    let payload = b"Hello from Rust ICMP!";
    let timeout = Duration::from_secs(5);

    match send_icmp_echo(dest, payload, timeout) {
        Ok(rtt) => {
            println!("✓ Reply received!");
            println!("  Round-trip time: {:.3} ms", rtt.as_secs_f64() * 1000.0);
        }
        Err(e) => {
            eprintln!("✗ Ping failed: {}", e);
            eprintln!("\nNote: This program requires raw socket permissions.");
            eprintln!("      Run with: sudo target/debug/examples/ping <ip>");
            std::process::exit(1);
        }
    }
}
