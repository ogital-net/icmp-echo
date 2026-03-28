use icmp_echo::ping_async;
use std::env;
use std::net::IpAddr;
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <ip_address> [count] [payload_size]", args[0]);
        eprintln!("Example: {} 8.8.8.8", args[0]);
        eprintln!("Example: {} 8.8.8.8 10 64", args[0]);
        eprintln!("Example: {} 2001:4860:4860::8888 5 56", args[0]);
        std::process::exit(1);
    }

    let address = &args[1];
    let dest: IpAddr = address.parse().unwrap_or_else(|_| {
        eprintln!("Invalid IP address: {}", address);
        std::process::exit(1);
    });

    let count = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);
    let payload_size = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(56);

    println!(
        "Pinging {} with {} bytes of data ({} times) [async]...",
        dest, payload_size, count
    );

    match ping_async(dest, payload_size, count, Duration::from_secs(5)).await {
        Ok((avg_rtt, packet_loss)) => {
            println!("✓ Ping successful!");
            println!("  Average round-trip time: {:.3} ms", avg_rtt);
            println!("  Packet loss: {:.1}%", packet_loss);
        }
        Err(e) => {
            eprintln!("✗ Ping failed: {}", e);
            eprintln!("\nNote: This program requires raw socket permissions.");
            eprintln!("      Run with: sudo target/debug/examples/async_ping <ip>");
            std::process::exit(1);
        }
    }
}
