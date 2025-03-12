use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use reqwest::{Client, StatusCode};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::task;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Print ASCII banner with two bombs
    println!(r#"
    [*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]
    ________   ______   ______   ______       ______   __ __ __   ______   ______   ______   ______   ______
   /_______/\ /_____/\ /_____/\ /_____/\     /_____/\ /_//_//_/\ /_____/\ /_____/\ /_____/\ /_____/\ /_____/\
   \::: _  \ \\:::_ \ \\:::__\/ \::::_\/_    \::::_\/_\:\\:\\:\ \\::::_\/_\::::_\/_\:::_ \ \\::::_\/_\:::_ \ \
    \::(_)  \ \\:\ \ \ \\:\ \  __\:\/___/\    \:\/___/\\:\\:\\:\ \\:\/___/\\:\/___/\\:(_) \ \\:\/___/\\:(_) ) )_
     \:: __  \ \\:\ \ \ \\:\ \/_/\\_::._\:\    \_::._\:\\:\\:\\:\ \\::___\/_\::___\/_\: ___\/ \::___\/_\: __ `\ \
      \:.\ \  \ \\:\/.:| |\:\_\ \ \ /____\:\     /____\:\\:\\:\\:\ \\:\____/\\:\____/\\ \ \    \:\____/\\ \ `\ \ \
       \__\/\__\/ \____/_/ \_____\/ \_____\/     \_____\/ \_______\/ \_____\/ \_____\/ \_\/     \_____\/ \_\/ \_\/
     [*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]

     version 1.0 Cr1ms3nRav3n7
    "#);
    // Get command line arguments
    let args: Vec<String> = env::args().collect();

    let filename = if args.len() < 2 {
        println!("Usage: {} <filename>", args[0]);
        println!("Example: {} hosts.txt", args[0]);
        println!("File should contain one IP address per line");
        return Ok(());
    } else {
        &args[1]
    };

    // Read hosts from file
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let hosts: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

    if hosts.is_empty() {
        println!("No hosts found in {}", filename);
        return Ok(());
    }

    // Create progress bar
    let pb = ProgressBar::new(hosts.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("##-")
    );

    // Create HTTP client with timeout, no redirects, and ignoring SSL errors
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .build()?;

    println!("Scanning {} hosts from {} for ADCS web endpoints (HTTP only)...", hosts.len(), filename);

    let mut confirmed_endpoints = 0;
    let mut potential_endpoints = 0;
    let mut tasks = Vec::new();

    // Spawn tasks for each host
    for host in &hosts {
        let client = client.clone();
        let host = host.clone();
        let pb = pb.clone();

        let task = task::spawn(async move {
            let result = scan_host(&client, &host).await;
            pb.inc(1);
            result
        });
        tasks.push(task);
    }

    // Wait for all tasks to complete and aggregate results
    for task in tasks {
        if let Ok(Ok((confirmed, potential))) = task.await {
            if confirmed {
                confirmed_endpoints += 1;
            }
            if potential {
                potential_endpoints += 1;
            }
        }
    }

    // Finish and clear the progress bar, then print the message on a new line
    pb.finish_and_clear();

    let finish_message = if confirmed_endpoints == 0 && potential_endpoints == 0 {
        String::from("⚠ No ADCS endpoints found in the scanned hosts. Scan complete")
    } else {
        let mut msg = String::new();
        if confirmed_endpoints > 0 {
            msg.push_str(&format!("Found {} confirmed ADCS endpoint(s). ", confirmed_endpoints));
        }
        if potential_endpoints > 0 {
            msg.push_str(&format!("Found {} potential ADCS endpoint(s) (401/403 responses). ", potential_endpoints));
        }
        msg.push_str("Scan complete");
        msg
    };

    println!("{}", finish_message);
    Ok(())
}

// Scan a single host, returning (confirmed, potential)
async fn scan_host(client: &Client, host: &str) -> Result<(bool, bool), reqwest::Error> {
    if let Ok(ip_addr) = host.parse::<IpAddr>() {
        let port = 80;
        if is_port_open(ip_addr, port).await {
            let url = format!("http://{}:{}/certsrv/certfnsh.asp", ip_addr, port);
            let display_url = format!("http://{}/certsrv/certfnsh.asp", ip_addr);

            let response = client.get(&url).send().await?;
            let status = response.status();

            if status.is_success() {
                let text = response.text().await?;
                let confirmed = text.contains("Certificate Services") ||
                               text.contains("certsrv") ||
                               text.contains("Microsoft Active Directory Certificate Services");
                if confirmed {
                    println!("✓ Confirmed ADCS endpoint at: {}", display_url);
                    return Ok((true, false));
                }
            } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                println!("? Potential ADCS endpoint at: {} (HTTP {})", display_url, status.as_u16());
                return Ok((false, true));
            }
        }
    } else {
        println!("Invalid IP address: {}", host);
    }
    Ok((false, false))
}

// Check if port is open
async fn is_port_open(ip: IpAddr, port: u16) -> bool {
    let address = format!("{}:{}", ip, port);
    let timeout_duration = Duration::from_secs(2);

    matches!(
        timeout(timeout_duration, TcpStream::connect(&address)).await,
        Ok(Ok(_))
    )
}
