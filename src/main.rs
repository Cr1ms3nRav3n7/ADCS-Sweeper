use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use reqwest::Client;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::task;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    
    // Check if file argument is provided
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

    // Track if any endpoints are found
    let mut endpoints_found = false;
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

    // Wait for all tasks to complete and check results
    for task in tasks {
        if let Ok(found) = task.await? {
            if found {
                endpoints_found = true;
            }
        }
    }

    // Check if no endpoints were found and print alert
    if !endpoints_found {
        println!("⚠ No ADCS endpoints found in the scanned hosts.");
    }

    pb.finish_with_message("Scan complete");
    Ok(())
}

// Scan a single host
async fn scan_host(client: &Client, host: &str) -> Result<bool, Box<dyn std::error::Error>> {
    if let Ok(ip_addr) = host.parse::<IpAddr>() {
        let port = 80;
        if is_port_open(ip_addr, port).await {
            let url = format!("http://{}:{}/certsrv/certfnsh.asp", ip_addr, port);
            let display_url = format!("http://{}/certsrv/certfnsh.asp", ip_addr);
            
            match check_adcs_endpoint(client, &url).await {
                Ok(found) => {
                    if found {
                        println!("✓ Found ADCS endpoint at: {}", display_url);
                        return Ok(true);
                    }
                }
                Err(e) => println!("Error checking {}: {}", display_url, e),
            }
        }
    } else {
        println!("Invalid IP address: {}", host);
    }
    Ok(false)
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

// Check if URL is an ADCS endpoint
async fn check_adcs_endpoint(client: &Client, url: &str) -> Result<bool, reqwest::Error> {
    let response = client.get(url)
        .send()
        .await?;
    
    if response.status().is_success() {
        let text = response.text().await?;
        Ok(text.contains("Certificate Services") || 
           text.contains("certsrv") || 
           text.contains("Microsoft Active Directory Certificate Services"))
    } else {
        Ok(false)
    }
}
