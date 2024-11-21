//Tool for sweeping Active Directory Certificate Services endpoints in an environment.//
//Created by Cr1ms3nRav3n7 Nov 21, 2024//
//Version 1.0//

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
extern crate reqwest;

fn main() {
    println!("Sweeping for ADCS web enrollment...");
    if let Ok(lines) = read_lines("./80.txt") {
        for line in lines.flatten() {
            let body = reqwest::blocking::get(format!("http://{}/certsrv/certfnsh.asp", line));
            let content = body.unwrap().text().unwrap();
            if content.contains("Unauthorized Access") {
                println!("{} is likely hosting ADCS!", line);
            }
        }
    }
    println!("Completed sweeps!");
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
