use rayon::prelude::*;
use tracing::{debug, error, info, instrument, trace, warn};
use tracing_subscriber::{fmt, EnvFilter};


use pff::{
    block::{add_ip_to_spammers, reload_firewall_rules},
    config::Config,
    IP, UNWANTED, WANTED,
};
use std::{
    fs::File,
    io::{self, prelude::*},
};


/// is_partial returns true when the line doesn't begin with an IP octet:
#[instrument]
fn is_partial(line: &str) -> bool {
    !IP.is_match(line)
}


/// Initialize logger and tracingformatter
#[instrument]
fn initialize() {
    let env_log = match EnvFilter::try_from_env("LOG") {
        Ok(env_value_from_env) => env_value_from_env,
        Err(_) => EnvFilter::from("info"),
    };
    fmt()
        .compact()
        .with_thread_names(false)
        .with_thread_ids(false)
        .with_ansi(true)
        .with_env_filter(env_log)
        .with_filter_reloading()
        .init();
}


/// Uncompress the input file using simple GzEncoder
#[instrument]
fn read_file_bytes(mut file: File) -> io::Result<Vec<u8>> {
    let mut buf = vec![];
    match file.read_to_end(&mut buf) {
        Ok(bytes_read) => {
            debug!("Input file read bytes: {bytes_read}");

            Ok(buf)
        }
        Err(err) => Err(err),
    }
}


#[instrument]
fn main() {
    initialize();
    info!(
        "Starting {} v{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
    let access_log = Config::access_log();
    let decoded_log = File::open(&access_log).and_then(read_file_bytes);
    info!("Loading the log: {access_log}");
    let maybe_log = decoded_log
        .map(|input_data| {
            let input_data_length = input_data.len();
            debug!("Input data length: {input_data_length}");
            if Config::buffer() == 0 || Config::buffer() >= input_data_length {
                debug!("Loading full uncompressed input file of size: {input_data_length}.");
                input_data
            } else {
                let buffer = input_data_length - Config::buffer();
                debug!("The uncompressed input file is now at position: {buffer}.");
                input_data.into_par_iter().skip(buffer).collect()
            }
        })
        .map(|input_contents| {
            String::from_utf8_lossy(&input_contents)
                .split('\n')
                .filter_map(|line| {
                    if line.is_empty() || is_partial(line) {
                        None
                    } else {
                        Some(line.to_string())
                    }
                })
                .collect::<Vec<_>>()
        });
    match maybe_log {
        Ok(lines) => {
            info!("Scanning the access_log…");
            let mut ips: Vec<String> = vec![];
            for line in lines {
                trace!("Processling line: '{line}'");
                match &IP.captures(&line) {
                    Some(ip_match) => {
                        let ip = &ip_match[0];
                        if !WANTED.is_match(&line) && !UNWANTED.is_match(&line) {
                            debug!("No match for the line: '{line}', skipping it.");
                        } else if WANTED.is_match(&line) {
                            debug!(
                                "Detected normal request from IPv4: {ip}, by the line: '{line}'"
                            );
                        } else if UNWANTED.is_match(&line) && !ips.contains(&ip.to_string()) {
                            debug!(
                                "Detected previously unseen malicious request from IPv4: {ip}, by the line: '{line}'"
                            );
                            ips.push(ip.to_string());
                        } else {
                            debug!(
                                "Detected malicious request from IPv4: {ip} that's already known, skipping it."
                            )
                        }
                    }
                    None => {
                        warn!("No IPv4 match in line: '{line}'. Skipping it");
                    }
                }
            }
            info!("Scan completed.");

            add_ip_to_spammers(&ips)
                .map(|_| reload_firewall_rules())
                .unwrap_or_default()
        }
        Err(reason) => {
            error!("Error reading file: {access_log}, the error is: {reason}")
        }
    }
}
