use rayon::prelude::*;
use std::fmt::Write;
use tracing::{debug, error, info, instrument, trace, warn};
use tracing_subscriber::{fmt, EnvFilter};


use pff::{
    block::{add_ip_to_spammers, all_current_spammers, reload_firewall_rules},
    config::Config,
    IP, UNWANTED, WANTED,
};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, prelude::*},
    sync::{Arc, Mutex},
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
    let system_log = Config::system_log();
    let decoded_log = File::open(&*access_log).and_then(read_file_bytes);
    let decoded_system_log = File::open(&*system_log).and_then(read_file_bytes);

    info!("Loading logs: {access_log}, {system_log}");
    let maybe_access_log = decoded_log
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
    let maybe_system_log = decoded_system_log
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

    // combine both logs
    let lines = [
        maybe_access_log.unwrap_or_default(),
        [String::from("\n")].to_vec(),
        maybe_system_log.unwrap_or_default(),
    ]
    .concat();

    // format: [key: IPv4, value: line]
    let new_seen = Arc::new(Mutex::new(HashMap::new()));
    let ips = lines
        .par_iter()
        .filter_map(|line| {
            trace!("Processling line: '{line}'");
            match &IP.captures(line) {
                Some(ip_match) => {
                    let ip = &ip_match[0];
                    let ip_str = ip.to_string();
                    match new_seen.lock() {
                        Ok(mut seen_lock) => {
                            if !WANTED.is_match(line) && !UNWANTED.is_match(line) {
                                None
                            } else if UNWANTED.is_match(line)
                                && !seen_lock.contains_key(&ip_str)
                            {
                                seen_lock.insert(ip_str.to_owned(), line);
                                Some(ip_str)
                            } else {
                                None
                            }
                        }
                        Err(e) => {
                            error!("Error: {e}");
                            None
                        }
                    }
                }
                None => {
                    debug!("No IPv4 match in line: '{line}'. Skipping it");
                    None
                }
            }
        })
        .collect();
    info!("Scan completed.");

    let all_current_spammers = all_current_spammers(&ips).unwrap_or_default();
    match new_seen.lock() {
        Ok(seen_lock) => {
            let block_list: String = seen_lock
                .iter()
                .filter(|(ip_key, _)| all_current_spammers.contains(*ip_key))
                .fold(String::new(), |mut result, (ipv4, line)| {
                    let _ = writeln!(result, "Blocked: '{ipv4}', Request line: '{line}'");
                    result
                });
            if !block_list.is_empty() {
                info!("Newly blocked:\n\n{block_list}\n\n");
            }
        }
        Err(e) => {
            error!("Failed to acquire lock. Failure: {e}");
        }
    }
    add_ip_to_spammers(&ips, &all_current_spammers)
        .and_then(|_| reload_firewall_rules())
        .map_err(|err| {
            info!("Firewall reload skipped.");
            debug!("Skipped because: {err}");
        })
        .unwrap_or_default();

    info!("Spammers processing is now complete.");
}
