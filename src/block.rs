use crate::{config::Config, *};

use rayon::prelude::*;
use std::{
    fs::OpenOptions,
    io::{Error, ErrorKind, Read, Write},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};


/// List Ipv4 from spammers file
#[instrument]
pub fn all_current_spammers(ips: &Vec<String>) -> Result<String, Error> {
    let buf = Arc::new(Mutex::new(String::from("")));
    if let Ok(mut inner_buf) = buf.lock() {
        OpenOptions::new()
            .read(true)
            .open(&*Config::spammers_file())?
            .read_to_string(&mut inner_buf)?;
    }

    let list_of_ips: String = ips
        .par_iter()
        .filter_map(|ip| {
            match buf.lock() {
                Ok(mut buffer) => {
                    if buffer.contains(ip) {
                        None
                    } else {
                        let formatted = format!("{ip}\n");
                        *buffer += &formatted;
                        Some(formatted)
                    }
                }
                Err(e) => {
                    error!("Error: {e}");
                    None
                }
            }
        })
        .collect();
    Ok(list_of_ips)
}


/// Add IPv4 to spammers file
#[instrument]
pub fn add_ip_to_spammers(ips: &Vec<String>, all_spammers: &String) -> Result<(), Error> {
    if ips.is_empty() {
        debug!("No need to reload firewall");
        return Err(Error::new(
            ErrorKind::Other,
            "Empty IP list, no need to reload the firewall",
        ));
    }

    if all_spammers.is_empty() {
        debug!("No need to reload firewall");
        Err(Error::new(
            ErrorKind::Other,
            "List of IPs is empty, no need to reload the firewall",
        ))
    } else {
        OpenOptions::new()
            .append(true)
            .open(&*Config::spammers_file())
            .and_then(|mut file| {
                debug!("Written to file: {file:?} all_spammers: {all_spammers:?}");
                file.write_all(all_spammers.as_bytes())
            })
    }
}


/// runs command to reload firewall rules
#[instrument]
pub fn reload_firewall_rules() -> Result<(), Error> {
    info!("Reloading firewall rules");
    #[cfg(target_os = "macos")]
    match Command::new("sudo")
        .args(["pfctl", "-v", "-Tl", "-f", "/etc/pf.conf"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) => {
            debug!("pfctl command successful. The output: {out:?}");
            Ok(())
        }
        Err(err) => {
            error!("pfctl failed with: {err}");
            Err(err)
        }
    }

    #[cfg(target_os = "freebsd")]
    match Command::new("pfctl")
        .args(&["-v", "-Tl", "-f", "/etc/pf.conf"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) => {
            debug!("pfctl command successful. The output: {out:?}");
            Ok(())
        }
        Err(err) => {
            error!("pfctl failed with: {err}");
            Err(err)
        }
    }
}
