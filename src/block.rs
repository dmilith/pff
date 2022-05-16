use crate::{config::Config, *};

use rayon::prelude::*;
use std::{
    fs::OpenOptions,
    io::{Error, ErrorKind, Read, Write},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};


/// Add IPv4 to spammers file
#[instrument]
pub fn add_ip_to_spammers(ips: &Vec<String>) -> Result<(), Error> {
    if ips.is_empty() {
        debug!("No need to reload firewall");
        return Err(Error::new(
            ErrorKind::Other,
            "Empty IP list, no need to reload the firewall",
        ));
    }
    let buf = Arc::new(Mutex::new(String::from("")));
    let mut buf_locked = buf.lock().unwrap();
    OpenOptions::new()
        .open(Config::spammers_file())?
        .read_to_string(&mut buf_locked)?;
    drop(buf_locked);

    let list_of_ips: String = ips
        .par_iter()
        .filter_map(|ip| {
            let mut buffer = buf.lock().unwrap();
            if buffer.contains(ip) {
                None
            } else {
                let formatted = format!("{ip}\n");
                *buffer += &formatted;
                Some(formatted)
            }
        })
        .collect();
    drop(buf);

    if list_of_ips.is_empty() {
        debug!("No need to reload firewall");
        Err(Error::new(
            ErrorKind::Other,
            "List of IPs is empty, no need to reload the firewall",
        ))
    } else {
        OpenOptions::new()
            .write(true)
            .append(true)
            .open(Config::spammers_file())
            .and_then(|mut file| file.write_all(list_of_ips.as_bytes()))
    }
}


/// runs command to reload firewall rules
#[instrument]
pub fn reload_firewall_rules() {
    info!("Reloading firewall rules");
    #[cfg(target_os = "macos")]
    match Command::new("sudo")
        .args(&["pfctl", "-v", "-Tl", "-f", "/etc/pf.conf"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(_) => debug!("pfctl command successful"),
        Err(err) => error!("pfctl failed with: {err}"),
    }


    #[cfg(target_os = "freebsd")]
    match Command::new("pfctl")
        .args(&["-v", "-Tl", "-f", "/etc/pf.conf"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(_) => debug!("pfctl command successful"),
        Err(err) => error!("pfctl failed with: {err}"),
    }
}
