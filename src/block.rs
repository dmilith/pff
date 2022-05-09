use crate::config::Config;
use crate::*;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;


#[instrument]
pub fn add_ip_to_spammers(ips: &Vec<String>) -> Result<(), Error> {
    let mut read_file = File::open(Config::spammers_file())?;
    let mut buf = String::new();
    read_file.read_to_string(&mut buf)?;
    drop(read_file);

    let list_of_ips: String = ips
        .iter()
        .filter_map(|ip| {
            if buf.contains(ip) {
                None
            } else {
                let formatted = format!("{ip}\n");
                buf += &formatted; // add the ip to the buf to deduplicate entries
                Some(formatted)
            }
        })
        .collect();
    drop(buf);

    OpenOptions::new()
        .write(true)
        .append(true)
        .open(Config::spammers_file())
        .and_then(|mut file| file.write_all(list_of_ips.as_bytes()))
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
        Ok(_) => info!("pfctl command successful"),
        Err(err) => error!("pfctl failed with: {err}"),
    }


    #[cfg(target_os = "freebsd")]
    match Command::new("pfctl")
        .args(&["-v", "-Tl", "-f", "/etc/pf.conf"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(_) => info!("pfctl command successful"),
        Err(err) => error!("pfctl failed with: {err}"),
    }
}
