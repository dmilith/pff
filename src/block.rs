use crate::config::Config;
use crate::*;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;


#[instrument]
pub fn add_ip_to_spammers(ip: &str) {
    let mut read_file = File::open(Config::spammers_file())
        .expect("The spammers file should exists with newline separated IPs.");
    let mut buf = String::new();
    read_file
        .read_to_string(&mut buf)
        .expect("The spammers file has to be readable.");
    if buf.contains(ip) {
        debug!("The IP: '{ip}' is already present in the spammers file.");
    } else {
        drop(read_file);
        drop(buf);

        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(Config::spammers_file())
            .expect("The spammers file should exists with newline separated IPs");
        file.write_all(format!("{ip}\n").as_bytes())
            .expect("Couldn't write to spammers file!");
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
