use regex::Regex;
use ron::ser::{to_string_pretty, PrettyConfig};
use std::sync::Arc;

use crate::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};


pub const BUFFER_TO_CHECK_IN_BYTES: usize = 16 * 1024 * 1024; // check last 16 MiBs of the log at once

pub const POSSIBLE_CONFIGS: &[&str] =
    &["pff.conf", "/Services/Pff/service.conf", "/etc/pff.conf"];


#[derive(Serialize, Deserialize)]
pub struct Config {
    access_log: Arc<str>,
    system_log: Arc<str>,
    spammers_file: Arc<str>,
    buffer: usize,

    #[serde(with = "serde_regex")]
    wanted: Regex,

    #[serde(with = "serde_regex")]
    unwanted: Regex,
}


impl Default for Config {
    fn default() -> Self {
        Self {
            spammers_file: "/etc/spammers".into(),
            access_log: "/Services/Nginx/logs/access.log".into(),
            system_log: "/var/log/messages".into(),
            buffer: BUFFER_TO_CHECK_IN_BYTES,
            wanted: Regex::new(r"(\.tgz|\.ttf|\.bz2|\.gz|\.xz|\.zfsx|\.zfsp|/robots\.txt|/security\.txt|favicon\.ico|\.m[4kop][34av]|sitemap.xml|/.well-known|\.svg|verknowsys|\.wasm|[[:alnum:]]{32}\.p[dn][fg]|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|10\.0\.0\.d{1,3})").expect("Wanted regex should work"),
            unwanted: Regex::new(r"(\.php|\.lua|XDEBUG|config\.|login\.|\.DS_Store|mifs|\.axd|wp-*|\.aws|\.[axy]ml|\.[aj]sp+|microsoft|\.env|\\x\d+|\.cgi|cgi-bin|HNAP1|formLogin|owa/auth/x|/dev|/tmp|/var/tmp|PAM: Authentication error for illegal user)").expect("Unwanted regex should work"),
        }
    }
}


impl Config {
    pub fn load() -> Self {
        Self::load_config_file()
    }


    /// Determine a default config file
    pub fn find_config() -> Option<Arc<str>> {
        let config = config::POSSIBLE_CONFIGS
            .iter()
            .filter_map(|file| {
                if !Path::new(file).exists() {
                    None
                } else {
                    Some(file.to_owned())
                }
            })
            .take(1)
            .collect::<String>();
        if config.is_empty() {
            None
        } else {
            Some(config.into())
        }
    }


    pub fn load_config_file() -> Config {
        match Config::find_config() {
            Some(log) => {
                debug!("Found configuration file: {log}");
                match File::open(&*log) {
                    Ok(mut read_file) => {
                        let mut buf = String::new();
                        let _ = read_file.read_to_string(&mut buf);
                        match ron::from_str(&buf) {
                            Ok(obj) => return obj,
                            Err(err) => {
                                error!("Failed to parse the configuration file: {log}: {err}");
                            }
                        }
                    }
                    Err(err) => {
                        error!("Couldn't open configuration file: {log}: {err}.");
                    }
                }
            }

            None => {
                let log = config::POSSIBLE_CONFIGS[0]; // fallback to the local dir configuration
                warn!("Creating the default configuration in: {log}.");

                match to_string_pretty(
                    &Config::default(),
                    PrettyConfig::new().new_line("\n".to_string()),
                ) {
                    Ok(config) => {
                        debug!("Writing the config: {config}");
                        let mut file = OpenOptions::new()
                            .create(true)
                            .write(true)
                            .open(log)
                            .expect("The configuration file should be in a writable place!");
                        file.write_all(format!("{config}\n").as_bytes())
                            .expect("Couldn't write to configuration file!");
                    }
                    Err(err) => {
                        error!(
                            "Couldn't serialize the default configuration file: {log}: {err}"
                        )
                    }
                }
            }
        };
        Config::default()
    }

    pub fn access_log() -> Arc<str> {
        Config::load().access_log
    }

    pub fn system_log() -> Arc<str> {
        Config::load().system_log
    }

    pub fn buffer() -> usize {
        Config::load().buffer
    }

    pub fn wanted() -> Regex {
        Config::load().wanted
    }

    pub fn unwanted() -> Regex {
        Config::load().unwanted
    }

    pub fn spammers_file() -> Arc<str> {
        Config::load().spammers_file
    }
}
