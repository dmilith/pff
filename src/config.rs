use regex::Regex;
use ron;
pub use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
};
use tracing::{debug, error};

// pub use serde_derive::{Deserialize, Serialize};


pub const BUFFER_TO_CHECK_IN_BYTES: usize = 65535;


#[derive(Serialize, Deserialize)]
pub struct Config {
    access_log: String,
    spammers_file: String,
    buffer: usize,

    #[serde(with = "serde_regex")]
    wanted: Regex,

    #[serde(with = "serde_regex")]
    unwanted: Regex,
}


impl Default for Config {
    fn default() -> Self {
        Self {
            spammers_file: "/etc/spammers".to_string(),
            access_log: "/Services/Nginx/logs/access.log.gz".to_string(),
            buffer: 65535usize,
            wanted: Regex::new(r"(/robots\.txt|favicon\.ico|\.m[4kop][34av]|sitemap.xml|/.well-known|\.svg|verknowsys|\.wasm|[[:alnum:]]{32}\.p[dn][fg])").unwrap(),
            unwanted: Regex::new(r"(\.php|XDEBUG|config\.*|login\.|\.DS_Store|mifs|\.axd|wp-*|\.aws|\.[axy]ml|\.[aj]sp*|microsoft|\.env|\\x\d+|\.cgi|cgi-bin|HNAP1|formLogin|owa/auth/x|/dev|/tmp|/var/tmp)").unwrap(),
        }
    }
}


impl Config {
    pub fn load() -> Self {
        Self::load_config_file()
    }

    pub fn load_config_file() -> Config {
        // for log in ["plog.conf", "/Services/Plog/service.conf", "/etc/plog.conf"] {
        //     // if File::from(&log).exists() {
        //     //     log
        //     // }
        // }
        match File::open("./plog.conf") {
            Ok(mut read_file) => {
                let mut buf = String::new();
                let _ = read_file.read_to_string(&mut buf);
                match ron::from_str(&buf) {
                    Ok(obj) => {
                        debug!("Loaded configuration");
                        obj
                    }
                    Err(err) => {
                        error!("Couldn't load configuration: {err}");
                        Config::default()
                    }
                }
            }
            Err(err) => {
                error!(
                    "Couldn't open configuration file {err}. Creating new default configuration."
                );

                match ron::to_string(&Config::default()) {
                    Ok(config) => {
                        debug!("Config: {config}");
                        let mut file = OpenOptions::new()
                            .create(true)
                            .write(true)
                            .open("./plog.conf")
                            .expect("The configuration file should be in a writable place!");
                        file.write_all(format!("{config}\n").as_bytes())
                            .expect("Couldn't write to configuration file!");
                    }
                    Err(err) => {
                        error!("Couldn't serialize the default configuration file! {err}")
                    }
                }
                Config::default()
            }
        }
    }

    pub fn access_log() -> String {
        Config::load().access_log
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

    pub fn spammers_file() -> String {
        Config::load().spammers_file
    }
}
