use regex::Regex;

pub const BUFFER_TO_CHECK_IN_BYTES: usize = 65535;


pub struct Config {
    access_log: String,
    spammers_file: String,
    buffer: usize,
    wanted: Option<Vec<Regex>>,
    unwanted: Option<Vec<Regex>>,
}


impl Default for Config {
    fn default() -> Self {
        Self {
            spammers_file: "/etc/spammers".to_string(),
            access_log: "/Services/Nginx/logs/access.log.gz".to_string(),
            buffer: 65535usize,
            wanted: Some(vec![ Regex::new(r"(/.well-known|\.svg|verknowsys|robots\.txt|favicon\.ico|[[:alnum:]]{32}\.p[dn][fg]|\.m[4kop][34av]|sitemap.xml|\.wasm)").unwrap() ]),
            unwanted: Some(vec![ Regex::new(r"(\.php|XDEBUG|config\.*|login\.|\.DS_Store|mifs|\.axd|wp-*|\.aws|\.[axy]ml|\.[aj]sp*|microsoft|\.env|\\x\d+|\.cgi|cgi-bin|HNAP1|formLogin|owa/auth/x|/dev|/tmp|/var/tmp)").unwrap() ]),
        }
    }
}


impl Config {
    pub fn load() -> Self {
        // TODO: load from file
        Self::default()
    }

    pub fn access_log() -> String {
        Config::load().access_log
    }

    pub fn buffer() -> usize {
        Config::load().buffer
    }

    pub fn wanted() -> Option<Vec<Regex>> {
        Config::load().wanted
    }

    pub fn unwanted() -> Option<Vec<Regex>> {
        Config::load().unwanted
    }

    pub fn spammers_file() -> String {
        Config::load().spammers_file
    }
}
