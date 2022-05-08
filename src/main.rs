use flate2::bufread::GzDecoder;
use lazy_static::lazy_static;
use regex::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::io::{self};


lazy_static! {
    static ref IP: Regex = Regex::new(r"(?P<ip>(\d+\.\d+\.\d+\.\d+))").unwrap();

    static ref UNWANTED: Vec<Regex> = vec![ Regex::new(r"(wp-*|\.php|\.xml|\.asp*|microsoft|\.env|\\x\d+|cgi-bin|HNAP1|formLogin|owa/auth/x|/dev|/tmp|/var/tmp)").unwrap() ];

    static ref WANTED: Vec<Regex> = vec![ Regex::new(r"(/.well-known|\.svg|verknowsys|robots\.txt|favicon\.ico|[[:alnum:]]{32}\.png)").unwrap() ];
}


/// Uncompress the input file using simple GzEncoder
fn decode_file(mut file: File) -> io::Result<Vec<u8>> {
    let mut buf = vec![];
    let _ = file.read_to_end(&mut buf);
    let mut deflater = GzDecoder::new(&*buf);
    let mut s = vec![];
    deflater.read_to_end(&mut s)?;
    Ok(s)
}


fn main() {
    let maybe_log =
        File::open("/Users/dmilith/Projects/plog/access.log.gz").and_then(decode_file);
    let maybe_log = maybe_log
        .map(|input_data| {
            let input_data_length = input_data.len();
            let input_data: Vec<u8> = input_data
                .iter()
                .skip(input_data_length - 16384)
                .cloned()
                .collect();
            input_data
        })
        .map(|input_contents| {
            let contents = String::from_utf8_lossy(&input_contents);
            let contents_split = contents.split('\n');
            contents_split
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
            for line in lines {
                match &IP.captures(&line) {
                    Some(ip_match) => {
                        let ip = &ip_match[0];
                        for w_reg in WANTED.iter() {
                            if w_reg.is_match(&line) {
                                println!("Detected normal request: {line} from IPv4: {ip}");
                            }
                        }
                        for w_reg in UNWANTED.iter() {
                            if w_reg.is_match(&line) {
                                println!("Detected malicious request: {line} from IPv4: {ip}");
                                break;
                            }
                        }
                    }
                    None => {
                        eprintln!("Error: No IP match in line: '{line}'");
                    }
                }
            }
        }
        Err(reason) => {
            eprintln!("Error reading the input file because of the: {reason}")
        }
    }
}


/// is_partial returns true when the line doesn't begin with an IP octet:
fn is_partial(line: &str) -> bool {
    !line.starts_with(char::is_numeric)
}


#[test]
fn test_regex_patterns() {
    let r = &IP;
    let ips = ["1.241.215.240", "192.241.215.24", "192.1.21.240", "1.2.1.2"];
    for ip in ips {
        let the_ip = r.captures(ip).unwrap().name("ip").unwrap().as_str();
        assert!(r.is_match(the_ip));
    }
}


#[test]
fn test_regex_match_wanted_and_unwanted() {
    let wanted = [
        r#"185.142.236.35 - - [05/Nov/2021:03:18:44 +0100] "GET /.well-known/security.txt HTTP/1.1" 404 153 "-" "-""#,
        r#"185.142.236.35 - - [05/Nov/2021:03:18:41 +0100] "GET /robots.txt HTTP/1.1" 404 153 "-" "-""#,
        r#"185.142.236.35 - - [05/Nov/2021:03:18:46 +0100] "GET /favicon.ico HTTP/1.1" 404 153 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0""#,
        r#"140.82.115.100 - - [05/Nov/2021:07:03:04 +0100] "GET /52ce884956e2373fb3e4be609d97a5b0.png HTTP/1.1" 301 169 "-" "github-camo (fa497f37)""#,
        r#"18.184.74.47 - - [05/Nov/2021:09:57:41 +0100] "GET //24a477a890163d15b8a66289e6d558a5.png HTTP/1.1" 404 153 "-" "Slack-ImgProxy (+https://api.slack.com/robots)""#,
        /* r#""#,
         * r#""#, */
    ];
    let unwanted = [
        r#"51.75.194.66 - - [08/May/2022:07:36:00 +0200] "GET //mysqladmin/index.php?lang=en HTTP/2.0" 404 548 "http://31.179.184.210/mysqladmin/index.php?lang=en" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36"#,
        r#"51.75.194.66 - - [08/May/2022:07:36:00 +0200] "GET //phpmyAdmin/index.php?lang=en HTTP/2.0" 404 548 "http://31.179.184.210/phpmyAdmin/index.php?lang=en" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36""#,
        r#"192.241.220.215 - - [08/May/2022:06:20:45 +0200] "GET /owa/auth/logon.aspx HTTP/1.1" 404 146 "-" "Mozilla/5.0 zgrab/0.x""#,
        r#"45.227.254.51 - - [07/May/2022:16:04:58 +0200] "\x03\x00\x00,'\xE0\x00\x00\x00\x00\x00Cookie: mstshash=Domain" 400 150 "-" "-""#,
        r#"45.146.164.110 - - [05/Nov/2021:07:45:42 +0100] "GET /index.php?s=/Index/\x5Cthink\x5Capp/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=HelloThinkPHP21 HTTP/1.1" 404 555 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36""#,
        r#"45.146.164.110 - - [05/Nov/2021:07:45:41 +0100] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1" 400 157 "-" "-""#,
        r#"198.199.112.26 - - [05/Nov/2021:01:50:07 +0100] "GET /owa/auth/x.js HTTP/1.1" 404 153 "-" "Mozilla/5.0 zgrab/0.x""#,
        r#"193.169.253.168 - - [05/Nov/2021:03:26:58 +0100] "GET /blog/wp-includes/wlwmanifest.xml HTTP/1.1" 404 555 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36""#,
        r#"193.169.253.168 - - [05/Nov/2021:03:26:56 +0100] "GET /xmlrpc.php?rsd HTTP/1.1" 404 555 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36""#,
        r#"182.122.177.189 - - [05/Nov/2021:04:23:42 +0100] "POST /HNAP1/ HTTP/1.0" 404 153 "-" "-""#,
        r#"193.107.216.49 - - [05/Nov/2021:06:25:44 +0100] "GET //remote/fgt_lang?lang=/../../../..//////////dev/ HTTP/1.1" 404 153 "-" "python-requests/2.26.0""#,
        r#"42.239.251.60 - - [05/Nov/2021:04:30:49 +0100] "GET /boaform/admin/formLogin?username=admin&psd=admin HTTP/1.0" 404 153 "-" "-""#,
        r#"23.228.109.147 - - [05/Nov/2021:06:16:59 +0100] "GET //fileupload/server/php/index.php?file=tf2rghf.jpg HTTP/1.1" 404 153 "-" "ALittle Client""#,
        r#"45.146.164.110 - - [05/Nov/2021:07:45:34 +0100] "POST /Autodiscover/Autodiscover.xml HTTP/1.1" 404 555 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36""#,
        /* r#""#,
         * r#""#,
         * r#""#,
         * r#""#, */
    ];

    for w_reg in WANTED.iter() {
        for this in wanted {
            dbg!(w_reg, this);
            assert!(w_reg.is_match(this));
        }
        for this in unwanted {
            dbg!(w_reg, this);
            assert!(!w_reg.is_match(this));
        }
    }

    for w_reg in UNWANTED.iter() {
        for this in wanted {
            dbg!(w_reg, this);
            assert!(!w_reg.is_match(this));
        }
        for this in unwanted {
            dbg!(w_reg, this);
            assert!(w_reg.is_match(this));
        }
    }
}
