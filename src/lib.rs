#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;


pub mod block;
pub mod config;


use crate::config::Config;
use lazy_static::lazy_static;
use regex::Regex;

pub use tracing::{debug, error, info, instrument, trace, warn};


lazy_static! {
    pub static ref IP: Regex = Regex::new(r"^(?P<ip>((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d))").unwrap();

    /// WANTED have higher priority over UNWANTED
    pub static ref WANTED: Regex = Config::wanted();
    pub static ref UNWANTED: Regex = Config::unwanted();

}


#[cfg(test)]
mod tests;
