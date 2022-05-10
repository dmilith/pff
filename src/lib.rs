#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;


pub mod block;
pub mod config;

pub use tracing::{debug, error, info, instrument, trace, warn};
