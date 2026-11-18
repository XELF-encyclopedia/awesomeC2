//! C2V2 agent library: crypto, wire protocol, transports and modules.

pub mod config;
pub mod crypto;
pub mod wire;
pub mod transport;
pub mod session;
pub mod platform;
pub mod modules;
pub mod persist;

pub const VERSION: &str = "2.0.0";
