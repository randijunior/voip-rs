#![warn(missing_docs)]
//! Transaction Layer.

use std::time::Duration;

pub use client::ClientTransaction;
pub use manager::TsxModule;
pub use server::ServerTransaction;

use crate::transport::incoming::{IncomingRequest, IncomingResponse};

pub mod client;
pub(crate) mod fsm;
pub(crate) mod manager;
pub mod server;

#[derive(PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub enum Role {
    UAS,
    UAC,
}

/// Estimated round‑trip time (RTT) for message exchanges.
pub(crate) const T1: Duration = Duration::from_millis(500);

/// Maximum retransmission interval for non‑INVITE requests and INVITE responses.
pub(crate) const T2: Duration = Duration::from_secs(4);

/// Maximum duration that a message may remain in the network before being discarded.
pub(crate) const T4: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub enum TransactionMessage {
    Request(IncomingRequest),
    Response(IncomingResponse),
}
