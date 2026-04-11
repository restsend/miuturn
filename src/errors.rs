use std::net::SocketAddr;

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Protocol(String),
    NotFound,
    AlreadyExists,
    InvalidChannel,
    NoAllocation,
    AllocationFailed,
    AllocationQuotaReached,
    RelayPortExhausted,
    RelayBindFailed { addr: SocketAddr, source: String },
    BandwidthLimitExceeded,
    Encode(&'static str),
    Decode(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Protocol(s) => write!(f, "Protocol error: {}", s),
            Error::NotFound => write!(f, "Not found"),
            Error::AlreadyExists => write!(f, "Already exists"),
            Error::InvalidChannel => write!(f, "Invalid channel"),
            Error::NoAllocation => write!(f, "No allocation"),
            Error::AllocationFailed => write!(f, "Allocation failed"),
            Error::AllocationQuotaReached => write!(f, "Allocation quota reached"),
            Error::RelayPortExhausted => write!(f, "No relay ports available"),
            Error::RelayBindFailed { addr, source } => {
                write!(f, "Failed to bind relay socket on {}: {}", addr, source)
            }
            Error::BandwidthLimitExceeded => write!(f, "Bandwidth limit exceeded"),
            Error::Encode(s) => write!(f, "Encode error: {}", s),
            Error::Decode(s) => write!(f, "Decode error: {}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
