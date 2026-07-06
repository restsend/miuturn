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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::SocketAddr;

    #[test]
    fn test_display_io_error() {
        let err = Error::Io(io::Error::new(io::ErrorKind::NotFound, "missing"));
        let s = format!("{}", err);
        assert!(s.starts_with("IO error:"));
        assert!(s.contains("missing"));
    }

    #[test]
    fn test_display_protocol_error() {
        let err = Error::Protocol("bad message".to_string());
        assert_eq!(format!("{}", err), "Protocol error: bad message");
    }

    #[test]
    fn test_display_simple_variants() {
        assert_eq!(format!("{}", Error::NotFound), "Not found");
        assert_eq!(format!("{}", Error::AlreadyExists), "Already exists");
        assert_eq!(format!("{}", Error::InvalidChannel), "Invalid channel");
        assert_eq!(format!("{}", Error::NoAllocation), "No allocation");
        assert_eq!(format!("{}", Error::AllocationFailed), "Allocation failed");
        assert_eq!(
            format!("{}", Error::AllocationQuotaReached),
            "Allocation quota reached"
        );
        assert_eq!(
            format!("{}", Error::RelayPortExhausted),
            "No relay ports available"
        );
        assert_eq!(
            format!("{}", Error::BandwidthLimitExceeded),
            "Bandwidth limit exceeded"
        );
    }

    #[test]
    fn test_display_relay_bind_failed() {
        let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let err = Error::RelayBindFailed {
            addr,
            source: "addr in use".to_string(),
        };
        let s = format!("{}", err);
        assert!(s.contains("10.0.0.1:5000"));
        assert!(s.contains("addr in use"));
    }

    #[test]
    fn test_display_encode_decode() {
        assert_eq!(
            format!("{}", Error::Encode("stun header")),
            "Encode error: stun header"
        );
        assert_eq!(
            format!("{}", Error::Decode("attr length")),
            "Decode error: attr length"
        );
    }

    #[test]
    fn test_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn test_error_is_std_error() {
        fn assert_error<T: std::error::Error>(_e: &T) {}
        let err = Error::Protocol("x".to_string());
        assert_error(&err);
    }

    #[test]
    fn test_error_source_is_none() {
        // Our Error has no wrapped source beyond what Display shows
        let err = Error::NotFound;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn test_debug_format_includes_variant() {
        let err = Error::BandwidthLimitExceeded;
        let dbg = format!("{:?}", err);
        assert!(dbg.contains("BandwidthLimitExceeded"));
    }
}
