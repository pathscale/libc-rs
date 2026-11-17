//! Typed status codes and result helpers for unikernel capability calls.

use core::fmt;

/// Typed status codes returned by unikernel capability calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(i64)]
pub enum Status {
    /// Operation cannot complete immediately without blocking.
    WouldBlock = -1,
    /// Target channel or resource is closed.
    Closed = -2,
    /// Caller supplied an invalid argument or state.
    Invalid = -3,
    /// Caller lacks permission for the requested operation.
    Denied = -4,
    /// Requested capability or resource is unavailable.
    Unavailable = -5,
    /// Operation failed due to an internal or hardware error.
    Failed = -6,
    /// Kernel or peer violated the expected ABI protocol.
    Protocol = -7,
    /// Operation exceeded its deadline.
    TimedOut = -8,
}

impl Status {
    /// Decodes a raw negative status code into a [`Status`].
    #[must_use]
    pub const fn decode(raw: i64) -> Self {
        match raw {
            -1 => Self::WouldBlock,
            -2 => Self::Closed,
            -3 => Self::Invalid,
            -4 => Self::Denied,
            -5 => Self::Unavailable,
            -6 => Self::Failed,
            -8 => Self::TimedOut,
            _ => Self::Protocol,
        }
    }

    /// Returns the raw `i64` representation of this status code.
    #[must_use]
    pub const fn code(self) -> i64 {
        self as i64
    }

    /// Returns a static human-readable description of this status code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WouldBlock => "would block",
            Self::Closed => "closed",
            Self::Invalid => "invalid",
            Self::Denied => "denied",
            Self::Unavailable => "unavailable",
            Self::Failed => "failed",
            Self::Protocol => "protocol error",
            Self::TimedOut => "timed out",
        }
    }

    /// Returns `true` if retrying the operation may succeed.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::WouldBlock | Self::TimedOut)
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::error::Error for Status {}

/// Result type for unikernel capability operations.
pub type Result<T> = core::result::Result<T, Status>;

/// Decodes a raw `u64` trap return value into a [`Result<u64>`].
///
/// Negative values (when interpreted as `i64`) map to `Err(Status::decode(...))`.
pub const fn decode_result(raw: u64) -> Result<u64> {
    let signed = raw as i64;
    if signed < 0 {
        Err(Status::decode(signed))
    } else {
        Ok(raw)
    }
}

/// Validates that a trap return value is zero, returning [`Status::Protocol`] otherwise.
pub const fn expect_zero(value: u64) -> Result<()> {
    match value {
        0 => Ok(()),
        _ => Err(Status::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_all_known_and_unknown_codes() {
        assert_eq!(Status::decode(-1), Status::WouldBlock);
        assert_eq!(Status::decode(-2), Status::Closed);
        assert_eq!(Status::decode(-3), Status::Invalid);
        assert_eq!(Status::decode(-4), Status::Denied);
        assert_eq!(Status::decode(-5), Status::Unavailable);
        assert_eq!(Status::decode(-6), Status::Failed);
        assert_eq!(Status::decode(-7), Status::Protocol);
        assert_eq!(Status::decode(-8), Status::TimedOut);
        assert_eq!(Status::decode(-99), Status::Protocol);
        assert_eq!(Status::decode(0), Status::Protocol);
    }

    #[test]
    fn decode_result_handles_non_negative_and_negative() {
        assert_eq!(decode_result(0), Ok(0));
        assert_eq!(decode_result(42), Ok(42));
        assert_eq!(decode_result(i64::MAX as u64), Ok(i64::MAX as u64));
        assert_eq!(decode_result((-1i64) as u64), Err(Status::WouldBlock));
        assert_eq!(decode_result((-8i64) as u64), Err(Status::TimedOut));
        assert_eq!(decode_result((-42i64) as u64), Err(Status::Protocol));
    }

    #[test]
    fn expect_zero_checks_exact_zero() {
        assert_eq!(expect_zero(0), Ok(()));
        assert_eq!(expect_zero(1), Err(Status::Protocol));
        assert_eq!(expect_zero(u64::MAX), Err(Status::Protocol));
    }

    #[test]
    fn display_and_retryable() {
        assert!(Status::WouldBlock.is_retryable());
        assert!(Status::TimedOut.is_retryable());
        assert!(!Status::Closed.is_retryable());
        assert!(!Status::Invalid.is_retryable());
        assert_eq!(Status::Denied.code(), -4);
        assert_eq!(Status::Unavailable.as_str(), "unavailable");
    }
}
