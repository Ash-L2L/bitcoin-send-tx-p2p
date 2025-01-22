use std::borrow::Cow;

pub use crate::async_encode::DecodeErrorErased as DecodeError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(Cow<'static, str>),
    #[error("bitcoin decoding error")]
    BitcoinDecode(#[from] DecodeError),
    #[error("system time error")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("timed out")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[cfg(feature = "tor")]
    #[error("socks5 error")]
    Socks5Error(#[from] tokio_socks::Error),
}

impl<T> From<crate::async_encode::DecodeError<T>> for Error {
    fn from(err: crate::async_encode::DecodeError<T>) -> Self {
        Self::BitcoinDecode(err.into())
    }
}
