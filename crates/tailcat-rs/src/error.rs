#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid tailcat address: {0}")]
    Addr(String),

    #[error("derp map: {0}")]
    DerpMap(String),

    #[error("derp: {0}")]
    Derp(String),

    #[error("{0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("server closed")]
    Closed,
}

pub type Result<T> = std::result::Result<T, Error>;
