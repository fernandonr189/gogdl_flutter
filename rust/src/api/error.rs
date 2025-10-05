use std::{
    error::Error,
    fmt::{self, Display},
};

#[derive(Debug)]
pub enum AuthError {
    Network(String),
    Io(String),
    UrlError(String),
    InvalidResponse(String),
    Auth(String),
}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        match self {
            AuthError::Network(str) => write!(f, "{}", str),
            AuthError::Io(str) => write!(f, "{}", str),
            AuthError::UrlError(str) => write!(f, "{}", str),
            AuthError::InvalidResponse(str) => write!(f, "{}", str),
            AuthError::Auth(str) => write!(f, "Response failed with status: {}", str),
        }
    }
}

impl Error for AuthError {}

#[derive(Debug)]
pub enum DownloaderError {
    GetLatestBuildError(String),
    MissingManifestUrl,
    RequestError(String),
}

impl Display for DownloaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        match self {
            DownloaderError::GetLatestBuildError(str) => write!(f, "{}", str),
            DownloaderError::MissingManifestUrl => write!(f, "Missing manifest URL"),
        }
    }
}

impl Error for DownloaderError {}
