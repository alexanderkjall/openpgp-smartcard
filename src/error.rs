#[derive(Debug)]
pub enum Error {
    Generic(&'static str),
    GenericDyn(String),
}

impl From<&str> for Error {
    fn from(err: &str) -> Error {
        Error::GenericDyn(err.to_string())
    }
}
