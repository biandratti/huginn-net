use std::fmt;

#[derive(Debug)]
pub struct TcpPackage {
    pub client: String,
    pub os: Option<String>,
    pub dist: i64,
    pub params: String,
    pub raw_sig: String,
}

impl fmt::Display for TcpPackage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            ".-[ {} (syn) ]-\n\
            |\n\
            | client   = {}\n\
            | os       = {}\n\
            | dist     = {}\n\
            | params   = {}\n\
            | raw_sig  = {}\n",
            self.client,
            self.client,
            self.os.as_deref().unwrap_or("Unknown"),
            self.dist,
            self.params,
            self.raw_sig
        )
    }
}
