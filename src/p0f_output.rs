use crate::tcp::Signature;
use std::fmt;

pub struct P0fOutput {
    pub client: String,
    pub os: Option<String>,
    pub raw_sig: Signature,
}

impl fmt::Display for P0fOutput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            ".-[ {} (syn) ]-\n\
            |\n\
            | os       = {}\n\
            | raw_sig  = {}\n",
            self.client,
            self.os.as_deref().unwrap_or("Unknown"),
            self.raw_sig,
        )
    }
}
