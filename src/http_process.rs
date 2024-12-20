use crate::http;
use failure::Error;
use pnet::packet::ipv4::Ipv4Packet;

pub fn process_http_ipv4(_packet: &Ipv4Packet) -> Result<ObservableHttpPackage, Error> {
    Ok(ObservableHttpPackage { http_request: None })
}

pub struct ObservableHttpPackage {
    http_request: Option<ObservableHttpRequest>,
}

pub struct ObservableHttpRequest {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub signature: http::Signature,
}
