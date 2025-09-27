use crate::http_common::{HttpCookie, HttpHeader};
use huginn_net_db::observable_signals::{
    HttpRequestObservation, HttpResponseObservation, TcpObservation,
};

// Observable TCP signals
#[derive(Debug, Clone)]
pub struct ObservableTcp {
    /// Core matching data for fingerprinting
    pub matching: TcpObservation,
    // Additional fields for extended analysis could go here in the future
}

// Observable HTTP signals
#[derive(Debug, Clone)]
pub struct ObservableHttpRequest {
    /// Core matching data for fingerprinting
    pub matching: HttpRequestObservation,
    /// Additional analysis fields
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    /// All parsed HTTP headers with original order, position, and source information
    pub headers: Vec<HttpHeader>,
    /// All parsed HTTP cookies with names, values, and positions
    pub cookies: Vec<HttpCookie>,
    /// Referer header value
    pub referer: Option<String>,
    /// HTTP method (GET, POST, PUT, etc.)
    pub method: Option<String>,
    /// Request URI/path
    pub uri: Option<String>,
}

// Observable HTTP response signals
#[derive(Debug, Clone)]
pub struct ObservableHttpResponse {
    /// Core matching data for fingerprinting
    pub matching: HttpResponseObservation,
    /// Additional analysis fields
    /// All parsed HTTP headers with original order, position, and source information
    pub headers: Vec<HttpHeader>,
    /// HTTP status code
    pub status_code: Option<u16>,
}

// Observable MTU signals
pub struct ObservableMtu {
    pub value: u16,
}

// Observable Uptime signals
pub struct ObservableUptime {
    pub days: u32,
    pub hours: u32,
    pub min: u32,
    pub up_mod_days: u32,
    pub freq: f64,
}
