use crate::http_common::{HttpCookie, HttpHeader};
use huginn_net_db::observable_signals::{HttpRequestObservation, HttpResponseObservation};

#[derive(Debug, Clone)]
pub struct ObservableHttpRequest {
    pub matching: HttpRequestObservation,
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub headers: Vec<HttpHeader>,
    pub cookies: Vec<HttpCookie>,
    pub referer: Option<String>,
    pub method: Option<String>,
    pub uri: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObservableHttpResponse {
    pub matching: HttpResponseObservation,
    pub headers: Vec<HttpHeader>,
    pub status_code: Option<u16>,
}
