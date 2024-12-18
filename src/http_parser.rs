use crate::http;

pub fn parse_http_request(payload: &[u8]) -> Option<ObservableHttpRequest> {
    if let Ok(payload_str) = std::str::from_utf8(payload) {
        let http_methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT"];
        if !http_methods.iter().any(|method| payload_str.starts_with(method)) {
            return None;
        }

        let mut headers = payload_str.lines();

        let mut user_agent: Option<String> = None;
        let mut lang: Option<String> = None;
        let mut raw_headers = vec![];

        for line in headers {
            if line.is_empty() {
                break;
            }
            raw_headers.push(line.to_string());

            if line.to_lowercase().starts_with("user-agent:") {
                user_agent = Some(line.split_once(":").unwrap().1.trim().to_string());
            }

            if line.to_lowercase().starts_with("accept-language:") {
                lang = Some(line.split_once(":").unwrap().1.trim().to_string());
            }
        }

        //TODO: create http::Signature
        let signature: http::Signature = ???
        return Some(ObservableHttpRequest {
            lang,
            user_agent,
            signature,
        });
    }
    None
}

pub struct ObservableHttpRequest {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub signature: http::Signature,
}
