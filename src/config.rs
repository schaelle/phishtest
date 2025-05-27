use serde_derive::Deserialize;
use serde_inline_default::serde_inline_default;
use std::fs;
use std::path::Path;

#[serde_inline_default]
#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
pub struct Config {
    #[serde_inline_default("0.0.0.0".to_string())]
    pub bind: String,

    #[serde_inline_default(53001_u16)]
    pub port: u16,
    pub turnstile: TurnstileConfig,

    pub targets: Option<Vec<Targets>>,
    
    pub domains: Vec<String>
}

#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
struct TurnstileConfig {
    secret: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
pub(crate) struct Targets {
    pub url: Vec<String>,
    pub request: Option<Mapping>,
    pub response: Option<Mapping>,
    pub static_response: Option<StaticResponse>,
}

#[serde_inline_default]
#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
pub(crate)  struct Mapping {
    pub headers: Option<Vec<Header>>,

    #[serde_inline_default(false)]
    pub rewrite: bool,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
pub(crate) struct StaticResponse {
    pub status: u16,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
pub(crate) struct Header {
    pub key: String,
    pub value: Option<String>,
}

pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Config> {
    let content = fs::read_to_string(path)?;
    let res = toml::from_str(&content)?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::config::{Config, Header, Mapping, StaticResponse, Targets, TurnstileConfig, load};

    #[test]
    fn test() {
        let config = load("test_config.toml").unwrap();

        let expected = Config {
            bind: "0.0.0.0".to_string(),
            port: 53001,
            turnstile: TurnstileConfig {
                secret: "turnstile1".to_string(),
            },
            domains: vec!["domain1".to_string()],
            targets: Some(vec![
                Targets {
                    url: vec!["path1/.*".to_string()],
                    request: None,
                    response: None,
                    static_response: Some(StaticResponse { status: 404 }),
                },
                Targets {
                    url: vec!["path1/.*".to_string(), "path2/.*".to_string()],
                    request: None,
                    response: None,
                    static_response: Some(StaticResponse { status: 202 }),
                },
                Targets {
                    url: vec![".*".to_string()],
                    request: Some(Mapping {
                        headers: None,
                        rewrite: true,
                    }),
                    response: Some(Mapping {
                        headers: Some(vec![Header {
                            key: "Referrer-Policy".to_string(),
                            value: Some("same-origin".to_string()),
                        }]),
                        rewrite: true,
                    }),
                    static_response: None,
                },
                Targets {
                    url: vec!["url2".to_string()],
                    request: None,
                    response: Some(Mapping {
                        headers: Some(vec![Header {
                            key: "header2".to_string(),
                            value: Some("value2".to_string()),
                        }]),
                        rewrite: false,
                    }),
                    static_response: None,
                },
            ]),
        };

        assert_eq!(expected, config);
    }
}
