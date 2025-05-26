use serde_derive::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub age: i64,
    pub body: Body,
    #[serde(rename = "type")]
    pub type_field: String,
    pub url: String,
    #[serde(rename = "user_agent")]
    pub user_agent: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Body {
    #[serde(rename = "blockedURL")]
    pub blocked_url: String,
    pub column_number: i64,
    pub disposition: String,
    #[serde(rename = "documentURL")]
    pub document_url: String,
    pub effective_directive: String,
    pub line_number: i64,
    pub original_policy: String,
    pub referrer: String,
    pub sample: String,
    pub source_file: String,
    pub status_code: i64,
}
