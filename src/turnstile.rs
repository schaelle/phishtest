use crate::{client, TrunstileResponse};
use anyhow::Result;
use std::collections::HashMap;

pub(crate) async fn check(token: &str, secret: &str) ->Result<TrunstileResponse>{
    let mut params = HashMap::new();
    params.insert("secret", secret);
    params.insert("response", token);
    let res = client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .json(&params)
        .send()
        .await?;

    let result: TrunstileResponse = res.json().await?;
    Ok(result)
}