use std::io::Read;
use axum::http::HeaderMap;
use bytes::Bytes;
use sqlx::SqlitePool;
use std::time::Instant;
use ulid::Ulid;
use uuid::Uuid;

pub(crate) async fn add_request(
    pool: &SqlitePool,
    session_id: Ulid,
    url: &str,
    method: &str,
    origin_request_header: &HeaderMap,
    origin_body: Vec<u8>,
    body: Vec<u8>,
) {
    let id = Ulid::new().to_string();
    let now = sqlx::types::chrono::Utc::now();
    let session_id = session_id.to_string();

    let origin_request_header = origin_request_header;

    sqlx::query!("INSERT INTO requests (id, session_id, method, timestamp, url, origin_request_header, origin_request_body, request_header, request_body, origin_response_header, origin_response_body, response_header, response_body, status_code) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        id,
        session_id,
        method,
        now,
        url,
        "",
        "",
        "",
        origin_body,
        body,
        "",
        "",
        "",
        ""
    ).execute(pool).await.unwrap();
}
