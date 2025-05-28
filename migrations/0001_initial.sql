CREATE TABLE IF NOT EXISTS requests
(
    id                     CHARACTER(26) PRIMARY KEY NOT NULL,
    session_id             CHARACTER(26)             NOT NULL,
    url                    TEXT                      NOT NULL,
    method                 VARCHAR(10)               NOT NULL,
    timestamp              DATETIME                  NOT NULL,
    origin_request_header  BLOB,
    origin_request_body    BLOB,
    request_header         BLOB,
    request_body           BLOB,
    origin_response_header BLOB,
    origin_response_body   BLOB,
    response_header        BLOB,
    response_body          BLOB,
    status_code            INT
);