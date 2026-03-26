use std::sync::Arc;

use keychat_uniffi::{ClientEvent, DataChange, KeychatClient};
use tokio::sync::broadcast;

fn temp_db(dir: &tempfile::TempDir, name: &str) -> String {
    dir.path().join(name).to_str().unwrap().to_string()
}

/// KeychatClient embeds its own tokio Runtime. Dropping a Runtime inside
/// another Runtime's `block_on` panics. To work around this, each test
/// runs on a dedicated OS thread and explicitly drops the client before
/// the outer Runtime is dropped.
macro_rules! async_test {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            std::thread::spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async { $body });
            })
            .join()
            .unwrap();
        }
    };
}

// ─── Client Creation ────────────────────────────────────────────

async_test!(test_cli_creates_client, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");

    let client = KeychatClient::new(db_path, "test-key-cli".into()).unwrap();

    // Client should be usable — get_pubkey_hex should fail (no identity yet)
    // but should not panic
    let result = client.get_pubkey_hex().await;
    assert!(result.is_err(), "no identity yet, should error");

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

// ─── Identity Creation ──────────────────────────────────────────

async_test!(test_create_and_get_identity, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "identity.db");

    let client = KeychatClient::new(db_path, "test-key-cli".into()).unwrap();

    let result = client.create_identity().await.unwrap();
    assert!(!result.pubkey_hex.is_empty(), "pubkey should not be empty");
    assert!(!result.mnemonic.is_empty(), "mnemonic should not be empty");

    let pubkey = client.get_pubkey_hex().await.unwrap();
    assert_eq!(pubkey, result.pubkey_hex, "get_pubkey_hex should return created key");

    // pubkey should be valid hex
    assert_eq!(pubkey.len(), 64, "pubkey should be 64 hex chars");
    assert!(
        pubkey.chars().all(|c| c.is_ascii_hexdigit()),
        "pubkey should be valid hex"
    );

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

// ─── Daemon Route Tests ─────────────────────────────────────────

async_test!(test_daemon_status_route, {
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "daemon.db");
    let client = Arc::new(KeychatClient::new(db_path, "test-key-cli".into()).unwrap());

    let (event_tx, _) = broadcast::channel::<ClientEvent>(16);
    let (data_tx, _) = broadcast::channel::<DataChange>(16);

    let app = keychat_cli::daemon::build_router(client.clone(), event_tx, data_tx);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    // Parse the JSON body
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ok"], true);
    // No identity created, so connection should be "no_identity"
    assert_eq!(json["data"]["connection"], "no_identity");
    assert!(json["data"]["identity"].is_null());

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(test_daemon_identity_route_no_identity, {
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "daemon2.db");
    let client = Arc::new(KeychatClient::new(db_path, "test-key-cli".into()).unwrap());

    let (event_tx, _) = broadcast::channel::<ClientEvent>(16);
    let (data_tx, _) = broadcast::channel::<DataChange>(16);

    let app = keychat_cli::daemon::build_router(client.clone(), event_tx, data_tx);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/identity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return 404 when no identity exists
    assert_eq!(response.status(), 404);

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(test_daemon_create_identity_route, {
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "daemon3.db");
    let client = Arc::new(KeychatClient::new(db_path, "test-key-cli".into()).unwrap());

    let (event_tx, _) = broadcast::channel::<ClientEvent>(16);
    let (data_tx, _) = broadcast::channel::<DataChange>(16);

    let app = keychat_cli::daemon::build_router(client.clone(), event_tx, data_tx);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/identity/create")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ok"], true);
    assert!(!json["data"]["pubkey_hex"].as_str().unwrap().is_empty());
    assert!(!json["data"]["mnemonic"].as_str().unwrap().is_empty());

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(test_daemon_rooms_route_empty, {
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "daemon4.db");
    let client = Arc::new(KeychatClient::new(db_path, "test-key-cli".into()).unwrap());

    let (event_tx, _) = broadcast::channel::<ClientEvent>(16);
    let (data_tx, _) = broadcast::channel::<DataChange>(16);

    let app = keychat_cli::daemon::build_router(client.clone(), event_tx, data_tx);

    // Create identity first so rooms query works
    client.create_identity().await.unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/rooms")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ok"], true);
    assert!(json["data"].as_array().unwrap().is_empty());

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});
