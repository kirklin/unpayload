//! Extracts payloads from a local HTTP server that answers range requests.

#![cfg(feature = "http")]

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tower_http::services::ServeFile;
use unpayload::{Error, ExtractOptions, Payload};

fn data(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(path)
}

/// Serves `router` on a local port in the background, returning its URL.
fn serve(router: Router) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, router).await.unwrap();
        });
    });
    format!("http://{address}")
}

fn file_server(path: PathBuf) -> Router {
    Router::new().route_service("/payload", ServeFile::new(path))
}

/// Counts the requests `router` answers.
fn counted(router: Router) -> (Router, Arc<AtomicUsize>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    let router = router.layer(middleware::from_fn(move |request: Request, next: Next| {
        counter.fetch_add(1, Ordering::Relaxed);
        next.run(request)
    }));
    (router, requests)
}

/// Extracts every partition, which checks it against the hashes in the
/// payload, reading source images from the `old` directory of `source`.
fn extract(payload: &Payload, source: Option<&str>) -> Result<usize, Error> {
    let out = tempfile::tempdir().unwrap();
    let options = ExtractOptions {
        output_dir: out.path().to_owned(),
        source_dir: source.map(|case| data(case).join("old")),
        ..ExtractOptions::default()
    };
    payload.extract(&options, &|_| {}).map(|images| images.len())
}

/// A payload that takes many range requests, with reads both through the
/// block cache and past it.
#[test]
fn payload() {
    let (router, requests) = counted(file_server(data("full/payload.bin")));
    let url = serve(router);
    let payload = Payload::open_url(&format!("{url}/payload")).unwrap();
    let local = Payload::open(data("full/payload.bin")).unwrap();
    assert_eq!(payload.partitions(), local.partitions());
    assert_eq!(extract(&payload, None).unwrap(), 3);
    assert!(requests.load(Ordering::Relaxed) >= 3);
}

#[test]
fn incremental() {
    let url = serve(file_server(data("files/payload.bin")));
    let payload = Payload::open_url(&format!("{url}/payload")).unwrap();
    assert_eq!(extract(&payload, Some("files")).unwrap(), 1);
}

/// An OTA package whose payload starts past the first block read.
#[test]
fn zip_archive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ota.zip");
    let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
    let stored = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("META-INF/padding", stored).unwrap();
    io::Write::write_all(&mut zip, &vec![0x5A; 600 << 10]).unwrap();
    zip.start_file("payload.bin", stored).unwrap();
    io::copy(&mut File::open(data("full/payload.bin")).unwrap(), &mut zip).unwrap();
    zip.finish().unwrap();

    let url = serve(file_server(path));
    let payload = Payload::open_url(&format!("{url}/payload")).unwrap();
    assert_eq!(extract(&payload, None).unwrap(), 3);
}

#[test]
fn server_without_range_requests() {
    let bytes = std::fs::read(data("full/payload.bin")).unwrap();
    let url = serve(Router::new().route("/payload", get(move || async move { bytes })));
    let error = Payload::open_url(&format!("{url}/payload")).err().unwrap();
    assert!(
        matches!(&error, Error::Http(message) if message.contains("does not support range requests")),
        "{error:?}"
    );
}

/// A server whose file changes after the first request.
#[test]
fn file_changing_while_reading() {
    let requests = Arc::new(AtomicUsize::new(0));
    let retag = move |mut response: Response| {
        let first = requests.fetch_add(1, Ordering::Relaxed) == 0;
        async move {
            let tag = if first { "\"one\"" } else { "\"two\"" };
            let headers = response.headers_mut();
            headers.insert(header::ETAG, HeaderValue::from_static(tag));
            response
        }
    };
    let url = serve(file_server(data("full/payload.bin")).layer(middleware::map_response(retag)));
    // Opening reads the header and the manifest from the first response.
    let payload = Payload::open_url(&format!("{url}/payload")).unwrap();
    let out = tempfile::tempdir().unwrap();
    let options = ExtractOptions {
        output_dir: out.path().to_owned(),
        ..ExtractOptions::default()
    };
    let error = payload.extract(&options, &|_| {}).unwrap_err();
    assert!(
        format!("{error:?}").contains("the file changed on the server"),
        "{error:?}"
    );
}

/// A server that fails its first two requests, which are retried after one
/// and two seconds.
#[test]
fn transient_failures() {
    let requests = Arc::new(AtomicUsize::new(0));
    let fail_twice = move |request: Request, next: Next| {
        let failing = requests.fetch_add(1, Ordering::Relaxed) < 2;
        async move {
            if failing {
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            } else {
                next.run(request).await
            }
        }
    };
    let url = serve(file_server(data("delta/payload.bin")).layer(middleware::from_fn(fail_twice)));
    let started = Instant::now();
    let payload = Payload::open_url(&format!("{url}/payload")).unwrap();
    assert!(started.elapsed().as_secs() >= 3);
    assert_eq!(extract(&payload, Some("delta")).unwrap(), 1);
}
