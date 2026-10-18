//! Payloads served over HTTP(S), read with range requests.
//!
//! Small reads go through a cache of aligned blocks so that parsing the zip
//! directory and payload header takes a handful of requests. Large reads, such
//! as operation data, are fetched directly.

use std::collections::VecDeque;
use std::io::{self, Read};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ureq::Agent;
use ureq::http::{HeaderMap, StatusCode, header};

use crate::error::{Error, Result};
use crate::input::ReadAt;

const BLOCK: u64 = 256 * 1024;
const CACHED_BLOCKS: usize = 32;
const ATTEMPTS: u32 = 6;

pub struct HttpFile {
    agent: Agent,
    url: String,
    size: u64,
    validator: Option<String>,
    cache: Mutex<VecDeque<(u64, Arc<Vec<u8>>)>>,
}

enum Failure {
    Transient(String),
    Permanent(String),
}

struct Part {
    data: Vec<u8>,
    total: u64,
    validator: Option<String>,
}

impl HttpFile {
    pub fn open(url: &str) -> Result<Self> {
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .user_agent(concat!("unpayload/", env!("CARGO_PKG_VERSION")))
            .max_idle_connections(64)
            .max_idle_connections_per_host(64)
            .timeout_connect(Some(Duration::from_secs(30)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .timeout_recv_body(Some(Duration::from_secs(600)))
            .build()
            .into();
        let first = with_retries(|| get_range(&agent, url, 0, BLOCK, None))
            .map_err(|message| Error::Http(format!("{url}: {message}")))?;
        let size = first.total;
        let mut cache = VecDeque::with_capacity(CACHED_BLOCKS);
        cache.push_back((0, Arc::new(first.data)));
        Ok(Self {
            agent,
            url: url.to_owned(),
            size,
            validator: first.validator,
            cache: Mutex::new(cache),
        })
    }

    fn fetch(&self, start: u64, end: u64) -> io::Result<Vec<u8>> {
        with_retries(|| get_range(&self.agent, &self.url, start, end, self.validator.as_deref()))
            .map(|part| part.data)
            .map_err(|message| io::Error::other(format!("{}: {message}", self.url)))
    }

    fn block(&self, index: u64) -> io::Result<Arc<Vec<u8>>> {
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(pos) = cache.iter().position(|(i, _)| *i == index) {
                let entry = cache.remove(pos).unwrap();
                let block = entry.1.clone();
                cache.push_back(entry);
                return Ok(block);
            }
        }
        let start = index * BLOCK;
        let block = Arc::new(self.fetch(start, (start + BLOCK).min(self.size))?);
        let mut cache = self.cache.lock().unwrap();
        if cache.len() == CACHED_BLOCKS {
            cache.pop_front();
        }
        cache.push_back((index, block.clone()));
        Ok(block)
    }
}

impl ReadAt for HttpFile {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .filter(|&end| end <= self.size)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        if buf.is_empty() {
            return Ok(());
        }
        if buf.len() as u64 >= 2 * BLOCK {
            buf.copy_from_slice(&self.fetch(offset, end)?);
            return Ok(());
        }
        let mut done = 0;
        while done < buf.len() {
            let position = offset + done as u64;
            let block = self.block(position / BLOCK)?;
            let within = (position % BLOCK) as usize;
            let n = (block.len() - within).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&block[within..within + n]);
            done += n;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn read_granularity(&self) -> u64 {
        8 << 20
    }
}

fn with_retries<T>(mut attempt: impl FnMut() -> Result<T, Failure>) -> Result<T, String> {
    let mut delay = Duration::from_secs(1);
    for remaining in (0..ATTEMPTS).rev() {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(Failure::Permanent(message)) => return Err(message),
            Err(Failure::Transient(message)) if remaining == 0 => return Err(message),
            Err(Failure::Transient(_)) => {
                thread::sleep(delay);
                delay *= 2;
            }
        }
    }
    unreachable!("the last attempt always returns")
}

/// Fetches bytes `start..end`. The first request passes no `validator` and
/// may be served fewer bytes than asked when the file is smaller than `end`.
fn get_range(agent: &Agent, url: &str, start: u64, end: u64, validator: Option<&str>) -> Result<Part, Failure> {
    let mut response = agent
        .get(url)
        .header(header::RANGE, format!("bytes={}-{}", start, end - 1))
        .call()
        .map_err(classify)?;
    let status = response.status();
    if status != StatusCode::PARTIAL_CONTENT {
        let message = match status {
            StatusCode::OK => "the server does not support range requests".to_owned(),
            _ => format!("HTTP {status}"),
        };
        let transient = status.is_server_error()
            || status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::REQUEST_TIMEOUT;
        return Err(if transient {
            Failure::Transient(message)
        } else {
            Failure::Permanent(message)
        });
    }
    let headers = response.headers();
    let (first, last, total) = headers
        .get(header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_content_range)
        .ok_or_else(|| Failure::Permanent("malformed Content-Range header".to_owned()))?;
    let served_whole_request = last + 1 == end || (validator.is_none() && last + 1 == total);
    if first != start || last >= end || !served_whole_request {
        return Err(Failure::Permanent(format!(
            "asked for bytes {start}-{}, server sent {first}-{last}",
            end - 1
        )));
    }
    let current = validator_of(headers);
    if let (Some(expected), Some(actual)) = (validator, current.as_deref())
        && expected != actual
    {
        return Err(Failure::Permanent(
            "the file changed on the server while reading it".to_owned(),
        ));
    }
    // The checks above bound the length by the request. Reading on to the end
    // of the body returns the connection to the pool.
    let mut data = vec![0u8; (last + 1 - first) as usize];
    let mut body = response.body_mut().as_reader();
    let io_failure = |error: io::Error| classify(error.into());
    body.read_exact(&mut data).map_err(io_failure)?;
    if body.read(&mut [0u8; 1]).map_err(io_failure)? != 0 {
        return Err(Failure::Permanent(
            "the server sent more bytes than its Content-Range says".to_owned(),
        ));
    }
    Ok(Part {
        data,
        total,
        validator: current,
    })
}

/// Parses `bytes first-last/total`.
fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let (range, total) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (first, last) = range.split_once('-')?;
    let (first, last, total) = (first.parse().ok()?, last.parse().ok()?, total.parse().ok()?);
    (first <= last && last < total).then_some((first, last, total))
}

fn validator_of(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::ETAG)
        .or_else(|| headers.get(header::LAST_MODIFIED))
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn classify(error: ureq::Error) -> Failure {
    match error {
        ureq::Error::Io(_)
        | ureq::Error::Timeout(_)
        | ureq::Error::ConnectionFailed
        | ureq::Error::HostNotFound
        | ureq::Error::Protocol(_) => Failure::Transient(error.to_string()),
        _ => Failure::Permanent(error.to_string()),
    }
}
