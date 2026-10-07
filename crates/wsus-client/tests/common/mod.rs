#![allow(dead_code)]

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::{
    future::Future,
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    pin::pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    thread::{self, JoinHandle, Thread},
    time::Duration,
};
use wsus_client::{
    download::ExpectedFile,
    transport::{
        BodySink, ErrorKind, HttpRequest, HttpResponse, Method, Phase, ResponseHead, Transport,
        TransportError,
    },
};
use wsus_protocol::identity::{DigestAlgorithm, FileDigest};

pub fn block_on<F: Future>(future: F) -> F::Output {
    struct Unpark(Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => thread::park(),
        }
    }
}

pub fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

pub fn expected_for(name: &str, body: &[u8]) -> ExpectedFile {
    ExpectedFile::new(
        name,
        body.len() as u64,
        vec![
            FileDigest {
                algorithm: DigestAlgorithm::Sha1,
                bytes: Sha1::digest(body).to_vec(),
            },
            FileDigest {
                algorithm: DigestAlgorithm::Sha256,
                bytes: Sha256::digest(body).to_vec(),
            },
            FileDigest {
                algorithm: DigestAlgorithm::Sha512,
                bytes: Sha512::digest(body).to_vec(),
            },
        ],
    )
    .expect("valid descriptor")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Behavior {
    Normal,
    IgnoreRange,
    DropAfter(usize),
    Corrupt,
    Oversize,
    BadContentRange,
    Status(u16),
}

#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub range: Option<String>,
    pub body: Vec<u8>,
}

pub struct TestServer {
    pub addr: String,
    script: Arc<Mutex<Vec<Behavior>>>,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl TestServer {
    pub fn start(body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let script: Arc<Mutex<Vec<Behavior>>> = Arc::default();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (s, l, st) = (script.clone(), seen.clone(), stop.clone());
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                if st.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(stream) = stream {
                    let _ = handle(stream, &body, &s, &l);
                }
            }
        });
        Self {
            addr,
            script,
            seen,
            stop,
            handle: Some(handle),
        }
    }

    /// Behaviors consumed one per request; afterwards `Normal`.
    pub fn script(&self, behaviors: Vec<Behavior>) {
        let mut guard = self.script.lock().unwrap();
        *guard = behaviors;
        guard.reverse();
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle(
    mut stream: TcpStream,
    body: &[u8],
    script: &Mutex<Vec<Behavior>>,
    seen: &Mutex<Vec<Seen>>,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_owned();
    let path = first.next().unwrap_or("").to_owned();
    let header = |name: &str| {
        head.lines().skip(1).find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
        })
    };
    let content_length: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut req_body = buf[head_end..].to_vec();
    while req_body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        req_body.extend_from_slice(&tmp[..n]);
    }
    let range = header("range");
    seen.lock().unwrap().push(Seen {
        method: method.clone(),
        path: path.clone(),
        range: range.clone(),
        body: req_body.clone(),
    });
    let behavior = script.lock().unwrap().pop().unwrap_or(Behavior::Normal);

    if method == "POST" {
        let status = if let Behavior::Status(s) = behavior {
            s
        } else {
            200
        };
        let head = format!(
            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nSet-Cookie: session=topsecret\r\nConnection: close\r\n\r\n",
            req_body.len()
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(&req_body)?;
        return stream.shutdown(Shutdown::Both);
    }

    if let Behavior::Status(status) = behavior {
        let head = format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        stream.write_all(head.as_bytes())?;
        return stream.shutdown(Shutdown::Both);
    }

    let total = body.len();
    let mut data = body.to_vec();
    if behavior == Behavior::Corrupt {
        data[total / 2] ^= 0xff;
    }
    let start = if behavior == Behavior::IgnoreRange {
        None
    } else {
        range
            .as_deref()
            .and_then(|r| r.strip_prefix("bytes="))
            .and_then(|r| r.strip_suffix('-'))
            .and_then(|s| s.parse::<usize>().ok())
    };
    let (status, mut payload, extra) = match start {
        Some(s) if s >= total => {
            let head = format!(
                "HTTP/1.1 416 X\r\nContent-Range: bytes */{total}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(head.as_bytes())?;
            return stream.shutdown(Shutdown::Both);
        }
        Some(s) => {
            let shown = if behavior == Behavior::BadContentRange {
                s + 1
            } else {
                s
            };
            (
                206,
                data[s..].to_vec(),
                format!("Content-Range: bytes {shown}-{}/{total}\r\n", total - 1),
            )
        }
        None => (200, data, String::new()),
    };
    if behavior == Behavior::Oversize {
        payload.extend_from_slice(b"EXTRA");
    }
    let head = format!(
        "HTTP/1.1 {status} X\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(head.as_bytes())?;
    if let Behavior::DropAfter(n) = behavior {
        let n = n.min(payload.len());
        stream.write_all(&payload[..n])?;
    } else {
        stream.write_all(&payload)?;
    }
    stream.shutdown(Shutdown::Both)
}

/// Blocking std-socket HTTP/1.1 client (Connection: close) used as a transport.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdTransport;

struct Collect(Vec<u8>, usize);

impl BodySink for Collect {
    fn start(&mut self, _: &ResponseHead) -> io::Result<bool> {
        Ok(true)
    }
    fn write(&mut self, chunk: &[u8]) -> io::Result<()> {
        if self.0.len() + chunk.len() > self.1 {
            return Err(io::Error::other("limit"));
        }
        self.0.extend_from_slice(chunk);
        Ok(())
    }
}

fn connect_and_send(request: &HttpRequest) -> Result<(TcpStream, Vec<u8>), TransportError> {
    let url = request.url.expose();
    let rest = url.strip_prefix("http://").expect("http only in tests");
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_owned()), |(a, p)| (a, format!("/{p}")));
    let mut stream =
        TcpStream::connect(authority).map_err(|e| TransportError::connect(&e.to_string()))?;
    stream
        .set_read_timeout(Some(request.timeout))
        .map_err(|e| TransportError::io(&e.to_string()))?;
    let method = match request.method {
        Method::Get => "GET",
        Method::Post => "POST",
    };
    let mut text =
        format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n");
    for (n, v) in request.headers.iter() {
        text.push_str(&format!("{n}: {v}\r\n"));
    }
    text.push_str(&format!("Content-Length: {}\r\n\r\n", request.body.len()));
    let mut out = text.into_bytes();
    out.extend_from_slice(&request.body);
    stream
        .write_all(&out)
        .map_err(|e| TransportError::io(&e.to_string()))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut tmp)
            .map_err(|e| TransportError::io(&e.to_string()))?;
        if n == 0 {
            return Err(TransportError::io("eof in head"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(p + 4);
            return Ok((stream, [buf, rest].concat()));
        }
    }
}

impl Transport for StdTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let mut sink = Collect(Vec::new(), request.max_response_bytes);
        let head = self.send_streaming(request, &mut sink).await?;
        Ok(HttpResponse {
            status: head.status,
            headers: head.headers,
            body: sink.0,
        })
    }

    async fn send_streaming<'a>(
        &'a self,
        request: HttpRequest,
        sink: &'a mut (dyn BodySink + Send),
    ) -> Result<ResponseHead, TransportError> {
        let (mut stream, buf) = connect_and_send(&request)?;
        let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let text = String::from_utf8_lossy(&buf[..split]).into_owned();
        let mut lines = text.lines();
        let status: u16 = lines
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let mut headers = wsus_client::transport::Headers::new();
        for l in lines {
            if let Some((n, v)) = l.split_once(':') {
                headers.append(n.trim(), v.trim());
            }
        }
        let head = ResponseHead { status, headers };
        let announced: Option<usize> = head
            .headers
            .get("content-length")
            .and_then(|v| v.parse().ok());
        let mut got = 0usize;
        let wants = sink
            .start(&head)
            .map_err(|_| TransportError::new(ErrorKind::Aborted, Phase::MaybeSent, "aborted"))?;
        let mut first = buf[split..].to_vec();
        let mut tmp = vec![0u8; 8192];
        loop {
            if !first.is_empty() {
                got += first.len();
                if wants {
                    sink.write(&first).map_err(|_| TransportError::aborted())?;
                }
                first.clear();
            }
            if wants || announced.is_none_or(|a| got < a) {
                let n = stream
                    .read(&mut tmp)
                    .map_err(|e| TransportError::io(&e.to_string()))?;
                if n == 0 {
                    break;
                }
                first.extend_from_slice(&tmp[..n]);
            } else {
                break;
            }
        }
        if wants && announced.is_some_and(|a| got < a) {
            return Err(TransportError::io("connection closed before full body"));
        }
        Ok(head)
    }
}
