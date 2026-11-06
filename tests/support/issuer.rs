use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

pub(super) struct Mock {
    pub task: tokio::task::JoinHandle<()>,
    pub entered: oneshot::Receiver<()>,
}

pub(super) struct Reply {
    pub path: &'static str,
    pub status: u16,
    pub body: String,
    pub headers: String,
    pub hold: bool,
}

impl Reply {
    pub fn new(
        path: &'static str,
        status: u16,
        body: impl Into<String>,
    ) -> Self {
        Self {
            path,
            status,
            body: body.into(),
            headers: String::new(),
            hold: false,
        }
    }

    pub fn nonce() -> Self {
        let mut reply = Self::new("/acme/new-nonce", 204, "");
        reply.headers = "Replay-Nonce: test-nonce\r\n".into();
        reply
    }
}

pub(super) async fn start(
    token: &str,
    hold_challenge: bool,
) -> (reqwest::Client, Mock) {
    let mut order = Reply::new(
        "/acme/new-order",
        201,
        r#"{"authorizations":["http://issuer.test/auth"],"finalize":"http://issuer.test/finalize"}"#,
    );
    order.headers = "Location: http://issuer.test/order\r\n".into();
    let auth = Reply::new("/auth", 200, serde_json::json!({"status":"pending", "challenges":[{"type":"http-01", "token":token, "url":"http://issuer.test/challenge"}]}).to_string());
    let mut challenge =
        Reply::new("/challenge", 200, r#"{"status":"invalid"}"#);
    challenge.hold = hold_challenge;
    scripted(vec![
        Reply::nonce(),
        order,
        Reply::nonce(),
        auth,
        Reply::nonce(),
        challenge,
        Reply::nonce(),
        Reply::new("/challenge", 200, r#"{"status":"invalid"}"#),
    ])
    .await
}

pub(super) async fn scripted(replies: Vec<Reply>) -> (reqwest::Client, Mock) {
    let listener =
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    // A local explicit HTTP proxy preserves the public account URL contract
    // without requiring port 80 or involving DNS or a real certificate issuer.
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{address}")).unwrap())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    serve(listener, client, replies)
}

pub(super) fn direct(
    listener: TcpListener,
    replies: Vec<Reply>,
) -> (reqwest::Client, Mock) {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    serve(listener, client, replies)
}

fn serve(
    listener: TcpListener,
    client: reqwest::Client,
    replies: Vec<Reply>,
) -> (reqwest::Client, Mock) {
    let (entered, receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let base = url::Url::parse("http://issuer.test").unwrap();
        let mut entered = Some(entered);
        for reply in replies {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut wire = Vec::new();
            let mut buffer = [0; 1024];
            let head = loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "unexpected EOF before mock request head");
                wire.extend_from_slice(&buffer[..read]);
                if let Some(end) =
                    wire.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                {
                    break end + 4;
                }
            };
            let headers = String::from_utf8(wire[..head].to_vec()).unwrap();
            let length: usize = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map_or(0, |(_, value)| value.trim().parse().unwrap());
            while wire.len() < head + length {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "unexpected EOF before mock request body");
                wire.extend_from_slice(&buffer[..read]);
            }
            let target = headers
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let path = base.join(target).unwrap();
            assert_eq!(path.path(), reply.path, "unexpected mock endpoint");
            if path.path() == "/challenge"
                && let Some(entered) = entered.take()
            {
                let _ = entered.send(());
            }
            if reply.hold {
                std::future::pending::<()>().await;
            }
            let response = format!(
                "HTTP/1.1 {} Fixture\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n{}\r\n{}",
                reply.status,
                reply.body.len(),
                reply.headers,
                reply.body,
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (client, Mock { task, entered: receiver })
}

pub(super) fn order_replies(
    body: &str,
    finalize: bool,
) -> Vec<Reply> {
    let mut order = Reply::new(
        "/acme/new-order",
        201,
        r#"{"authorizations":["http://issuer.test/auth"],"finalize":"http://issuer.test/finalize"}"#,
    );
    order.headers = "Location: http://issuer.test/order\r\n".into();
    let auth = Reply::new(
        "/auth",
        200,
        r#"{"status":"pending","challenges":[{"type":"http-01","token":"LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0","url":"http://issuer.test/challenge"}]}"#,
    );
    let mut replies = vec![
        Reply::nonce(),
        order,
        Reply::nonce(),
        auth,
        Reply::nonce(),
        Reply::new("/challenge", 200, "{}"),
        Reply::nonce(),
        Reply::new("/challenge", 200, r#"{"status":"valid"}"#),
    ];
    if finalize {
        replies.extend([
            Reply::nonce(),
            Reply::new("/order", 200, r#"{"status":"ready"}"#),
            Reply::nonce(),
            Reply::new("/finalize", 200, "{}"),
        ]);
    }
    replies.extend([Reply::nonce(), Reply::new("/order", 200,
        r#"{"status":"valid","certificate":"http://issuer.test/certificate"}"#),
        Reply::nonce(), Reply::new("/certificate", 200, body)]);
    replies
}
