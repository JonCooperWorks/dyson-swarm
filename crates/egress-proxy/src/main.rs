use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HOST, HeaderName, HeaderValue};
use hyper::http::uri::Scheme;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use dyson_swarm_core::network_policy::NetworkPolicy;

const DEFAULT_POLICY_PATH: &str = "/run/dyson-egress/policies.json";
const DEFAULT_LISTEN: &str = "192.168.0.1:3128";
const POLICY_RELOAD_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_MAX_CONNECTIONS: usize = 2048;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = BoxBody<Bytes, BoxError>;

#[derive(Debug, Parser)]
#[command(name = "dyson-egress-proxy")]
#[command(about = "Dyson policy-aware sandbox egress proxy")]
struct Args {
    #[arg(long, default_value = DEFAULT_LISTEN)]
    listen: SocketAddr,
    #[arg(long, default_value = DEFAULT_POLICY_PATH)]
    policy: PathBuf,
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,
    #[arg(long, default_value_t = DEFAULT_CONNECT_TIMEOUT_SECS)]
    connect_timeout_secs: u64,
}

#[derive(Debug, Clone, Copy)]
struct ProxyLimits {
    connect_timeout: Duration,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let store = PolicyStore::new(args.policy.clone());
    if let Err(err) = store.reload().await {
        warn!(
            policy = %args.policy.display(),
            error = %err,
            "initial policy load failed; proxy will fail closed until a valid policy is loaded"
        );
    }

    tokio::spawn(policy_reload_task(store.clone()));

    let listener = TcpListener::bind(args.listen).await?;
    let max_connections = args.max_connections.max(1);
    let limits = ProxyLimits {
        connect_timeout: Duration::from_secs(args.connect_timeout_secs.max(1)),
    };
    info!(
        listen = %args.listen,
        policy = %args.policy.display(),
        max_connections,
        connect_timeout_secs = args.connect_timeout_secs.max(1),
        "dyson egress proxy listening"
    );
    serve(listener, store, max_connections, limits).await
}

async fn serve(
    listener: TcpListener,
    store: PolicyStore,
    max_connections: usize,
    limits: ProxyLimits,
) -> Result<(), BoxError> {
    let permits = Arc::new(Semaphore::new(max_connections));
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            warn!(peer = %peer, max_connections, "proxy connection rejected: limit reached");
            drop(stream);
            continue;
        };
        let store = store.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let peer_ip = peer.ip();
            let service = service_fn(move |req| {
                let store = store.clone();
                async move { Ok::<_, Infallible>(handle_request(req, peer_ip, store, limits).await) }
            });
            let io = TokioIo::new(stream);
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                debug!(peer = %peer, error = %err, "proxy connection ended with error");
            }
        });
    }
}

async fn policy_reload_task(store: PolicyStore) {
    let mut interval = tokio::time::interval(POLICY_RELOAD_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    #[cfg(unix)]
    let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(sig) => Some(sig),
        Err(err) => {
            warn!(error = %err, "failed to install SIGHUP handler; periodic policy reload remains active");
            None
        }
    };

    loop {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = interval.tick() => reload_and_log(&store).await,
                _ = async {
                    if let Some(hup) = hup.as_mut() {
                        hup.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => reload_and_log(&store).await,
            }
        }

        #[cfg(not(unix))]
        {
            interval.tick().await;
            reload_and_log(&store).await;
        }
    }
}

async fn reload_and_log(store: &PolicyStore) {
    match store.reload().await {
        Ok(count) => info!(sandboxes = count, "egress policy reloaded"),
        Err(err) => warn!(
            policy = %store.path().display(),
            error = %err,
            "egress policy reload failed; keeping last known-good policy"
        ),
    }
}

async fn handle_request(
    req: Request<Incoming>,
    source_ip: IpAddr,
    store: PolicyStore,
    limits: ProxyLimits,
) -> Response<ProxyBody> {
    if req.version() != hyper::Version::HTTP_11 {
        return text_response(StatusCode::BAD_REQUEST, "bad request");
    }

    if req.method() == Method::CONNECT {
        handle_connect(req, source_ip, store, limits).await
    } else {
        handle_http(req, source_ip, store, limits).await
    }
}

async fn handle_http(
    mut req: Request<Incoming>,
    source_ip: IpAddr,
    store: PolicyStore,
    limits: ProxyLimits,
) -> Response<ProxyBody> {
    let dest = match Destination::from_absolute_uri(req.uri()) {
        Ok(dest) => dest,
        Err(err) => {
            debug!(source = %source_ip, error = %err, "malformed proxy request");
            return text_response(StatusCode::BAD_REQUEST, "bad request");
        }
    };

    let connect_addr = match resolve_authorized(&dest, source_ip, &store).await {
        Ok(addrs) => addrs[0],
        Err(ProxyError::Denied(reason)) => {
            log_denial(source_ip, &dest, &reason, &store);
            return text_response(StatusCode::FORBIDDEN, "egress denied");
        }
        Err(ProxyError::Gateway(err)) => {
            debug!(source = %source_ip, target = %dest.log_target(), error = %err, "upstream resolution failed");
            return text_response(StatusCode::BAD_GATEWAY, "bad gateway");
        }
    };

    let stream = match connect_with_timeout(connect_addr, limits).await {
        Ok(stream) => stream,
        Err(err) => {
            debug!(
                source = %source_ip,
                target = %dest.log_target(),
                addr = %connect_addr,
                error = %err,
                "upstream connect failed"
            );
            return text_response(StatusCode::BAD_GATEWAY, "bad gateway");
        }
    };

    strip_hop_headers(req.headers_mut());
    if let Err(err) = rewrite_to_origin_form(&mut req, &dest) {
        debug!(source = %source_ip, target = %dest.log_target(), error = %err, "failed to rewrite request URI");
        return text_response(StatusCode::BAD_REQUEST, "bad request");
    }

    let io = TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(parts) => parts,
        Err(err) => {
            debug!(source = %source_ip, target = %dest.log_target(), error = %err, "upstream handshake failed");
            return text_response(StatusCode::BAD_GATEWAY, "bad gateway");
        }
    };
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            debug!(error = %err, "upstream HTTP connection ended with error");
        }
    });

    match sender.send_request(req).await {
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();
            strip_hop_headers(&mut parts.headers);
            Response::from_parts(parts, boxed_incoming(body))
        }
        Err(err) => {
            debug!(source = %source_ip, target = %dest.log_target(), error = %err, "upstream request failed");
            text_response(StatusCode::BAD_GATEWAY, "bad gateway")
        }
    }
}

async fn handle_connect(
    mut req: Request<Incoming>,
    source_ip: IpAddr,
    store: PolicyStore,
    limits: ProxyLimits,
) -> Response<ProxyBody> {
    let dest = match Destination::from_connect_uri(req.uri()) {
        Ok(dest) => dest,
        Err(err) => {
            debug!(source = %source_ip, error = %err, "malformed CONNECT request");
            return text_response(StatusCode::BAD_REQUEST, "bad request");
        }
    };

    let connect_addr = match resolve_authorized(&dest, source_ip, &store).await {
        Ok(addrs) => addrs[0],
        Err(ProxyError::Denied(reason)) => {
            log_denial(source_ip, &dest, &reason, &store);
            return text_response(StatusCode::FORBIDDEN, "egress denied");
        }
        Err(ProxyError::Gateway(err)) => {
            debug!(source = %source_ip, target = %dest.log_target(), error = %err, "upstream resolution failed");
            return text_response(StatusCode::BAD_GATEWAY, "bad gateway");
        }
    };

    let upstream = match connect_with_timeout(connect_addr, limits).await {
        Ok(stream) => stream,
        Err(err) => {
            debug!(
                source = %source_ip,
                target = %dest.log_target(),
                addr = %connect_addr,
                error = %err,
                "CONNECT upstream connect failed"
            );
            return text_response(StatusCode::BAD_GATEWAY, "bad gateway");
        }
    };

    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let mut upgraded = TokioIo::new(upgraded);
                let mut upstream = upstream;
                if let Err(err) = copy_bidirectional(&mut upgraded, &mut upstream).await {
                    debug!(error = %err, "CONNECT tunnel ended with error");
                }
            }
            Err(err) => debug!(error = %err, "CONNECT upgrade failed"),
        }
    });

    empty_response(StatusCode::OK)
}

async fn connect_with_timeout(
    addr: SocketAddrV4,
    limits: ProxyLimits,
) -> Result<TcpStream, std::io::Error> {
    match tokio::time::timeout(limits.connect_timeout, TcpStream::connect(addr)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "connect timeout",
        )),
    }
}

fn rewrite_to_origin_form(req: &mut Request<Incoming>, dest: &Destination) -> Result<(), String> {
    let origin = req
        .uri()
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    *req.uri_mut() = origin
        .parse::<Uri>()
        .map_err(|err| format!("invalid origin URI: {err}"))?;
    let host = HeaderValue::from_str(&dest.host_header())
        .map_err(|err| format!("invalid Host header: {err}"))?;
    req.headers_mut().insert(HOST, host);
    Ok(())
}

fn strip_hop_headers(headers: &mut hyper::HeaderMap) {
    let connection_tokens: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();

    for name in connection_tokens {
        headers.remove(name);
    }

    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

async fn resolve_authorized(
    dest: &Destination,
    source_ip: IpAddr,
    store: &PolicyStore,
) -> Result<Vec<SocketAddrV4>, ProxyError> {
    let policy = store
        .policy_for(source_ip)
        .await
        .ok_or_else(|| ProxyError::Denied("missing source sandbox policy".to_owned()))?;

    let addrs = resolve_destination(dest).await?;
    for addr in &addrs {
        if !policy.allows(*addr.ip()) {
            return Err(ProxyError::Denied(format!(
                "destination {} denied by {} policy",
                addr.ip(),
                policy.kind.kind_str()
            )));
        }
    }
    Ok(addrs)
}

async fn resolve_destination(dest: &Destination) -> Result<Vec<SocketAddrV4>, ProxyError> {
    match &dest.host {
        Host::Ipv4(ip) => Ok(vec![SocketAddrV4::new(*ip, dest.port)]),
        Host::Name(host) => {
            let lookup = tokio::net::lookup_host((host.as_str(), dest.port))
                .await
                .map_err(|err| ProxyError::Gateway(format!("DNS lookup failed: {err}")))?;
            let mut addrs = Vec::new();
            let mut saw_ipv6 = false;
            for addr in lookup {
                match addr {
                    SocketAddr::V4(v4) => addrs.push(v4),
                    SocketAddr::V6(_) => saw_ipv6 = true,
                }
            }
            addrs.sort();
            addrs.dedup();
            if addrs.is_empty() {
                let msg = if saw_ipv6 {
                    "hostname resolved only to IPv6 addresses; IPv6 proxy egress is not enabled"
                } else {
                    "hostname resolved to no addresses"
                };
                return Err(ProxyError::Gateway(msg.to_owned()));
            }
            Ok(addrs)
        }
    }
}

fn log_denial(source_ip: IpAddr, dest: &Destination, reason: &str, store: &PolicyStore) {
    if let Some(policy) = store.current_policy_for(source_ip) {
        info!(
            source = %source_ip,
            instance_id = %policy.instance_id,
            kind = %policy.kind.kind_str(),
            target = %dest.log_target(),
            reason = %reason,
            "egress denied"
        );
    } else {
        info!(
            source = %source_ip,
            target = %dest.log_target(),
            reason = %reason,
            "egress denied"
        );
    }
}

#[derive(Debug)]
enum ProxyError {
    Denied(String),
    Gateway(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Destination {
    host: Host,
    port: u16,
    authority: String,
}

impl Destination {
    fn from_absolute_uri(uri: &Uri) -> Result<Self, String> {
        if uri.scheme() != Some(&Scheme::HTTP) {
            return Err("HTTP proxy requests must use absolute http:// URIs".to_owned());
        }
        let authority = uri
            .authority()
            .ok_or_else(|| "absolute URI missing authority".to_owned())?;
        let port = authority.port_u16().unwrap_or(80);
        Self::from_host_port(authority.host(), port, authority.as_str())
    }

    fn from_connect_uri(uri: &Uri) -> Result<Self, String> {
        if uri.scheme().is_some() || uri.path_and_query().is_some() {
            return Err("CONNECT target must be authority-form host:port".to_owned());
        }
        let authority = uri
            .authority()
            .ok_or_else(|| "CONNECT target missing authority".to_owned())?;
        let port = authority
            .port_u16()
            .ok_or_else(|| "CONNECT target missing numeric port".to_owned())?;
        Self::from_host_port(authority.host(), port, authority.as_str())
    }

    fn from_host_port(host: &str, port: u16, authority: &str) -> Result<Self, String> {
        if port == 0 {
            return Err("destination port 0 is invalid".to_owned());
        }
        if host.is_empty() {
            return Err("destination host is empty".to_owned());
        }
        if host.contains(':') || host.starts_with('[') || host.ends_with(']') {
            return Err("IPv6 destinations are not supported".to_owned());
        }
        let host = match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => Host::Ipv4(ip),
            Ok(IpAddr::V6(_)) => return Err("IPv6 destinations are not supported".to_owned()),
            Err(_) => Host::Name(host.to_ascii_lowercase()),
        };
        Ok(Self {
            host,
            port,
            authority: authority.to_owned(),
        })
    }

    fn host_header(&self) -> String {
        self.authority.clone()
    }

    fn log_target(&self) -> String {
        self.authority.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Host {
    Ipv4(Ipv4Addr),
    Name(String),
}

#[derive(Clone)]
struct PolicyStore {
    path: Arc<PathBuf>,
    current: Arc<RwLock<Option<Arc<PolicySet>>>>,
}

impl PolicyStore {
    fn new(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
            current: Arc::new(RwLock::new(None)),
        }
    }

    #[cfg(test)]
    fn from_policy(policy: PolicySet) -> Self {
        Self {
            path: Arc::new(PathBuf::from(DEFAULT_POLICY_PATH)),
            current: Arc::new(RwLock::new(Some(Arc::new(policy)))),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    async fn reload(&self) -> Result<usize, PolicyLoadError> {
        let text = tokio::fs::read_to_string(self.path.as_ref())
            .await
            .map_err(PolicyLoadError::Read)?;
        let policy = PolicySet::from_json_str(&text)?;
        let count = policy.sandboxes.len();
        *self.current.write().await = Some(Arc::new(policy));
        Ok(count)
    }

    async fn policy_for(&self, source_ip: IpAddr) -> Option<Arc<SandboxPolicy>> {
        let ip = match source_ip {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return None,
        };
        self.current
            .read()
            .await
            .as_ref()
            .and_then(|set| set.sandboxes.get(&ip).cloned())
    }

    fn current_policy_for(&self, source_ip: IpAddr) -> Option<Arc<SandboxPolicy>> {
        let ip = match source_ip {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return None,
        };
        self.current.try_read().ok().and_then(|guard| {
            guard
                .as_ref()
                .and_then(|set| set.sandboxes.get(&ip).cloned())
        })
    }
}

#[derive(Debug, thiserror::Error)]
enum PolicyLoadError {
    #[error("read policy file: {0}")]
    Read(std::io::Error),
    #[error("parse policy JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported policy version {0}")]
    Version(u32),
    #[error("invalid sandbox IP {0:?}")]
    SandboxIp(String),
    #[error("invalid CIDR {cidr:?}: {reason}")]
    Cidr { cidr: String, reason: String },
    #[error("invalid policy kind {0:?}")]
    Kind(String),
}

#[derive(Debug, Clone)]
struct PolicySet {
    sandboxes: BTreeMap<Ipv4Addr, Arc<SandboxPolicy>>,
}

impl PolicySet {
    fn from_json_str(text: &str) -> Result<Self, PolicyLoadError> {
        let raw: RawPolicyFile = serde_json::from_str(text)?;
        if raw.version != 1 {
            return Err(PolicyLoadError::Version(raw.version));
        }

        let mut sandboxes = BTreeMap::new();
        for (source, raw_policy) in raw.sandboxes {
            let source_ip = source
                .parse::<Ipv4Addr>()
                .map_err(|_| PolicyLoadError::SandboxIp(source.clone()))?;
            let allow_out = parse_cidrs(raw_policy.allow_out)?;
            let deny_out = parse_cidrs(raw_policy.deny_out)?;
            let kind = parse_policy_kind(&raw_policy.kind)?;
            sandboxes.insert(
                source_ip,
                Arc::new(SandboxPolicy {
                    instance_id: raw_policy.instance_id,
                    kind,
                    allow_out,
                    deny_out,
                }),
            );
        }
        Ok(Self { sandboxes })
    }
}

#[derive(Debug, Deserialize)]
struct RawPolicyFile {
    version: u32,
    #[serde(default)]
    sandboxes: BTreeMap<String, RawSandboxPolicy>,
}

#[derive(Debug, Deserialize)]
struct RawSandboxPolicy {
    instance_id: String,
    kind: String,
    #[serde(default)]
    allow_out: Vec<String>,
    #[serde(default)]
    deny_out: Vec<String>,
}

#[derive(Debug, Clone)]
struct SandboxPolicy {
    instance_id: String,
    kind: NetworkPolicy,
    allow_out: Vec<Ipv4Cidr>,
    deny_out: Vec<Ipv4Cidr>,
}

impl SandboxPolicy {
    fn allows(&self, ip: Ipv4Addr) -> bool {
        let allowed = self.allow_out.iter().any(|cidr| cidr.contains(ip));
        let denied = self.deny_out.iter().any(|cidr| cidr.contains(ip));
        match &self.kind {
            NetworkPolicy::Airgap => false,
            NetworkPolicy::Allowlist { .. } => allowed,
            NetworkPolicy::Open => allowed || !denied,
            NetworkPolicy::NoLocalNet | NetworkPolicy::Denylist { .. } => !denied,
        }
    }
}

fn parse_cidrs(raw: Vec<String>) -> Result<Vec<Ipv4Cidr>, PolicyLoadError> {
    raw.into_iter().map(|cidr| Ipv4Cidr::parse(&cidr)).collect()
}

fn parse_policy_kind(kind: &str) -> Result<NetworkPolicy, PolicyLoadError> {
    match kind {
        "airgap" => Ok(NetworkPolicy::Airgap),
        "nolocalnet" => Ok(NetworkPolicy::NoLocalNet),
        "allowlist" => Ok(NetworkPolicy::Allowlist {
            entries: Vec::new(),
        }),
        "denylist" => Ok(NetworkPolicy::Denylist {
            entries: Vec::new(),
        }),
        "open" => Ok(NetworkPolicy::Open),
        other => Err(PolicyLoadError::Kind(other.to_owned())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4Cidr {
    network: u32,
    prefix: u8,
}

impl Ipv4Cidr {
    fn parse(raw: &str) -> Result<Self, PolicyLoadError> {
        let (addr, prefix) = raw.split_once('/').ok_or_else(|| PolicyLoadError::Cidr {
            cidr: raw.to_owned(),
            reason: "missing prefix".to_owned(),
        })?;
        let ip = addr
            .parse::<Ipv4Addr>()
            .map_err(|err| PolicyLoadError::Cidr {
                cidr: raw.to_owned(),
                reason: err.to_string(),
            })?;
        let prefix = prefix.parse::<u8>().map_err(|err| PolicyLoadError::Cidr {
            cidr: raw.to_owned(),
            reason: err.to_string(),
        })?;
        if prefix > 32 {
            return Err(PolicyLoadError::Cidr {
                cidr: raw.to_owned(),
                reason: "prefix must be <= 32".to_owned(),
            });
        }
        let mask = mask(prefix);
        Ok(Self {
            network: u32::from(ip) & mask,
            prefix,
        })
    }

    fn contains(self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & mask(self.prefix)) == self.network
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn text_response(status: StatusCode, text: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header(CONNECTION, "close")
        .body(boxed_full(text))
        .expect("static response is valid")
}

fn empty_response(status: StatusCode) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static response is valid")
}

fn boxed_full(text: &'static str) -> ProxyBody {
    Full::new(Bytes::from_static(text.as_bytes()))
        .map_err(|never| match never {})
        .boxed()
}

fn boxed_incoming(body: Incoming) -> ProxyBody {
    body.map_err(|err| -> BoxError { Box::new(err) }).boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dyson_swarm_core::network_policy::DEFAULT_DENY_OUT;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn default_deny() -> Vec<Ipv4Cidr> {
        DEFAULT_DENY_OUT
            .iter()
            .copied()
            .map(Ipv4Cidr::parse)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn policy(kind: NetworkPolicy, allow: &[&str], deny: &[&str]) -> SandboxPolicy {
        SandboxPolicy {
            instance_id: "inst-test".to_owned(),
            kind,
            allow_out: allow.iter().map(|c| Ipv4Cidr::parse(c).unwrap()).collect(),
            deny_out: deny.iter().map(|c| Ipv4Cidr::parse(c).unwrap()).collect(),
        }
    }

    fn store_with_source(source: &str, sandbox_policy: SandboxPolicy) -> PolicyStore {
        let mut sandboxes = BTreeMap::new();
        sandboxes.insert(
            source.parse::<Ipv4Addr>().unwrap(),
            Arc::new(sandbox_policy),
        );
        PolicyStore::from_policy(PolicySet { sandboxes })
    }

    #[test]
    fn cidr_matching_and_precedence() {
        let cidr = Ipv4Cidr::parse("192.168.0.0/16").unwrap();
        assert!(cidr.contains("192.168.0.1".parse().unwrap()));
        assert!(!cidr.contains("192.169.0.1".parse().unwrap()));

        let allowlist = policy(
            NetworkPolicy::Allowlist {
                entries: Vec::new(),
            },
            &["192.168.0.1/32"],
            &["192.168.0.0/16"],
        );
        assert!(allowlist.allows("192.168.0.1".parse().unwrap()));
        assert!(!allowlist.allows("192.168.0.2".parse().unwrap()));

        let denylist = policy(
            NetworkPolicy::Denylist {
                entries: Vec::new(),
            },
            &["0.0.0.0/0"],
            &["203.0.113.0/24"],
        );
        assert!(!denylist.allows("203.0.113.7".parse().unwrap()));
        assert!(denylist.allows("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn nolocalnet_denies_internal_and_metadata() {
        let p = SandboxPolicy {
            instance_id: "inst".to_owned(),
            kind: NetworkPolicy::NoLocalNet,
            allow_out: Vec::new(),
            deny_out: default_deny(),
        };
        for ip in ["192.168.0.1", "127.0.0.1", "169.254.169.254"] {
            assert!(!p.allows(ip.parse().unwrap()), "{ip} should be denied");
        }
    }

    #[test]
    fn nolocalnet_allows_public_ips() {
        let p = SandboxPolicy {
            instance_id: "inst".to_owned(),
            kind: NetworkPolicy::NoLocalNet,
            allow_out: Vec::new(),
            deny_out: default_deny(),
        };
        assert!(p.allows("8.8.8.8".parse().unwrap()));
        assert!(p.allows("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn open_can_allow_internal_ips() {
        let p = SandboxPolicy {
            instance_id: "inst".to_owned(),
            kind: NetworkPolicy::Open,
            allow_out: vec![Ipv4Cidr::parse("0.0.0.0/0").unwrap()],
            deny_out: default_deny(),
        };
        assert!(p.allows("192.168.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn unknown_source_sandbox_fails_closed() {
        let store = PolicyStore::from_policy(PolicySet {
            sandboxes: BTreeMap::new(),
        });
        let dest = Destination::from_absolute_uri(&"http://8.8.8.8/".parse().unwrap()).unwrap();
        let err = resolve_authorized(&dest, IpAddr::V4("127.0.0.1".parse().unwrap()), &store)
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Denied(_)));
    }

    #[test]
    fn malformed_absolute_uri_rejected() {
        assert!(Destination::from_absolute_uri(&"/relative".parse().unwrap()).is_err());
        assert!(Destination::from_absolute_uri(&"https://example.com/".parse().unwrap()).is_err());
    }

    #[test]
    fn malformed_connect_authority_rejected() {
        assert!(Destination::from_connect_uri(&"example.com".parse().unwrap()).is_err());
        assert!(
            Destination::from_connect_uri(&"http://example.com:443/".parse().unwrap()).is_err()
        );
        assert!(Destination::from_connect_uri(&"[::1]:443".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn absolute_form_http_forwarding() {
        let (origin_addr, origin_task) = spawn_http_origin().await;
        let proxy_addr = spawn_proxy(policy(
            NetworkPolicy::Open,
            &["0.0.0.0/0"],
            &["127.0.0.0/8"],
        ))
        .await;

        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "GET http://{origin_addr}/ok HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
        assert!(out.contains("origin-ok"), "{out}");

        origin_task.abort();
    }

    #[tokio::test]
    async fn connect_forwarding() {
        let (echo_addr, echo_task) = spawn_echo_origin().await;
        let proxy_addr = spawn_proxy(policy(
            NetworkPolicy::Open,
            &["0.0.0.0/0"],
            &["127.0.0.0/8"],
        ))
        .await;

        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut headers = Vec::new();
        let mut byte = [0; 1];
        while !headers.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            headers.push(byte[0]);
        }
        let status = String::from_utf8(headers).unwrap();
        assert!(status.starts_with("HTTP/1.1 200 OK"), "{status}");
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        echo_task.abort();
    }

    #[tokio::test]
    async fn denied_http_destination() {
        let (origin_addr, origin_task) = spawn_http_origin().await;
        let proxy_addr =
            spawn_proxy(policy(NetworkPolicy::NoLocalNet, &[], &["127.0.0.0/8"])).await;

        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "GET http://{origin_addr}/ok HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 403 Forbidden"), "{out}");
        assert!(out.contains("egress denied"), "{out}");

        origin_task.abort();
    }

    #[tokio::test]
    async fn denied_connect_destination() {
        let (echo_addr, echo_task) = spawn_echo_origin().await;
        let proxy_addr =
            spawn_proxy(policy(NetworkPolicy::NoLocalNet, &[], &["127.0.0.0/8"])).await;

        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 403 Forbidden"), "{out}");

        echo_task.abort();
    }

    #[tokio::test]
    async fn policy_reload_keeps_last_good_on_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policies.json");
        tokio::fs::write(
            &path,
            r#"{"version":1,"sandboxes":{"127.0.0.1":{"instance_id":"inst","kind":"nolocalnet","allow_out":[],"deny_out":["127.0.0.0/8"]}}}"#,
        )
        .await
        .unwrap();
        let store = PolicyStore::new(path.clone());
        store.reload().await.unwrap();
        tokio::fs::write(&path, "{not-json").await.unwrap();
        assert!(store.reload().await.is_err());
        let policy = store
            .policy_for(IpAddr::V4("127.0.0.1".parse().unwrap()))
            .await
            .unwrap();
        assert!(!policy.allows("127.0.0.1".parse().unwrap()));
    }

    async fn spawn_proxy(sandbox_policy: SandboxPolicy) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = store_with_source("127.0.0.1", sandbox_policy);
        tokio::spawn(async move {
            let _ = serve(
                listener,
                store,
                DEFAULT_MAX_CONNECTIONS,
                ProxyLimits {
                    connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
                },
            )
            .await;
        });
        addr
    }

    async fn spawn_http_origin() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let service = service_fn(|_req| async {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            b"origin-ok",
                        ))))
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (addr, task)
    }

    async fn spawn_echo_origin() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0; 4];
                    if stream.read_exact(&mut buf).await.is_ok() && &buf == b"ping" {
                        let _ = stream.write_all(b"pong").await;
                    }
                });
            }
        });
        (addr, task)
    }
}
