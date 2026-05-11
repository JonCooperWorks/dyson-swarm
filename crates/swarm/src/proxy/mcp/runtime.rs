use std::collections::BTreeMap;
use std::path::Path as FsPath;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, Response, StatusCode};
use serde::{Deserialize, Serialize};

use crate::error::SwarmError;
use crate::instance::{DeletedMcpServer, SYSTEM_OWNER};
use crate::mcp_servers::{self, McpAuthSpec, McpRuntimeSpec, McpServerEntry};
use crate::traits::{InstanceStatus, ListFilter};

use super::McpService;
use super::errors::error_resp;
use super::tools::filter_tools_list_body;
use super::{validate_remote_mcp_auth_urls, validate_remote_mcp_url};

const MAX_RUNTIME_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(super) enum RuntimeRequest<'a> {
    Forward {
        instance_id: &'a str,
        server_name: &'a str,
        transport: RuntimeTransportSpec<'a>,
        request_json: &'a str,
    },
    StopServer {
        instance_id: &'a str,
        server_name: &'a str,
    },
    StopInstance {
        instance_id: &'a str,
    },
    RestartServer {
        instance_id: &'a str,
        server_name: &'a str,
        transport: RuntimeTransportSpec<'a>,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
pub(super) enum RuntimeTransportSpec<'a> {
    DockerStdio {
        args: &'a [String],
        env: &'a std::collections::HashMap<String, String>,
    },
    HttpStreamable {
        url: &'a str,
        #[serde(skip_serializing_if = "BTreeMap::is_empty")]
        headers: BTreeMap<String, String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_bearer_env: Option<&'a str>,
    },
}

impl<'a> RuntimeRequest<'a> {
    pub(super) fn forward_docker(
        instance_id: &'a str,
        server_name: &'a str,
        args: &'a [String],
        env: &'a std::collections::HashMap<String, String>,
        request_json: &'a str,
    ) -> Self {
        Self::Forward {
            instance_id,
            server_name,
            transport: RuntimeTransportSpec::DockerStdio { args, env },
            request_json,
        }
    }

    fn forward_http_streamable(
        instance_id: &'a str,
        server_name: &'a str,
        url: &'a str,
        headers: BTreeMap<String, String>,
        auth_bearer_env: Option<&'a str>,
        request_json: &'a str,
    ) -> Self {
        Self::Forward {
            instance_id,
            server_name,
            transport: RuntimeTransportSpec::HttpStreamable {
                url,
                headers,
                auth_bearer_env,
            },
            request_json,
        }
    }

    fn restart_server(
        instance_id: &'a str,
        server_name: &'a str,
        transport: RuntimeTransportSpec<'a>,
    ) -> Self {
        Self::RestartServer {
            instance_id,
            server_name,
            transport,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeForwardResponse {
    pub(super) status: u16,
    #[serde(default)]
    pub(super) content_type: Option<String>,
    #[serde(default)]
    pub(super) body: String,
}

pub(super) async fn forward_runtime_stdio(
    svc: &McpService,
    instance_id: &str,
    server_name: &str,
    entry: &McpServerEntry,
    body_bytes: &[u8],
    peek: Option<&(String, serde_json::Value, serde_json::Value)>,
) -> Response<Body> {
    let Some(socket_path) = svc.runtime_socket_path.as_deref() else {
        return error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp runtime helper not configured",
        );
    };
    let request_json = match std::str::from_utf8(body_bytes) {
        Ok(s) => s,
        Err(_) => return error_resp(StatusCode::BAD_REQUEST, "JSON-RPC body must be UTF-8"),
    };
    if let Some(McpRuntimeSpec::HttpStreamable { url, .. }) = entry.runtime.as_ref() {
        if let Err(err) = validate_remote_mcp_url(svc, url).await {
            tracing::warn!(error = %err, server = %server_name, "mcp runtime: upstream rejected");
            return error_resp(StatusCode::FORBIDDEN, "mcp upstream not allowed");
        }
        if let Err(err) = validate_remote_mcp_auth_urls(svc, &entry.auth).await {
            tracing::warn!(error = %err, server = %server_name, "mcp runtime: auth URL rejected");
            return error_resp(StatusCode::FORBIDDEN, "mcp upstream not allowed");
        }
    }
    let request =
        match runtime_forward_request_for_entry(instance_id, server_name, entry, request_json) {
            Ok(request) => request,
            Err(msg) => return error_resp(StatusCode::INTERNAL_SERVER_ERROR, &msg),
        };
    let runtime_resp = match call_runtime(socket_path, &request).await {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(
                error = %err,
                server = %server_name,
                "mcp runtime: request failed"
            );
            return error_resp(StatusCode::BAD_GATEWAY, "mcp runtime request failed");
        }
    };
    let status =
        StatusCode::from_u16(runtime_resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let content_type = runtime_resp.content_type;
    let mut body = runtime_resp.body.into_bytes();
    let response_ct = content_type.as_deref().unwrap_or({
        if body.is_empty() {
            ""
        } else {
            "application/json"
        }
    });
    let should_filter_list = matches!(peek, Some((m, _, _)) if m == "tools/list")
        && entry.enabled_tools.is_some()
        && response_ct.to_lowercase().starts_with("application/json")
        && status.is_success();
    if should_filter_list {
        let allowed = entry.enabled_tools.as_deref().unwrap_or(&[]);
        body = match filter_tools_list_body(&body, allowed) {
            Ok(filtered) => filtered,
            Err(err) => {
                tracing::warn!(error = %err, "mcp runtime: tools/list filter failed; passing through");
                body
            }
        };
    }
    let mut builder = Response::builder().status(status);
    if let Some(ct) = content_type {
        builder = builder.header(axum::http::header::CONTENT_TYPE, ct);
    } else if !body.is_empty() {
        builder = builder.header(axum::http::header::CONTENT_TYPE, "application/json");
    }
    if !body.is_empty() {
        builder = builder.header(
            axum::http::header::CONTENT_LENGTH,
            HeaderValue::from(body.len()),
        );
    }
    let body_stream =
        futures::stream::once(async move { Ok::<Bytes, std::io::Error>(Bytes::from(body)) });
    builder
        .body(Body::from_stream(body_stream))
        .unwrap_or_else(|_| error_resp(StatusCode::INTERNAL_SERVER_ERROR, "build resp"))
}

pub(super) fn runtime_forward_request_for_entry<'a>(
    instance_id: &'a str,
    server_name: &'a str,
    entry: &'a McpServerEntry,
    request_json: &'a str,
) -> Result<RuntimeRequest<'a>, String> {
    Ok(match runtime_transport_for_entry(entry)? {
        RuntimeTransportSpec::DockerStdio { args, env } => {
            RuntimeRequest::forward_docker(instance_id, server_name, args, env, request_json)
        }
        RuntimeTransportSpec::HttpStreamable {
            url,
            headers,
            auth_bearer_env,
        } => RuntimeRequest::forward_http_streamable(
            instance_id,
            server_name,
            url,
            headers,
            auth_bearer_env,
            request_json,
        ),
    })
}

fn runtime_restart_request_for_entry<'a>(
    instance_id: &'a str,
    server_name: &'a str,
    entry: &'a McpServerEntry,
) -> Result<RuntimeRequest<'a>, String> {
    Ok(RuntimeRequest::restart_server(
        instance_id,
        server_name,
        runtime_transport_for_entry(entry)?,
    ))
}

fn runtime_transport_for_entry<'a>(
    entry: &'a McpServerEntry,
) -> Result<RuntimeTransportSpec<'a>, String> {
    match entry.runtime.as_ref() {
        Some(McpRuntimeSpec::DockerStdio { command, args, env }) => {
            if command != "docker" {
                return Err("invalid docker MCP runtime command".into());
            }
            Ok(RuntimeTransportSpec::DockerStdio { args, env })
        }
        Some(McpRuntimeSpec::HttpStreamable {
            url,
            headers,
            auth_bearer_env,
        }) => {
            let mut runtime_headers: BTreeMap<String, String> = headers.clone();
            match &entry.auth {
                McpAuthSpec::None => {}
                McpAuthSpec::Bearer { token } => {
                    runtime_headers.insert("Authorization".into(), format!("Bearer {token}"));
                }
                McpAuthSpec::Oauth { .. } => {
                    let tokens = entry
                        .oauth_tokens
                        .as_ref()
                        .ok_or_else(|| "oauth not authorised yet".to_owned())?;
                    runtime_headers.insert(
                        "Authorization".into(),
                        format!("Bearer {}", tokens.access_token),
                    );
                }
            }
            Ok(RuntimeTransportSpec::HttpStreamable {
                url,
                headers: runtime_headers,
                auth_bearer_env: auth_bearer_env.as_deref(),
            })
        }
        None => Err("invalid mcp runtime entry".into()),
    }
}

pub(super) async fn call_runtime(
    socket_path: &FsPath,
    request: &RuntimeRequest<'_>,
) -> Result<RuntimeForwardResponse, String> {
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("connect {}: {e}", socket_path.display()))?;
    let line = serde_json::to_vec(request).map_err(|e| format!("encode request: {e}"))?;
    stream
        .write_all(&line)
        .await
        .map_err(|e| format!("write request: {e}"))?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|e| format!("write newline: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;

    let mut reader = BufReader::new(stream);
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(125),
        read_line_capped(&mut reader, MAX_RUNTIME_RESPONSE_BYTES),
    )
    .await
    .map_err(|_| "runtime response timed out".to_owned())?
    .map_err(|e| format!("read response: {e}"))?;
    if out.is_empty() {
        return Err("runtime closed without response".into());
    }
    let out = String::from_utf8(out).map_err(|e| format!("runtime response was not utf-8: {e}"))?;
    serde_json::from_str(&out).map_err(|e| format!("decode response: {e}"))
}

async fn read_line_capped<R>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, std::io::Error>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;

    let mut out = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(out);
        }
        let take = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |pos| pos + 1);
        if out.len().saturating_add(take) > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "runtime response exceeded 16 MiB cap",
            ));
        }
        out.extend_from_slice(&available[..take]);
        reader.consume(take);
        if out.last() == Some(&b'\n') {
            return Ok(out);
        }
    }
}

pub async fn stop_runtime_server(
    socket_path: Option<&FsPath>,
    instance_id: &str,
    server_name: &str,
) -> Result<(), String> {
    let Some(socket_path) = socket_path else {
        return Ok(());
    };
    let resp = call_runtime(
        socket_path,
        &RuntimeRequest::StopServer {
            instance_id,
            server_name,
        },
    )
    .await?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(format!(
            "runtime stop_server HTTP {}: {}",
            resp.status, resp.body
        ))
    }
}

pub async fn stop_runtime_instance(
    socket_path: Option<&FsPath>,
    instance_id: &str,
) -> Result<(), String> {
    let Some(socket_path) = socket_path else {
        return Ok(());
    };
    let resp = call_runtime(socket_path, &RuntimeRequest::StopInstance { instance_id }).await?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(format!(
            "runtime stop_instance HTTP {}: {}",
            resp.status, resp.body
        ))
    }
}

pub async fn restart_runtime_server(
    socket_path: Option<&FsPath>,
    instance_id: &str,
    server_name: &str,
    entry: &McpServerEntry,
) -> Result<(), String> {
    let Some(socket_path) = socket_path else {
        return Ok(());
    };
    let req = runtime_restart_request_for_entry(instance_id, server_name, entry)?;
    let resp = call_runtime(socket_path, &req).await?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(format!(
            "runtime restart_server HTTP {}: {}",
            resp.status, resp.body
        ))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeRestartReport {
    pub visited_instances: usize,
    pub runtime_servers: usize,
    pub restarted: usize,
    pub failed: usize,
}

pub async fn restart_active_runtime_servers(
    svc: Arc<McpService>,
) -> Result<RuntimeRestartReport, SwarmError> {
    if svc.runtime_socket_path.is_none() {
        return Ok(RuntimeRestartReport::default());
    }
    let live = svc
        .instances
        .list(
            SYSTEM_OWNER,
            ListFilter {
                status: Some(InstanceStatus::Live),
                include_destroyed: false,
            },
        )
        .await?;
    let mut report = RuntimeRestartReport {
        visited_instances: live.len(),
        ..RuntimeRestartReport::default()
    };

    for row in live {
        let names = match mcp_servers::list_names(&svc.user_secrets, &row.owner_id, &row.id).await {
            Ok(names) => names,
            Err(err) => {
                report.failed += 1;
                tracing::warn!(
                    error = %err,
                    instance = %row.id,
                    "mcp runtime restart: list failed"
                );
                continue;
            }
        };
        for name in names {
            let entry =
                match mcp_servers::get(&svc.user_secrets, &row.owner_id, &row.id, &name).await {
                    Ok(Some(entry)) => entry,
                    Ok(None) => continue,
                    Err(err) => {
                        report.failed += 1;
                        tracing::warn!(
                            error = %err,
                            instance = %row.id,
                            server = %name,
                            "mcp runtime restart: entry read failed"
                        );
                        continue;
                    }
                };
            let Some(runtime) = entry.runtime.as_ref() else {
                continue;
            };
            if matches!(entry.auth, McpAuthSpec::Oauth { .. }) && entry.oauth_tokens.is_none() {
                tracing::debug!(
                    instance = %row.id,
                    server = %name,
                    "mcp runtime restart: skipping unauthorised oauth server"
                );
                continue;
            }
            report.runtime_servers += 1;
            if let McpRuntimeSpec::HttpStreamable { url, .. } = runtime {
                if let Err(err) = validate_remote_mcp_url(&svc, url).await {
                    report.failed += 1;
                    tracing::warn!(
                        error = %err,
                        instance = %row.id,
                        server = %name,
                        "mcp runtime restart: upstream rejected"
                    );
                    continue;
                }
                if let Err(err) = validate_remote_mcp_auth_urls(&svc, &entry.auth).await {
                    report.failed += 1;
                    tracing::warn!(
                        error = %err,
                        instance = %row.id,
                        server = %name,
                        "mcp runtime restart: auth URL rejected"
                    );
                    continue;
                }
            }

            match restart_runtime_server(svc.runtime_socket_path.as_deref(), &row.id, &name, &entry)
                .await
            {
                Ok(()) => {
                    report.restarted += 1;
                    tracing::debug!(
                        instance = %row.id,
                        server = %name,
                        "mcp runtime restart: restarted"
                    );
                }
                Err(err) => {
                    report.failed += 1;
                    tracing::warn!(
                        error = %err,
                        instance = %row.id,
                        server = %name,
                        "mcp runtime restart: failed"
                    );
                }
            }
        }
    }

    Ok(report)
}

pub(super) async fn stop_deleted_runtime_server(
    svc: &McpService,
    deleted: &DeletedMcpServer,
) -> Result<(), Response<Body>> {
    if deleted.runtime.is_none() {
        return Ok(());
    }
    stop_runtime_server(
        svc.runtime_socket_path.as_deref(),
        &deleted.instance_id,
        &deleted.name,
    )
    .await
    .map_err(|err| {
        tracing::warn!(
            error = %err,
            owner = %deleted.owner_id,
            instance = %deleted.instance_id,
            server = %deleted.name,
            "mcp runtime: deleted server cleanup failed"
        );
        error_resp(StatusCode::BAD_GATEWAY, "mcp runtime cleanup failed")
    })
}

pub(super) async fn stop_deleted_runtime_servers_best_effort(
    svc: &McpService,
    deleted: &[DeletedMcpServer],
) -> usize {
    let mut errors = 0usize;
    for server in deleted {
        if server.runtime.is_none() {
            continue;
        }
        if let Err(err) = stop_runtime_server(
            svc.runtime_socket_path.as_deref(),
            &server.instance_id,
            &server.name,
        )
        .await
        {
            errors += 1;
            tracing::warn!(
                error = %err,
                owner = %server.owner_id,
                instance = %server.instance_id,
                server = %server.name,
                "mcp runtime: catalog delete cleanup failed"
            );
        }
    }
    errors
}
