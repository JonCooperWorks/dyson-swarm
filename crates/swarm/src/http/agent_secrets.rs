//! Agent-visible, instance-scoped secrets.

use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::agent_secrets::{AgentSecretActor, AgentSecretError};
use crate::auth::{CallerIdentity, extract_bearer};
use crate::http::AppState;
use crate::instance::SHARED_PROVIDER;
use crate::traits::AgentSecretMetadata;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/instances/:id/agent-secrets", get(list_user))
        .route(
            "/v1/instances/:id/agent-secrets/:name",
            put(put_user).delete(delete_user),
        )
        .route(
            "/v1/instances/:id/agent-secrets/:name/reveal",
            get(reveal_user),
        )
        .with_state(state)
}

pub fn internal_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/internal/agent-secrets", get(list_internal))
        .route(
            "/v1/internal/agent-secrets/:name",
            get(get_internal).put(put_internal).delete(delete_internal),
        )
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct AgentSecretView {
    name: String,
    created_at: i64,
    updated_at: i64,
    last_read_at: Option<i64>,
}

impl From<AgentSecretMetadata> for AgentSecretView {
    fn from(row: AgentSecretMetadata) -> Self {
        Self {
            name: row.name,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_read_at: row.last_read_at,
        }
    }
}

#[derive(Debug, Serialize)]
struct AgentSecretValue {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct PutSecretBody {
    value: String,
}

async fn list_user(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<Vec<AgentSecretView>>, (StatusCode, String)> {
    let instance = state
        .instances
        .get(&caller.user_id, &id)
        .await
        .map_err(instance_err_to_response)?;
    let rows = state
        .agent_secrets
        .list(
            &instance.owner_id,
            &instance.id,
            AgentSecretActor::user(&caller.user_id),
        )
        .await
        .map_err(agent_secret_err_to_response)?;
    Ok(Json(rows.into_iter().map(AgentSecretView::from).collect()))
}

async fn reveal_user(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((id, name)): Path<(String, String)>,
) -> Result<Json<AgentSecretValue>, (StatusCode, String)> {
    let instance = state
        .instances
        .get(&caller.user_id, &id)
        .await
        .map_err(instance_err_to_response)?;
    let value = state
        .agent_secrets
        .get(
            &instance.owner_id,
            &instance.id,
            &name,
            AgentSecretActor::user(&caller.user_id),
        )
        .await
        .map_err(agent_secret_err_to_response)?
        .ok_or((StatusCode::NOT_FOUND, "secret not found".to_owned()))?;
    Ok(Json(AgentSecretValue {
        name,
        value: String::from_utf8(value).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "secret is not utf-8".to_owned(),
            )
        })?,
    }))
}

async fn put_user(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((id, name)): Path<(String, String)>,
    Json(body): Json<PutSecretBody>,
) -> Result<Json<AgentSecretView>, (StatusCode, String)> {
    let instance = state
        .instances
        .get(&caller.user_id, &id)
        .await
        .map_err(instance_err_to_response)?;
    let meta = state
        .agent_secrets
        .put(
            &instance.owner_id,
            &instance.id,
            &name,
            body.value.as_bytes(),
            AgentSecretActor::user(&caller.user_id),
        )
        .await
        .map_err(agent_secret_err_to_response)?;
    Ok(Json(AgentSecretView::from(meta)))
}

async fn delete_user(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((id, name)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let instance = state
        .instances
        .get(&caller.user_id, &id)
        .await
        .map_err(instance_err_to_response)?;
    state
        .agent_secrets
        .delete(
            &instance.owner_id,
            &instance.id,
            &name,
            AgentSecretActor::user(&caller.user_id),
        )
        .await
        .map_err(agent_secret_err_to_response)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AgentSecretView>>, (StatusCode, String)> {
    let instance = resolve_internal_instance_from_headers(&state, &headers).await?;
    let rows = state
        .agent_secrets
        .list(
            &instance.owner_id,
            &instance.id,
            AgentSecretActor::agent(&instance.id),
        )
        .await
        .map_err(agent_secret_err_to_response)?;
    Ok(Json(rows.into_iter().map(AgentSecretView::from).collect()))
}

async fn get_internal(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AgentSecretValue>, (StatusCode, String)> {
    let instance = resolve_internal_instance_from_headers(&state, &headers).await?;
    let value = state
        .agent_secrets
        .get(
            &instance.owner_id,
            &instance.id,
            &name,
            AgentSecretActor::agent(&instance.id),
        )
        .await
        .map_err(agent_secret_err_to_response)?
        .ok_or((StatusCode::NOT_FOUND, "secret not found".to_owned()))?;
    Ok(Json(AgentSecretValue {
        name,
        value: String::from_utf8(value).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "secret is not utf-8".to_owned(),
            )
        })?,
    }))
}

async fn put_internal(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PutSecretBody>,
) -> Result<Json<AgentSecretView>, (StatusCode, String)> {
    let instance = resolve_internal_instance_from_headers(&state, &headers).await?;
    let meta = state
        .agent_secrets
        .put(
            &instance.owner_id,
            &instance.id,
            &name,
            body.value.as_bytes(),
            AgentSecretActor::agent(&instance.id),
        )
        .await
        .map_err(agent_secret_err_to_response)?;
    Ok(Json(AgentSecretView::from(meta)))
}

async fn delete_internal(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let instance = resolve_internal_instance_from_headers(&state, &headers).await?;
    state
        .agent_secrets
        .delete(
            &instance.owner_id,
            &instance.id,
            &name,
            AgentSecretActor::agent(&instance.id),
        )
        .await
        .map_err(agent_secret_err_to_response)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn resolve_internal_instance_from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<crate::traits::InstanceRow, (StatusCode, String)> {
    let token =
        extract_bearer(headers).ok_or((StatusCode::UNAUTHORIZED, "missing bearer".to_owned()))?;
    let record = match state.tokens.resolve(&token).await {
        Ok(Some(r)) if r.revoked_at.is_none() => r,
        Ok(_) => return Err((StatusCode::UNAUTHORIZED, "invalid bearer".to_owned())),
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "token store error".to_owned(),
            ));
        }
    };
    if record.provider != SHARED_PROVIDER {
        return Err((StatusCode::UNAUTHORIZED, "invalid bearer".to_owned()));
    }
    state
        .instances
        .get_unscoped(&record.instance_id)
        .await
        .map_err(instance_err_to_response)
}

fn instance_err_to_response(err: crate::error::SwarmError) -> (StatusCode, String) {
    match err {
        crate::error::SwarmError::NotFound => (StatusCode::NOT_FOUND, "instance not found".into()),
        crate::error::SwarmError::BadRequest(e) => (StatusCode::BAD_REQUEST, e),
        crate::error::SwarmError::PolicyDenied(e) => (StatusCode::BAD_REQUEST, e),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

fn agent_secret_err_to_response(err: AgentSecretError) -> (StatusCode, String) {
    match err {
        AgentSecretError::InvalidName => (
            StatusCode::BAD_REQUEST,
            "secret name must be 1-128 chars and use letters, numbers, dot, dash, or underscore"
                .into(),
        ),
        AgentSecretError::NotFound => (StatusCode::NOT_FOUND, "secret not found".into()),
        AgentSecretError::Store(crate::error::StoreError::NotFound) => {
            (StatusCode::NOT_FOUND, "secret not found".into())
        }
        AgentSecretError::Store(_) | AgentSecretError::Envelope(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "agent secret store error".into(),
        ),
    }
}
