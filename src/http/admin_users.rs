//! Admin-only user management. Mounted under `/v1/admin/*` so the
//! admin-bearer middleware gates these calls.
//!
//! - `GET    /v1/admin/users` — list all users (auto-created + provisioned)
//! - `POST   /v1/admin/users/:id/activate` — flip status to `active`
//! - `POST   /v1/admin/users/:id/suspend` — flip status to `suspended`
//! - `POST   /v1/admin/users/:id/keys` — mint an opaque bearer for the user
//! - `DELETE /v1/admin/users/keys/:token` — revoke an api key by value

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::http::{secrets::store_err_to_status, AppState};
use crate::traits::{UserRow, UserStatus};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/users", get(list_users))
        .route("/v1/admin/users/:id/activate", post(activate))
        .route("/v1/admin/users/:id/suspend", post(suspend))
        .route("/v1/admin/users/:id/keys", post(mint_key))
        .route("/v1/admin/users/keys/:token", delete(revoke_key))
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub status: String,
    pub created_at: i64,
    pub activated_at: Option<i64>,
    pub last_seen_at: Option<i64>,
}

impl From<UserRow> for UserView {
    fn from(r: UserRow) -> Self {
        Self {
            id: r.id,
            subject: r.subject,
            email: r.email,
            display_name: r.display_name,
            status: r.status.as_str().into(),
            created_at: r.created_at,
            activated_at: r.activated_at,
            last_seen_at: r.last_seen_at,
        }
    }
}

async fn list_users(State(state): State<AppState>) -> Result<Json<Vec<UserView>>, StatusCode> {
    match state.users.list().await {
        Ok(rows) => Ok(Json(rows.into_iter().map(UserView::from).collect())),
        Err(e) => Err(store_err_to_status(e)),
    }
}

async fn activate(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> StatusCode {
    match state.users.set_status(&id, UserStatus::Active).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => store_err_to_status(e),
    }
}

async fn suspend(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> StatusCode {
    match state.users.set_status(&id, UserStatus::Suspended).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => store_err_to_status(e),
    }
}

#[derive(Debug, Deserialize)]
struct MintKeyBody {
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Serialize)]
struct MintKeyResp {
    token: String,
}

async fn mint_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<MintKeyBody>,
) -> Result<(StatusCode, Json<MintKeyResp>), StatusCode> {
    match state
        .users
        .mint_api_key(&id, body.label.as_deref())
        .await
    {
        Ok(token) => Ok((StatusCode::CREATED, Json(MintKeyResp { token }))),
        Err(e) => Err(store_err_to_status(e)),
    }
}

async fn revoke_key(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> StatusCode {
    match state.users.revoke_api_key(&token).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => store_err_to_status(e),
    }
}
