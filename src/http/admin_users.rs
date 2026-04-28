//! Admin-only user management. Mounted under `/v1/admin/*` so the
//! admin-role middleware gates these calls.
//!
//! - `GET    /v1/admin/users` — list all users (auto-created + provisioned)
//! - `POST   /v1/admin/users/:id/activate` — flip status to `active`
//! - `POST   /v1/admin/users/:id/suspend` — flip status to `suspended`,
//!                                          revoke OR key upstream
//! - `POST   /v1/admin/users/:id/keys` — mint an opaque bearer for the user
//! - `DELETE /v1/admin/users/keys/:token` — revoke an api key by value
//! - `PATCH  /v1/admin/users/:id/openrouter_limit` — set OR USD cap
//! - `POST   /v1/admin/users/:id/openrouter_key/mint` — force a fresh
//!                                                     mint, returns the
//!                                                     plaintext once

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::http::{secrets::store_err_to_status, AppState};
use crate::openrouter::USER_OR_KEY_SECRET_NAME;
use crate::traits::{UserRow, UserStatus};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/users", get(list_users).post(create_user))
        .route("/v1/admin/users/:id/activate", post(activate))
        .route("/v1/admin/users/:id/suspend", post(suspend))
        .route("/v1/admin/users/:id/keys", post(mint_key))
        .route("/v1/admin/users/keys/:token", delete(revoke_key))
        .route("/v1/admin/users/:id/openrouter_limit", patch(set_or_limit))
        .route("/v1/admin/users/:id/openrouter_key/mint", post(force_mint_or_key))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct CreateUserBody {
    /// Stable identity string. With OIDC this is the `sub` claim; for
    /// admin-bootstrapped users it can be anything unique (e.g. an
    /// email or a label).
    subject: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    /// Skip the inactive->active step when true. Equivalent to posting
    /// `/v1/admin/users/:id/activate` immediately after.
    #[serde(default)]
    activate: bool,
}

async fn create_user(
    State(state): State<AppState>,
    Json(body): Json<CreateUserBody>,
) -> Result<(StatusCode, Json<UserView>), StatusCode> {
    let now = crate::now_secs();
    let initial_status = if body.activate {
        UserStatus::Active
    } else {
        UserStatus::Inactive
    };
    let row = UserRow {
        id: uuid::Uuid::new_v4().simple().to_string(),
        subject: body.subject,
        email: body.email,
        display_name: body.display_name,
        status: initial_status,
        created_at: now,
        activated_at: if body.activate { Some(now) } else { None },
        last_seen_at: None,
        openrouter_key_id: None,
        openrouter_key_limit_usd: 10.0,
    };
    match state.users.create(row.clone()).await {
        Ok(()) => Ok((StatusCode::CREATED, Json(UserView::from(row)))),
        Err(e) => Err(store_err_to_status(e)),
    }
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
    /// True when warden has minted an OR key for this user.  We don't
    /// surface the id itself — operators don't need it, and exposing
    /// it through the SPA's admin pane would invite copy-paste leaks.
    pub openrouter_key_present: bool,
    pub openrouter_key_limit_usd: f64,
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
            openrouter_key_present: r.openrouter_key_id.is_some(),
            openrouter_key_limit_usd: r.openrouter_key_limit_usd,
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
    // Stage 6.5: revoke the user's OpenRouter key upstream BEFORE
    // flipping local status, so a leaked plaintext stops accruing
    // charges even if the local DB write fails.  Best-effort — we
    // log on failure and continue, since suspending a tenant whose
    // key is already gone (manual rotation, OR-side revoke) shouldn't
    // be blocked by the upstream call.
    if let Some(prov) = state.openrouter_provisioning.as_ref() {
        if let Ok(Some(user)) = state.users.get(&id).await
            && let Some(key_id) = user.openrouter_key_id.as_deref()
        {
            if let Err(err) = prov.delete(key_id).await {
                tracing::warn!(
                    error = %err,
                    user = %id,
                    or_key_id = %key_id,
                    "suspend: openrouter delete failed; continuing"
                );
            }
            // Wipe the local plaintext + id regardless of upstream
            // outcome.  If upstream still has the key, the operator
            // can reconcile via the OR dashboard.
            let _ = state.user_secrets.delete(&id, USER_OR_KEY_SECRET_NAME).await;
            let _ = state.users.set_openrouter_key_id(&id, None).await;
        }
    }
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

#[derive(Debug, Deserialize)]
struct SetLimitBody {
    /// New USD spend cap on the user's OR key.  Mirrored upstream
    /// when the user already has a key minted; otherwise just
    /// persisted (next lazy mint will use it).
    limit_usd: f64,
}

async fn set_or_limit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<SetLimitBody>,
) -> StatusCode {
    if !body.limit_usd.is_finite() || body.limit_usd < 0.0 {
        return StatusCode::BAD_REQUEST;
    }
    let user = match state.users.get(&id).await {
        Ok(Some(u)) => u,
        Ok(None) => return StatusCode::NOT_FOUND,
        Err(e) => return store_err_to_status(e),
    };
    if let Err(e) = state.users.set_openrouter_limit(&id, body.limit_usd).await {
        return store_err_to_status(e);
    }
    if let (Some(prov), Some(key_id)) = (
        state.openrouter_provisioning.as_ref(),
        user.openrouter_key_id.as_deref(),
    ) {
        if let Err(err) = prov.update_limit(key_id, body.limit_usd).await {
            tracing::warn!(
                error = %err,
                user = %id,
                or_key_id = %key_id,
                "set_or_limit: openrouter PATCH failed; local row is updated"
            );
            // Don't fail the request — the local view is the source
            // of truth and the next mint/rotate will reconcile.
        }
    }
    StatusCode::NO_CONTENT
}

#[derive(Debug, Serialize)]
struct ForceMintResp {
    /// Plaintext key.  Surfaced once; the next call to this endpoint
    /// returns a different value because the previous one is wiped
    /// upstream.
    token: String,
    or_key_id: String,
}

async fn force_mint_or_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<ForceMintResp>), StatusCode> {
    let resolver = state
        .user_or_keys
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    // Force a fresh mint by clearing the existing one (if any) first,
    // so the lazy-mint path picks "new key needed".  Upstream revoke
    // is best-effort.
    let user = match state.users.get(&id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => return Err(store_err_to_status(e)),
    };
    if let (Some(prov), Some(old_id)) = (
        state.openrouter_provisioning.as_ref(),
        user.openrouter_key_id.as_deref(),
    ) {
        let _ = prov.delete(old_id).await;
        let _ = state.user_secrets.delete(&id, USER_OR_KEY_SECRET_NAME).await;
        let _ = state.users.set_openrouter_key_id(&id, None).await;
    }
    let plaintext = resolver
        .resolve_plaintext(&id)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, user = %id, "force mint OR key failed");
            StatusCode::BAD_GATEWAY
        })?;
    // Re-read so we surface the new id.
    let new_id = match state.users.get(&id).await {
        Ok(Some(u)) => u.openrouter_key_id.unwrap_or_default(),
        _ => String::new(),
    };
    Ok((
        StatusCode::CREATED,
        Json(ForceMintResp { token: plaintext, or_key_id: new_id }),
    ))
}
