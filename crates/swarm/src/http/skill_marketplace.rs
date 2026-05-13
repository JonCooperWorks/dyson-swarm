//! Skill marketplace catalog routes.

use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::Deserialize;

use crate::auth::CallerIdentity;
use crate::error::SwarmError;
use crate::http::AppState;
use crate::skill_marketplace::{
    CatalogError, CatalogListing, CatalogSkill, CatalogSkillAuthor, SkillMarketplaceError,
    SkillMarketplaceSourceConfig, SkillMarketplaceSourceView, SkillPackageBody, SkillPackageDetail,
    skill_body_preview, skill_body_sha256, validate_skill_body, validate_skill_name,
};
use crate::traits::{InstanceRow, InstanceStatus, ListFilter};

const STATE_TOKEN_PREFIX: &str = "st_";
const AGENT_MARKETPLACE_PREFIX: &str = "agent-";

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/skill-marketplaces", get(list_sources))
        .route("/v1/skill-marketplaces/skills", get(list_skills))
        .route(
            "/v1/skill-marketplaces/:marketplace/skills/:skill",
            get(skill_detail),
        )
        .route(
            "/v1/skill-marketplaces/:marketplace/skills/:skill/content",
            get(skill_content),
        )
        .with_state(state)
}

pub fn internal_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/internal/skill-marketplaces",
            get(internal_list_sources),
        )
        .route(
            "/v1/internal/skill-marketplaces/skills",
            get(internal_list_skills),
        )
        .route(
            "/v1/internal/skill-marketplaces/:marketplace/skills/:skill",
            get(internal_skill_detail),
        )
        .route(
            "/v1/internal/skill-marketplaces/:marketplace/skills/:skill/content",
            get(internal_skill_content),
        )
        .with_state(state)
}

pub fn admin_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/skill-marketplaces", get(admin_list_sources))
        .route(
            "/v1/admin/skill-marketplaces/:marketplace",
            put(admin_put_source).delete(admin_delete_source),
        )
        .with_state(state)
}

async fn list_sources(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
) -> impl IntoResponse {
    match source_views_for_owner(&state, &caller.user_id).await {
        Ok(sources) => Json(serde_json::json!({ "sources": sources })).into_response(),
        Err(err) => error_response(err),
    }
}

async fn list_skills(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
) -> impl IntoResponse {
    Json(catalog_for_owner(&state, &caller.user_id).await)
}

async fn skill_detail(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((marketplace, skill)): Path<(String, String)>,
) -> impl IntoResponse {
    if is_agent_marketplace(&marketplace) {
        return json_result(
            agent_skill_detail(&state, &caller.user_id, &marketplace, &skill).await,
        );
    }
    json_result(state.skill_marketplace.detail(&marketplace, &skill).await)
}

async fn skill_content(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((marketplace, skill)): Path<(String, String)>,
) -> impl IntoResponse {
    json_result(skill_content_for_owner(&state, &caller.user_id, &marketplace, &skill).await)
}

pub(crate) async fn skill_content_for_owner(
    state: &AppState,
    owner_id: &str,
    marketplace: &str,
    skill: &str,
) -> Result<SkillPackageBody, SkillMarketplaceError> {
    if is_agent_marketplace(marketplace) {
        return agent_skill_content(state, owner_id, marketplace, skill).await;
    }
    state.skill_marketplace.content(marketplace, skill).await
}

async fn internal_list_sources(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match authorize_state_token_owner(&state, &headers).await {
        Ok(owner_id) => match source_views_for_owner(&state, &owner_id).await {
            Ok(sources) => Json(serde_json::json!({ "sources": sources })).into_response(),
            Err(err) => error_response(err),
        },
        Err(status) => status.into_response(),
    }
}

async fn internal_list_skills(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match authorize_state_token_owner(&state, &headers).await {
        Ok(owner_id) => Json(catalog_for_owner(&state, &owner_id).await).into_response(),
        Err(status) => status.into_response(),
    }
}

async fn internal_skill_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((marketplace, skill)): Path<(String, String)>,
) -> impl IntoResponse {
    match authorize_state_token_owner(&state, &headers).await {
        Ok(owner_id) if is_agent_marketplace(&marketplace) => {
            json_result(agent_skill_detail(&state, &owner_id, &marketplace, &skill).await)
        }
        Ok(_) => json_result(state.skill_marketplace.detail(&marketplace, &skill).await),
        Err(status) => status.into_response(),
    }
}

async fn internal_skill_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((marketplace, skill)): Path<(String, String)>,
) -> impl IntoResponse {
    match authorize_state_token_owner(&state, &headers).await {
        Ok(owner_id) => {
            json_result(skill_content_for_owner(&state, &owner_id, &marketplace, &skill).await)
        }
        Err(status) => status.into_response(),
    }
}

async fn authorize_state_token_owner(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, StatusCode> {
    let bearer = match extract_bearer(headers) {
        Some(b) if b.starts_with(STATE_TOKEN_PREFIX) => b.to_owned(),
        _ => return Err(StatusCode::UNAUTHORIZED),
    };
    let token_record = match state.tokens.resolve(&bearer).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED),
        Err(e) => {
            tracing::warn!(error = %e, "skill marketplace: token resolve failed");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let instance = match state
        .instances
        .get_unscoped(&token_record.instance_id)
        .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!(
                error = %e,
                instance = %token_record.instance_id,
                "skill marketplace: token instance lookup failed"
            );
            return Err(super::instances::swarm_err_to_status(e));
        }
    };
    if !crate::db::state_sync_provider_matches(&token_record.provider, &instance.state_generation) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(instance.owner_id)
}

async fn source_views_for_owner(
    state: &AppState,
    owner_id: &str,
) -> Result<Vec<SkillMarketplaceSourceView>, SkillMarketplaceError> {
    let mut sources = state.skill_marketplace.source_views().await?;
    let instances = live_instances_for_owner(state, owner_id)
        .await
        .map_err(|status| {
            SkillMarketplaceError::Store(format!("agent skill scan failed: {status}"))
        })?;
    sources.extend(agent_source_views(state, &instances).await);
    Ok(sources)
}

async fn catalog_for_owner(state: &AppState, owner_id: &str) -> CatalogListing {
    let mut listing = state.skill_marketplace.catalog().await;
    match live_instances_for_owner(state, owner_id).await {
        Ok(instances) => {
            let agent_catalog = agent_catalog(state, &instances).await;
            listing.sources.extend(agent_catalog.sources);
            listing.skills.extend(agent_catalog.skills);
            listing.errors.extend(agent_catalog.errors);
            listing.skills.sort_by(|a, b| {
                a.name
                    .cmp(&b.name)
                    .then_with(|| a.marketplace_id.cmp(&b.marketplace_id))
            });
        }
        Err(status) => listing.errors.push(CatalogError {
            marketplace_id: "agent-skills".into(),
            error: format!("agent skill scan failed: {status}"),
        }),
    }
    listing
}

async fn live_instances_for_owner(
    state: &AppState,
    owner_id: &str,
) -> Result<Vec<InstanceRow>, StatusCode> {
    state
        .instances
        .list(
            owner_id,
            ListFilter {
                status: Some(InstanceStatus::Live),
                include_destroyed: false,
            },
        )
        .await
        .map_err(super::instances::swarm_err_to_status)
}

struct AgentCatalog {
    sources: Vec<SkillMarketplaceSourceView>,
    skills: Vec<CatalogSkill>,
    errors: Vec<CatalogError>,
}

async fn agent_catalog(state: &AppState, instances: &[InstanceRow]) -> AgentCatalog {
    let mut sources = Vec::new();
    let mut skills = Vec::new();
    let mut errors = Vec::new();
    for instance in instances {
        let marketplace_id = agent_marketplace_id(&instance.id);
        let rows = match crate::skill_inventory::list_instance_skills(
            state.state_files.as_ref(),
            &instance.id,
        )
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    instance = %instance.id,
                    "skill marketplace: agent skill inventory failed"
                );
                errors.push(CatalogError {
                    marketplace_id,
                    error: e.to_string(),
                });
                continue;
            }
        };

        let mut added_source = false;
        for row in rows {
            if !is_agent_created_skill(&row) {
                continue;
            }
            if !added_source {
                sources.push(agent_source_view(instance));
                added_source = true;
            }
            match agent_catalog_skill(instance, &row) {
                Ok(skill) => skills.push(skill),
                Err(e) => errors.push(CatalogError {
                    marketplace_id: agent_marketplace_id(&instance.id),
                    error: e.to_string(),
                }),
            }
        }
    }
    AgentCatalog {
        sources,
        skills,
        errors,
    }
}

async fn agent_source_views(
    state: &AppState,
    instances: &[InstanceRow],
) -> Vec<SkillMarketplaceSourceView> {
    let mut sources = Vec::new();
    for instance in instances {
        match crate::skill_inventory::list_instance_skills(state.state_files.as_ref(), &instance.id)
            .await
        {
            Ok(rows) if rows.iter().any(is_agent_created_skill) => {
                sources.push(agent_source_view(instance));
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    instance = %instance.id,
                    "skill marketplace: agent skill source scan failed"
                );
            }
        }
    }
    sources
}

fn is_agent_created_skill(row: &crate::skill_inventory::SkillInventoryEntry) -> bool {
    row.has_body
        && (row.origin_kind != "marketplace"
            || row
                .marketplace_id
                .as_deref()
                .is_some_and(is_agent_marketplace))
}

fn agent_catalog_skill(
    instance: &InstanceRow,
    row: &crate::skill_inventory::SkillInventoryEntry,
) -> Result<CatalogSkill, SkillMarketplaceError> {
    validate_skill_name(&row.skill)?;
    let author = agent_author(instance);
    Ok(CatalogSkill {
        marketplace_id: agent_marketplace_id(&instance.id),
        marketplace_name: format!("{} skills", author.name),
        name: row.skill.clone(),
        version: row.version.clone().unwrap_or_else(|| "0.1.0".into()),
        description: if row.description.trim().is_empty() {
            format!("Skill learned by {}.", author.name)
        } else {
            row.description.clone()
        },
        tags: agent_skill_tags(&row.origin_kind),
        license: None,
        min_dyson_version: None,
        sha256: None,
        content_type: "workspace".into(),
        author: Some(author),
    })
}

fn agent_skill_tags(origin_kind: &str) -> Vec<String> {
    let mut tags = vec!["agent-created".to_owned()];
    if !origin_kind.trim().is_empty() && origin_kind != "local" {
        tags.push(origin_kind.to_owned());
    }
    tags
}

async fn agent_skill_detail(
    state: &AppState,
    owner_id: &str,
    marketplace: &str,
    skill: &str,
) -> Result<SkillPackageDetail, SkillMarketplaceError> {
    let (skill, body) = load_agent_skill(state, owner_id, marketplace, skill).await?;
    Ok(SkillPackageDetail {
        skill,
        preview: skill_body_preview(&body),
        computed_sha256: skill_body_sha256(&body),
    })
}

async fn agent_skill_content(
    state: &AppState,
    owner_id: &str,
    marketplace: &str,
    skill: &str,
) -> Result<SkillPackageBody, SkillMarketplaceError> {
    let (skill, body) = load_agent_skill(state, owner_id, marketplace, skill).await?;
    let computed_sha256 = skill_body_sha256(&body);
    Ok(SkillPackageBody {
        marketplace_id: skill.marketplace_id,
        marketplace_name: skill.marketplace_name,
        name: skill.name,
        version: skill.version,
        description: skill.description,
        declared_sha256: None,
        computed_sha256,
        skill_md: body,
    })
}

async fn load_agent_skill(
    state: &AppState,
    owner_id: &str,
    marketplace: &str,
    skill: &str,
) -> Result<(CatalogSkill, String), SkillMarketplaceError> {
    let instance_id = agent_marketplace_instance_id(marketplace)
        .ok_or_else(|| SkillMarketplaceError::MarketplaceNotFound(marketplace.to_owned()))?;
    validate_skill_name(skill)?;
    let instance = state
        .instances
        .get(owner_id, instance_id)
        .await
        .map_err(|e| skill_marketplace_error_for_instance_lookup(e, marketplace))?;
    if !matches!(instance.status, InstanceStatus::Live) {
        return Err(SkillMarketplaceError::MarketplaceNotFound(
            marketplace.to_owned(),
        ));
    }
    let rows =
        crate::skill_inventory::list_instance_skills(state.state_files.as_ref(), &instance.id)
            .await
            .map_err(|e| SkillMarketplaceError::Store(e.to_string()))?;
    let row = rows
        .into_iter()
        .find(|row| row.skill == skill && is_agent_created_skill(row))
        .ok_or_else(|| SkillMarketplaceError::SkillNotFound {
            marketplace: marketplace.to_owned(),
            skill: skill.to_owned(),
        })?;
    let body = crate::skill_inventory::read_instance_skill_body(
        state.state_files.as_ref(),
        &instance.id,
        skill,
    )
    .await
    .map_err(|e| SkillMarketplaceError::Store(e.to_string()))?
    .ok_or_else(|| SkillMarketplaceError::SkillNotFound {
        marketplace: marketplace.to_owned(),
        skill: skill.to_owned(),
    })?;
    validate_skill_body(&body)?;
    Ok((agent_catalog_skill(&instance, &row)?, body))
}

fn skill_marketplace_error_for_instance_lookup(
    err: SwarmError,
    marketplace: &str,
) -> SkillMarketplaceError {
    match err {
        SwarmError::NotFound => SkillMarketplaceError::MarketplaceNotFound(marketplace.to_owned()),
        other => SkillMarketplaceError::Store(other.to_string()),
    }
}

fn agent_source_view(instance: &InstanceRow) -> SkillMarketplaceSourceView {
    SkillMarketplaceSourceView {
        id: agent_marketplace_id(&instance.id),
        source_type: "agent".into(),
        location: format!("swarm://instances/{}/skills", instance.id),
        is_default: false,
    }
}

fn agent_author(instance: &InstanceRow) -> CatalogSkillAuthor {
    let name = agent_display_name(instance);
    CatalogSkillAuthor {
        name,
        instance_id: instance.id.clone(),
        href: format!("#/i/{}/skills", instance.id),
    }
}

fn agent_display_name(instance: &InstanceRow) -> String {
    let name = instance.name.trim();
    if name.is_empty() {
        instance.id.clone()
    } else {
        name.to_owned()
    }
}

fn agent_marketplace_id(instance_id: &str) -> String {
    format!("{AGENT_MARKETPLACE_PREFIX}{instance_id}")
}

fn is_agent_marketplace(marketplace: &str) -> bool {
    agent_marketplace_instance_id(marketplace).is_some()
}

fn agent_marketplace_instance_id(marketplace: &str) -> Option<&str> {
    marketplace
        .strip_prefix(AGENT_MARKETPLACE_PREFIX)
        .filter(|id| !id.is_empty())
}

#[derive(Deserialize)]
struct AdminPutSkillMarketplaceSourceBody {
    source_type: String,
    location: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_enabled() -> bool {
    true
}

async fn admin_list_sources(State(state): State<AppState>) -> impl IntoResponse {
    match state.skill_marketplace.admin_source_views().await {
        Ok(sources) => Json(serde_json::json!({ "sources": sources })).into_response(),
        Err(err) => error_response(err),
    }
}

async fn admin_put_source(
    State(state): State<AppState>,
    Path(marketplace): Path<String>,
    Json(body): Json<AdminPutSkillMarketplaceSourceBody>,
) -> impl IntoResponse {
    let enabled = body.enabled;
    let source = match source_from_admin_body(marketplace, body) {
        Ok(source) => source,
        Err(err) => return error_response(err),
    };
    match state.skill_marketplace.upsert_source(source, enabled).await {
        Ok(source) => Json(source).into_response(),
        Err(err) => error_response(err),
    }
}

async fn admin_delete_source(
    State(state): State<AppState>,
    Path(marketplace): Path<String>,
) -> impl IntoResponse {
    match state.skill_marketplace.delete_source(&marketplace).await {
        Ok(deleted) => Json(serde_json::json!({ "ok": true, "deleted": deleted })).into_response(),
        Err(err) => error_response(err),
    }
}

fn source_from_admin_body(
    id: String,
    body: AdminPutSkillMarketplaceSourceBody,
) -> Result<SkillMarketplaceSourceConfig, SkillMarketplaceError> {
    let source = match body.source_type.trim().to_ascii_lowercase().as_str() {
        "inline" => SkillMarketplaceSourceConfig::Inline {
            id,
            index_json: body.location,
        },
        "http" => SkillMarketplaceSourceConfig::Http {
            id,
            url: body.location,
        },
        "file" => {
            return Err(SkillMarketplaceError::Invalid(
                "file marketplace sources removed for safety; use type: inline".into(),
            ));
        }
        other => {
            return Err(SkillMarketplaceError::Invalid(format!(
                "unsupported marketplace source_type {other:?}"
            )));
        }
    };
    crate::skill_marketplace::validate_marketplace_source_config(&source)?;
    Ok(source)
}

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim();
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn json_result<T: serde::Serialize>(
    result: Result<T, SkillMarketplaceError>,
) -> axum::response::Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(err) => error_response(err),
    }
}

fn error_response(err: SkillMarketplaceError) -> axum::response::Response {
    (
        status_for_error(&err),
        Json(serde_json::json!({ "error": err.to_string() })),
    )
        .into_response()
}

fn status_for_error(err: &SkillMarketplaceError) -> StatusCode {
    match err {
        SkillMarketplaceError::MarketplaceNotFound(_)
        | SkillMarketplaceError::SkillNotFound { .. } => StatusCode::NOT_FOUND,
        SkillMarketplaceError::Invalid(_) => StatusCode::BAD_REQUEST,
        SkillMarketplaceError::Io(_) | SkillMarketplaceError::Http(_) => StatusCode::BAD_GATEWAY,
        SkillMarketplaceError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_policy::NetworkPolicy;

    fn instance() -> InstanceRow {
        InstanceRow {
            id: "axelrod".into(),
            owner_id: "u1".into(),
            name: "Axelrod".into(),
            task: String::new(),
            cube_sandbox_id: None,
            state_generation: String::new(),
            template_id: "t".into(),
            status: InstanceStatus::Live,
            bearer_token: String::new(),
            pinned: false,
            expires_at: None,
            last_active_at: 0,
            last_probe_at: None,
            last_probe_status: None,
            created_at: 0,
            destroyed_at: None,
            rotated_to: None,
            network_policy: NetworkPolicy::default(),
            network_policy_cidrs: Vec::new(),
            models: Vec::new(),
            tools: Vec::new(),
        }
    }

    fn skill(origin_kind: &str) -> crate::skill_inventory::SkillInventoryEntry {
        crate::skill_inventory::SkillInventoryEntry {
            instance_id: "axelrod".into(),
            skill: "debug-logs".into(),
            description: "Read logs before guessing.".into(),
            origin_kind: origin_kind.into(),
            marketplace_id: None,
            version: None,
            installed_at: None,
            updated_at: 1,
            synced_at: 2,
            has_body: true,
            has_metadata: false,
            source_path: "workspace/skills/debug-logs/SKILL.md".into(),
        }
    }

    #[test]
    fn agent_created_skill_projects_to_attributed_catalog_entry() {
        let catalog = agent_catalog_skill(&instance(), &skill("learned")).unwrap();

        assert_eq!(catalog.marketplace_id, "agent-axelrod");
        assert_eq!(catalog.marketplace_name, "Axelrod skills");
        assert_eq!(catalog.name, "debug-logs");
        assert_eq!(catalog.version, "0.1.0");
        assert_eq!(catalog.content_type, "workspace");
        assert_eq!(catalog.tags, vec!["agent-created", "learned"]);
        assert_eq!(
            catalog.author,
            Some(CatalogSkillAuthor {
                name: "Axelrod".into(),
                instance_id: "axelrod".into(),
                href: "#/i/axelrod/skills".into(),
            })
        );
    }

    #[test]
    fn installed_marketplace_skills_are_not_republished_as_agent_created() {
        assert!(!is_agent_created_skill(&skill("marketplace")));
        let mut marketplace = skill("marketplace");
        marketplace.marketplace_id = Some("official".into());
        assert!(!is_agent_created_skill(&marketplace));
        assert!(is_agent_created_skill(&skill("local")));
    }

    #[test]
    fn agent_backed_marketplace_skills_remain_catalog_visible_after_restore() {
        let mut row = skill("marketplace");
        row.marketplace_id = Some("agent-axelrod".into());

        assert!(is_agent_created_skill(&row));
    }

    #[test]
    fn admin_body_rejects_file_marketplace_source_type() {
        let err = source_from_admin_body(
            "local".into(),
            AdminPutSkillMarketplaceSourceBody {
                source_type: "file".into(),
                location: "/etc/passwd".into(),
                enabled: true,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("file marketplace sources removed"));
    }
}
