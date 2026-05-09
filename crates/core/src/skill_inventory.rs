//! Derived skill inventory from mirrored Dyson workspace files.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::db::state_files::StateFileRow;
use crate::state_files::{StateFileError, StateFileService};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SkillInventoryEntry {
    pub instance_id: String,
    pub skill: String,
    pub description: String,
    pub origin_kind: String,
    pub marketplace_id: Option<String>,
    pub version: Option<String>,
    pub installed_at: Option<String>,
    pub updated_at: i64,
    pub synced_at: i64,
    pub has_body: bool,
    pub has_metadata: bool,
    pub source_path: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SkillInventoryError {
    #[error(transparent)]
    StateFile(#[from] StateFileError),
}

#[derive(Default)]
struct SkillParts {
    body_row: Option<StateFileRow>,
    metadata_row: Option<StateFileRow>,
}

#[derive(Debug, Deserialize)]
struct InstalledSkillMetadata {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    installed_at: Option<String>,
    #[serde(default)]
    origin: Option<InstalledSkillOrigin>,
}

#[derive(Debug, Deserialize)]
struct InstalledSkillOrigin {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    marketplace_id: Option<String>,
}

pub async fn list_instance_skills(
    state_files: &StateFileService,
    instance_id: &str,
) -> Result<Vec<SkillInventoryEntry>, SkillInventoryError> {
    let rows = state_files.list_for_instance(instance_id).await?;
    let mut grouped: BTreeMap<String, SkillParts> = BTreeMap::new();
    for row in rows {
        if row.namespace != "workspace" {
            continue;
        }
        let Some((skill, kind)) = classify_skill_path(&row.path) else {
            continue;
        };
        let parts = grouped.entry(skill.to_owned()).or_default();
        match kind {
            SkillFileKind::Body => parts.body_row = Some(row),
            SkillFileKind::Metadata => parts.metadata_row = Some(row),
        }
    }

    let mut out = Vec::new();
    for (skill, parts) in grouped {
        let body = read_utf8(state_files, parts.body_row.as_ref()).await?;
        let metadata_body = read_utf8(state_files, parts.metadata_row.as_ref()).await?;
        let metadata = metadata_body
            .as_deref()
            .and_then(|body| serde_json::from_str::<InstalledSkillMetadata>(body).ok());
        let has_body = body.is_some();
        let has_metadata = metadata_body.is_some();

        if !has_body && !has_metadata {
            continue;
        }

        let description = metadata
            .as_ref()
            .and_then(|m| m.description.clone())
            .filter(|s| !s.trim().is_empty())
            .or_else(|| body.as_deref().and_then(skill_description))
            .unwrap_or_default();
        let origin_kind = if has_body {
            metadata
                .as_ref()
                .and_then(|m| m.origin.as_ref())
                .and_then(|o| o.kind.clone())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "local".to_owned())
        } else {
            "unknown".to_owned()
        };
        let marketplace_id = metadata
            .as_ref()
            .and_then(|m| m.origin.as_ref())
            .and_then(|o| o.marketplace_id.clone())
            .filter(|s| !s.trim().is_empty());
        let version = metadata
            .as_ref()
            .and_then(|m| m.version.clone())
            .filter(|s| !s.trim().is_empty());
        let installed_at = metadata
            .as_ref()
            .and_then(|m| m.installed_at.clone())
            .filter(|s| !s.trim().is_empty());
        let updated_at = parts
            .body_row
            .as_ref()
            .map(|r| r.updated_at)
            .into_iter()
            .chain(parts.metadata_row.as_ref().map(|r| r.updated_at))
            .max()
            .unwrap_or_default();
        let synced_at = parts
            .body_row
            .as_ref()
            .map(|r| r.synced_at)
            .into_iter()
            .chain(parts.metadata_row.as_ref().map(|r| r.synced_at))
            .max()
            .unwrap_or_default();
        out.push(SkillInventoryEntry {
            instance_id: instance_id.to_owned(),
            skill: skill.clone(),
            description,
            origin_kind,
            marketplace_id,
            version,
            installed_at,
            updated_at,
            synced_at,
            has_body,
            has_metadata,
            source_path: format!("workspace/skills/{skill}/SKILL.md"),
        });
    }
    Ok(out)
}

pub async fn read_instance_skill_body(
    state_files: &StateFileService,
    instance_id: &str,
    skill: &str,
) -> Result<Option<String>, SkillInventoryError> {
    let body_path = format!("skills/{skill}/SKILL.md");
    if classify_skill_path(&body_path).is_none() {
        return Ok(None);
    }
    let rows = state_files.list_for_instance(instance_id).await?;
    let row = rows
        .iter()
        .find(|row| row.namespace == "workspace" && row.path == body_path);
    read_utf8(state_files, row).await
}

enum SkillFileKind {
    Body,
    Metadata,
}

fn classify_skill_path(path: &str) -> Option<(&str, SkillFileKind)> {
    let mut parts = path.split('/');
    if parts.next()? != "skills" {
        return None;
    }
    let skill = parts.next()?;
    if skill.is_empty() || skill.starts_with('.') || skill.contains("..") {
        return None;
    }
    match (parts.next()?, parts.next()) {
        ("SKILL.md", None) => Some((skill, SkillFileKind::Body)),
        ("dyson-skill.json", None) => Some((skill, SkillFileKind::Metadata)),
        _ => None,
    }
}

async fn read_utf8(
    state_files: &StateFileService,
    row: Option<&StateFileRow>,
) -> Result<Option<String>, SkillInventoryError> {
    let Some(row) = row else {
        return Ok(None);
    };
    let Some(bytes) = state_files.read_body(row).await? else {
        return Ok(None);
    };
    Ok(String::from_utf8(bytes).ok())
}

fn skill_description(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(frontmatter) = frontmatter(trimmed) {
        for line in frontmatter.lines() {
            let line = line.trim();
            if let Some((key, value)) = line.split_once(':')
                && key.trim() == "description"
            {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_owned());
                }
            }
        }
    }
    trimmed
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && *line != "---")
        .map(|line| line.trim_start_matches('#').trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn frontmatter(body: &str) -> Option<&str> {
    let rest = body.strip_prefix("---")?;
    if !rest.starts_with(['\r', '\n']) {
        return None;
    }
    let rest = rest.trim_start_matches(['\r', '\n']);
    let close = rest.find("\n---")?;
    Some(&rest[..close])
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::db::open_in_memory;

    const ALICE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    async fn svc() -> (StateFileService, tempfile::TempDir) {
        let pool = open_in_memory().await.unwrap();
        let keys = tempfile::tempdir().unwrap();
        let ciphers: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
        (StateFileService::new(pool, ciphers), keys)
    }

    #[tokio::test]
    async fn derives_marketplace_and_learned_skills_from_state_files() {
        let (svc, _keys) = svc().await;
        svc.ingest(
            crate::state_files::StateFileMeta {
                instance_id: "inst-a",
                owner_id: ALICE,
                namespace: "workspace",
                path: "skills/code-review/SKILL.md",
                mime: Some("text/markdown"),
                updated_at: 10,
            },
            b"---\ndescription: Review diffs.\n---\n\nRead the diff.",
        )
        .await
        .unwrap();
        svc.ingest(
            crate::state_files::StateFileMeta {
                instance_id: "inst-a",
                owner_id: ALICE,
                namespace: "workspace",
                path: "skills/code-review/dyson-skill.json",
                mime: Some("application/json"),
                updated_at: 11,
            },
            br#"{
                "version": "1.0.0",
                "description": "Review code from marketplace.",
                "origin": { "kind": "marketplace", "marketplace_id": "official" },
                "installed_at": "2026-05-07T09:00:00Z"
            }"#,
        )
        .await
        .unwrap();
        svc.ingest(
            crate::state_files::StateFileMeta {
                instance_id: "inst-a",
                owner_id: ALICE,
                namespace: "workspace",
                path: "skills/debug/SKILL.md",
                mime: Some("text/markdown"),
                updated_at: 12,
            },
            b"Debug runtime failures.\n\nUse logs first.",
        )
        .await
        .unwrap();

        let skills = list_instance_skills(&svc, "inst-a").await.unwrap();
        assert_eq!(skills.len(), 2);
        assert_eq!(skills[0].skill, "code-review");
        assert_eq!(skills[0].origin_kind, "marketplace");
        assert_eq!(skills[0].marketplace_id.as_deref(), Some("official"));
        assert_eq!(skills[1].skill, "debug");
        assert_eq!(skills[1].origin_kind, "local");

        let body = read_instance_skill_body(&svc, "inst-a", "debug")
            .await
            .unwrap();
        assert_eq!(
            body.as_deref(),
            Some("Debug runtime failures.\n\nUse logs first.")
        );
        let invalid = read_instance_skill_body(&svc, "inst-a", "../debug")
            .await
            .unwrap();
        assert!(invalid.is_none());
    }

    #[tokio::test]
    async fn tombstoned_skill_files_disappear_from_inventory() {
        let (svc, _keys) = svc().await;
        svc.ingest(
            crate::state_files::StateFileMeta {
                instance_id: "inst-a",
                owner_id: ALICE,
                namespace: "workspace",
                path: "skills/code-review/SKILL.md",
                mime: Some("text/markdown"),
                updated_at: 10,
            },
            b"Review diffs.",
        )
        .await
        .unwrap();
        svc.ingest(
            crate::state_files::StateFileMeta {
                instance_id: "inst-a",
                owner_id: ALICE,
                namespace: "workspace",
                path: "skills/code-review/dyson-skill.json",
                mime: Some("application/json"),
                updated_at: 11,
            },
            br#"{"version":"1.0.0","origin":{"kind":"marketplace"}}"#,
        )
        .await
        .unwrap();

        assert_eq!(list_instance_skills(&svc, "inst-a").await.unwrap().len(), 1);

        for path in [
            "skills/code-review/SKILL.md",
            "skills/code-review/dyson-skill.json",
        ] {
            svc.tombstone(crate::state_files::StateFileMeta {
                instance_id: "inst-a",
                owner_id: ALICE,
                namespace: "workspace",
                path,
                mime: None,
                updated_at: 12,
            })
            .await
            .unwrap();
        }

        assert!(
            list_instance_skills(&svc, "inst-a")
                .await
                .unwrap()
                .is_empty()
        );
    }
}
