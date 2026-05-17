//! Swarm-native, instance-scoped secrets intentionally visible to agents.
//!
//! This is not the human vault. Values are sealed under the owning user's
//! envelope key and scoped by `(owner_user_id, instance_id, name)`, then
//! exposed through owner-authorized UI/API routes and a Swarm-authenticated
//! Dyson built-in tool.

use std::sync::Arc;

use crate::envelope::{
    CipherDirectory, EnvelopeError, KmsContext, KmsScope, SecretAccessOperation,
    SecretAccessReason, SecretAccessResult, open_context, rewrap_context_as_string,
    seal_context_as_string,
};
use crate::error::StoreError;
use crate::kms_audit;
use crate::traits::{
    AgentSecretMetadata, AgentSecretStore, SecretAccessAuditEntry, SecretAccessAuditStore,
};

#[derive(Debug, thiserror::Error)]
pub enum AgentSecretError {
    #[error("invalid secret name")]
    InvalidName,
    #[error("secret not found")]
    NotFound,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
}

#[derive(Debug, Clone, Copy)]
pub enum AgentSecretActorKind {
    Agent,
    User,
}

impl AgentSecretActorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::User => "user",
        }
    }

    fn reason(self) -> SecretAccessReason {
        match self {
            Self::Agent => SecretAccessReason::AgentSecretTool,
            Self::User => SecretAccessReason::AgentSecretUser,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentSecretActor {
    pub kind: AgentSecretActorKind,
    pub id: Option<String>,
}

impl AgentSecretActor {
    pub fn agent(instance_id: &str) -> Self {
        Self {
            kind: AgentSecretActorKind::Agent,
            id: Some(instance_id.to_owned()),
        }
    }

    pub fn user(user_id: &str) -> Self {
        Self {
            kind: AgentSecretActorKind::User,
            id: Some(user_id.to_owned()),
        }
    }
}

#[derive(Clone)]
pub struct AgentSecretsService {
    store: Arc<dyn AgentSecretStore>,
    ciphers: Arc<dyn CipherDirectory>,
    audit: Arc<dyn SecretAccessAuditStore>,
}

impl AgentSecretsService {
    pub fn new(
        store: Arc<dyn AgentSecretStore>,
        ciphers: Arc<dyn CipherDirectory>,
        audit: Arc<dyn SecretAccessAuditStore>,
    ) -> Self {
        Self {
            store,
            ciphers,
            audit,
        }
    }

    pub async fn list(
        &self,
        owner_user_id: &str,
        instance_id: &str,
        actor: AgentSecretActor,
    ) -> Result<Vec<AgentSecretMetadata>, AgentSecretError> {
        let rows = self.store.list_metadata(owner_user_id, instance_id).await?;
        self.record(
            owner_user_id,
            instance_id,
            None,
            &actor,
            SecretAccessOperation::List,
            SecretAccessResult::Success,
            None,
        )
        .await;
        Ok(rows)
    }

    pub async fn put(
        &self,
        owner_user_id: &str,
        instance_id: &str,
        name: &str,
        value: &[u8],
        actor: AgentSecretActor,
    ) -> Result<AgentSecretMetadata, AgentSecretError> {
        validate_name(name)?;
        let context = agent_secret_context(owner_user_id, instance_id, name);
        let ciphertext =
            seal_context_as_string(self.ciphers.as_ref(), &context, value, actor.kind.reason())?;
        let meta = self
            .store
            .put(owner_user_id, instance_id, name, &ciphertext)
            .await?;
        self.record(
            owner_user_id,
            instance_id,
            Some(name),
            &actor,
            SecretAccessOperation::Encrypt,
            SecretAccessResult::Success,
            None,
        )
        .await;
        Ok(meta)
    }

    pub async fn get(
        &self,
        owner_user_id: &str,
        instance_id: &str,
        name: &str,
        actor: AgentSecretActor,
    ) -> Result<Option<Vec<u8>>, AgentSecretError> {
        validate_name(name)?;
        let Some(row) = self.store.get(owner_user_id, instance_id, name).await? else {
            return Ok(None);
        };
        let context = agent_secret_context(owner_user_id, instance_id, name);
        let opened = open_context(
            self.ciphers.as_ref(),
            &context,
            row.ciphertext.as_bytes(),
            actor.kind.reason(),
        )?;
        if opened.needs_rewrap {
            let rewrapped = rewrap_context_as_string(
                self.ciphers.as_ref(),
                &context,
                opened.plaintext.as_slice(),
                actor.kind.reason(),
            )?;
            self.store
                .put(owner_user_id, instance_id, name, &rewrapped)
                .await?;
        }
        self.store
            .touch_last_read(owner_user_id, instance_id, name)
            .await?;
        self.record(
            owner_user_id,
            instance_id,
            Some(name),
            &actor,
            SecretAccessOperation::Decrypt,
            SecretAccessResult::Success,
            None,
        )
        .await;
        Ok(Some(opened.plaintext))
    }

    pub async fn delete(
        &self,
        owner_user_id: &str,
        instance_id: &str,
        name: &str,
        actor: AgentSecretActor,
    ) -> Result<(), AgentSecretError> {
        validate_name(name)?;
        self.store.delete(owner_user_id, instance_id, name).await?;
        self.record(
            owner_user_id,
            instance_id,
            Some(name),
            &actor,
            SecretAccessOperation::Delete,
            SecretAccessResult::Success,
            None,
        )
        .await;
        Ok(())
    }

    pub async fn delete_for_instance(&self, instance_id: &str) -> Result<(), AgentSecretError> {
        Ok(self.store.delete_for_instance(instance_id).await?)
    }

    async fn record(
        &self,
        owner_user_id: &str,
        instance_id: &str,
        name: Option<&str>,
        actor: &AgentSecretActor,
        operation: SecretAccessOperation,
        result: SecretAccessResult,
        error_message: Option<String>,
    ) {
        let entry = SecretAccessAuditEntry {
            timestamp: crate::now_secs(),
            actor_kind: actor.kind.as_str().to_owned(),
            actor_id: actor.id.clone(),
            reason: actor.kind.reason(),
            operation,
            scope: KmsScope::AgentSecret,
            owner_id: Some(owner_user_id.to_owned()),
            instance_id: Some(instance_id.to_owned()),
            secret_name: name.map(str::to_owned),
            key_id: None,
            key_version: None,
            result,
            error_class: error_message.as_ref().map(|_| "agent_secret".to_owned()),
            error_message,
        };
        kms_audit::best_effort_record(self.audit.as_ref(), entry).await;
    }
}

pub fn validate_name(name: &str) -> Result<(), AgentSecretError> {
    let valid = !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(AgentSecretError::InvalidName)
    }
}

pub fn agent_secret_context(owner_user_id: &str, instance_id: &str, name: &str) -> KmsContext {
    KmsContext::user_scoped(
        KmsScope::AgentSecret,
        owner_user_id.to_owned(),
        Some(instance_id.to_owned()),
        Some(name.to_owned()),
    )
}
