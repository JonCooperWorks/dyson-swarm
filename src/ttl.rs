//! TTL sweeper.
//!
//! Background task that ticks every minute, asks the instance store for rows
//! whose `expires_at` is in the past (and which aren't pinned or already
//! destroyed), and destroys each. Snapshots and backups are intentionally
//! untouched — TTL governs running sandboxes only.

use std::sync::Arc;
use std::time::Duration;

use crate::instance::InstanceService;
use crate::now_secs;
use crate::traits::InstanceStore;

/// Default sweep cadence (per the brief: "every minute").
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);

/// Run one sweep tick. Public for test access; production code uses
/// [`spawn_loop`].
pub async fn run_once(instances: &dyn InstanceStore, service: &InstanceService) {
    let now = now_secs();
    let expired = match instances.expired(now).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "ttl sweep: list expired failed");
            return;
        }
    };
    for row in expired {
        if let Err(e) = service
            .destroy(crate::instance::SYSTEM_OWNER, &row.id, false)
            .await
        {
            tracing::warn!(
                error = %e,
                instance = %row.id,
                "ttl sweep: destroy failed"
            );
        } else {
            tracing::info!(instance = %row.id, "ttl sweep: destroyed expired instance");
        }
    }
}

pub fn spawn_loop(
    instances: Arc<dyn InstanceStore>,
    service: Arc<InstanceService>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate-first tick so we don't sweep before bootstrap
        // finishes.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_once(&*instances, &service).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::db::secrets::SqlxSecretStore;
    use crate::db::tokens::SqlxTokenStore;
    use crate::error::CubeError;
    use crate::instance::{CreateRequest, ENV_MODEL};
    use crate::traits::{
        CreateSandboxArgs, CubeClient, InstanceStatus, InstanceStore, SandboxInfo, SecretStore,
        SnapshotInfo, TokenStore,
    };

    #[derive(Default)]
    struct MockCube {
        next: Mutex<u32>,
        destroyed: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl CubeClient for MockCube {
        async fn create_sandbox(
            &self,
            _: CreateSandboxArgs,
        ) -> Result<SandboxInfo, CubeError> {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            let sid = format!("sb-{}", *n);
            Ok(SandboxInfo {
                sandbox_id: sid.clone(),
                host_ip: "10.0.0.1".into(),
                url: format!("https://{sid}.cube.test"),
            })
        }
        async fn destroy_sandbox(&self, sandbox_id: &str) -> Result<(), CubeError> {
            self.destroyed.lock().unwrap().push(sandbox_id.into());
            Ok(())
        }
        async fn snapshot_sandbox(
            &self,
            _: &str,
            _: &str,
        ) -> Result<SnapshotInfo, CubeError> {
            unimplemented!()
        }
        async fn delete_snapshot(&self, _: &str, _: &str) -> Result<(), CubeError> {
            unimplemented!()
        }
    }

    fn env_with_model() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(ENV_MODEL.into(), "anthropic/claude-sonnet-4-5".into());
        m
    }

    #[tokio::test]
    async fn run_once_destroys_only_expired_unpinned() {
        let pool = open_in_memory().await.unwrap();
        let cube = Arc::new(MockCube::default());
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(pool.clone()));
        let secrets: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));
        let svc = Arc::new(InstanceService::new(
            cube.clone(),
            instances.clone(),
            secrets,
            tokens,
            "http://t/llm",
        ));

        // a: unpinned, will expire shortly
        let a = svc
            .create("legacy", CreateRequest {
                template_id: "t".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: Some(1),
                network_policy: crate::network_policy::NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            })
            .await
            .unwrap();

        // b: pinned, must NOT be destroyed even though TTL is 1
        let b = svc
            .create("legacy", CreateRequest {
                template_id: "t".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: Some(1),
                network_policy: crate::network_policy::NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            })
            .await
            .unwrap();
        instances.pin(&b.id, true, None).await.unwrap();

        // c: long TTL, must NOT be destroyed
        let c = svc
            .create("legacy", CreateRequest {
                template_id: "t".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: Some(10_000),
                network_policy: crate::network_policy::NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            })
            .await
            .unwrap();

        // Force the wall-clock past `a`'s expiry without sleeping: rewrite
        // the row directly via raw SQL.
        sqlx::query("UPDATE instances SET expires_at = 1 WHERE id = ?")
            .bind(&a.id)
            .execute(&pool)
            .await
            .unwrap();

        run_once(&*instances, &svc).await;

        let a_row = instances.get(&a.id).await.unwrap().unwrap();
        assert_eq!(a_row.status, InstanceStatus::Destroyed);
        let b_row = instances.get(&b.id).await.unwrap().unwrap();
        assert_eq!(b_row.status, InstanceStatus::Live);
        let c_row = instances.get(&c.id).await.unwrap().unwrap();
        assert_eq!(c_row.status, InstanceStatus::Live);

        // Cube saw exactly one destroy for the expired sandbox.
        let destroyed = cube.destroyed.lock().unwrap().clone();
        assert_eq!(destroyed.len(), 1);
        assert_eq!(
            destroyed[0],
            a_row.cube_sandbox_id.expect("sandbox id present")
        );
    }
}
