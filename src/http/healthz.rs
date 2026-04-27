//! Liveness probe. Unauthenticated by design — load balancers and process
//! supervisors must be able to reach it without a bearer. The body is the
//! constant string `"ok"` so a hexdump matches even when JSON parsers fail.

use axum::routing::get;
use axum::Router;

pub fn router() -> Router {
    Router::new().route("/healthz", get(|| async { "ok" }))
}
