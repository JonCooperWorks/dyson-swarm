use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Initialise structured JSON logging once at process startup.
/// `RUST_LOG` controls the filter (default `info`).
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .json()
                .with_current_span(false)
                .with_span_list(false),
        )
        .init();
}
