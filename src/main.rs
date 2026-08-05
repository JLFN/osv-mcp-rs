mod client;
mod server;

use client::AdvisoryClient;
use rmcp::{ServiceExt, transport::stdio};
use server::SecurityAdvisoryServer;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse().expect("static directive is valid"))).init();
    let client = Arc::new(AdvisoryClient::new());
    let server = SecurityAdvisoryServer { client };
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
