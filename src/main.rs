// src/main.rs
mod core;
mod dtos;
mod entity;
mod extractors;
mod handlers;
mod middleware;
mod routes;
mod services;
mod start;
mod state;
mod utils;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    start::run().await?;
    Ok(())
}
