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

#[tokio::main]
async fn main() {
    start::run().await;
}