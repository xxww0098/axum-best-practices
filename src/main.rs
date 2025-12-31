// src/main.rs
mod core;
mod dtos;
mod entity;
mod extractors; // ✨ 新增模块
mod handlers;
mod middleware;
mod routes;
mod services;
mod start;
mod state;
mod utils;

#[tokio::main]
async fn main() {
    // 启动逻辑被封装在 start 模块中，main 函数保持干净
    start::run().await;
}