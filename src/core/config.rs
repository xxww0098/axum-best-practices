// src/core/config.rs
use config::{Config as ConfigLoader, Environment};
use dotenvy::dotenv;
use secrecy::SecretString;
use serde::Deserialize;

/// 应用程序配置
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Postgres 数据库连接串
    #[serde(alias = "DATABASE_URL")]
    pub database_url: SecretString,

    /// Redis 连接串
    #[serde(alias = "REDIS_URL")]
    pub redis_url: SecretString,

    /// JWT 签名密钥
    #[serde(alias = "JWT_SECRET")]
    pub jwt_secret: SecretString,

    /// HTTP服务器端口，默认 3000
    #[serde(default = "default_port", alias = "SERVER_PORT")]
    pub port: u16,

    /// 监听地址，默认 "0.0.0.0"
    #[serde(default = "default_host", alias = "SERVER_HOST")]
    pub host: String,

    /// 日志级别，默认 "info"
    #[serde(default = "default_log", alias = "RUST_LOG")]
    pub rust_log: String,

    /// JWT Access Token 过期时间（秒），默认 1小时
    #[serde(default = "default_jwt_exp", alias = "JWT_EXPIRATION")]
    pub jwt_expiration: i64,

    /// JWT Refresh Token 过期时间（秒），默认 7天
    #[serde(default = "default_refresh_exp", alias = "REFRESH_TOKEN_EXPIRATION")]
    pub refresh_token_expiration: i64,
}

impl Config {
    /// 加载配置：优先从环境变量读取，支持 .env 文件
    pub fn new() -> Self {
        dotenv().ok();

        let builder = ConfigLoader::builder().add_source(Environment::default().try_parsing(true));

        match builder.build() {
            Ok(config) => config
                .try_deserialize()
                .expect("❌ Failed to deserialize configuration"),
            Err(e) => panic!("❌ Failed to build configuration: {e}"),
        }
    }
}

// --- 默认值 ---

fn default_port() -> u16 {
    3000
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_log() -> String {
    "info".to_string()
}

fn default_jwt_exp() -> i64 {
    3600
}

fn default_refresh_exp() -> i64 {
    86400 * 7
}
