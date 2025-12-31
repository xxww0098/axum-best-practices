use config::{Config as ConfigLoader, Environment};
use dotenvy::dotenv;
use secrecy::SecretString;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Postgres 连接串（敏感信息）
    #[serde(alias = "DATABASE_URL")]
    pub database_url: SecretString,

    /// Redis 连接串（敏感信息）
    #[serde(alias = "REDIS_URL")]
    pub redis_url: SecretString,

    /// JWT 签名密钥（敏感信息）
    #[serde(alias = "JWT_SECRET")]
    pub jwt_secret: SecretString,

    #[serde(default = "default_port", alias = "SERVER_PORT")]
    pub server_port: u16,

    #[serde(default = "default_host", alias = "SERVER_HOST")]
    pub server_host: String,

    #[serde(default = "default_log", alias = "RUST_LOG")]
    pub rust_log: String,

    #[serde(default = "default_jwt_exp", alias = "JWT_EXPIRATION")]
    pub jwt_expiration: i64,

    #[serde(default = "default_refresh_exp", alias = "REFRESH_TOKEN_EXPIRATION")]
    pub refresh_token_expiration: i64,
}

impl Config {
    /// 加载配置：
    /// - 支持 `.env`
    /// - 优先从环境变量加载
    pub fn new() -> Self {
        dotenv().ok();

        // 注意：Environment::default() 会把 `FOO__BAR=baz` 映射到 `foo.bar=baz`
        // 并且 try_parsing(true) 会把 "3000" 解析成数字等类型。
        let builder = ConfigLoader::builder().add_source(Environment::default().try_parsing(true));

        match builder.build() {
            Ok(config) => config
                .try_deserialize()
                .expect("❌ Failed to deserialize configuration"),
            Err(e) => panic!("❌ Failed to build configuration: {e}"),
        }
    }
}

// --- 默认值函数 ---
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
} // 1 hour
fn default_refresh_exp() -> i64 {
    86400 * 7
} // 7 days