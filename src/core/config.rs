// src/core/config.rs
use config::{Config as ConfigLoader, Environment};
use dotenvy::dotenv;
use secrecy::SecretString;
use serde::Deserialize;

/// 应用程序配置结构体。包含所有运行时需要的配置项，
/// 包括数据库连接、Redis连接、JWT密钥等敏感信息，以及服务器端口、日志级别等非敏感配置。
///
/// 所有敏感字段都使用 `SecretString` 类型包装，防止意外泄露到日志中。
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Postgres 数据库连接串（敏感信息）。格式：postgresql://user:password@host:port/database
    #[serde(alias = "DATABASE_URL")]
    pub database_url: SecretString,

    /// Redis 连接串（敏感信息）。格式：redis://host:port
    #[serde(alias = "REDIS_URL")]
    pub redis_url: SecretString,

    /// JWT 签名密钥（敏感信息）。用于签名和验证JWT令牌，必须保密。
    #[serde(alias = "JWT_SECRET")]
    pub jwt_secret: SecretString,

    /// HTTP服务器监听端口。默认值为3000。
    #[serde(default = "default_port", alias = "SERVER_PORT")]
    pub port: u16,

    /// HTTP服务器监听地址。默认值为 "0.0.0.0"，表示监听所有网络接口。
    #[serde(default = "default_host", alias = "SERVER_HOST")]
    pub host: String,

    /// 日志级别配置。默认值为 "info"。可选值：trace, debug, info, warn, error。
    #[serde(default = "default_log", alias = "RUST_LOG")]
    pub rust_log: String,

    /// JWT访问令牌的过期时间（单位：秒）。默认值为3600秒（1小时）。
    #[serde(default = "default_jwt_exp", alias = "JWT_EXPIRATION")]
    pub jwt_expiration: i64,

    /// JWT刷新令牌的过期时间（单位：秒）。默认值为604800秒（7天）。
    #[serde(default = "default_refresh_exp", alias = "REFRESH_TOKEN_EXPIRATION")]
    pub refresh_token_expiration: i64,
}

impl Config {
    /// 加载应用程序配置。配置加载优先级如下：
    /// 1. 首先尝试从 `.env` 文件加载（如果存在）
    /// 2. 然后从系统环境变量中读取（优先级更高）
    ///
    /// 环境变量命名规则：
    /// - 嵌套字段使用双下划线分隔，如 `SERVER_PORT` 映射到 `server_port`
    /// - 使用 `alias` 属性支持多种命名方式，如 `DATABASE_URL` 和 `database_url` 都可以
    ///
    /// # 返回值
    /// - `Config`: 加载完成的配置结构体
    pub fn new() -> Self {
        // 尝试加载 .env 文件。如果文件不存在，使用 ok() 忽略错误。
        dotenv().ok();

        // 配置加载器：从环境变量中读取配置。
        // Environment::default() 会把 `FOO__BAR=baz` 映射到 `foo.bar=baz`
        // try_parsing(true) 会自动将字符串转换为正确的类型（如 "3000" -> 3000u16）
        let builder = ConfigLoader::builder().add_source(Environment::default().try_parsing(true));

        // 构建配置并反序列化为 Config 结构体
        match builder.build() {
            Ok(config) => config
                .try_deserialize()
                .expect("❌ Failed to deserialize configuration"),
            Err(e) => panic!("❌ Failed to build configuration: {e}"),
        }
    }
}

// --- 默认值函数 ---

/// 返回默认的HTTP服务器端口：3000
fn default_port() -> u16 {
    3000
}

/// 返回默认的HTTP服务器监听地址：0.0.0.0（监听所有网络接口）
fn default_host() -> String {
    "0.0.0.0".to_string()
}

/// 返回默认的日志级别：info
fn default_log() -> String {
    "info".to_string()
}

/// 返回默认的JWT访问令牌过期时间：3600秒（1小时）
fn default_jwt_exp() -> i64 {
    3600
}

/// 返回默认的JWT刷新令牌过期时间：604800秒（7天）
fn default_refresh_exp() -> i64 {
    86400 * 7
}