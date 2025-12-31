use std::sync::LazyLock;
use regex::Regex;

pub mod auth;
pub mod response;
pub mod user;

pub static PHONE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^1[3-9]\d{9}$").expect("Invalid Regex")
});