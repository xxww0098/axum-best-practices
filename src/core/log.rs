use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, registry, util::SubscriberInitExt};

pub fn init(log_level: &str) -> WorkerGuard {
    // 1. 文件输出：按天轮询
    let file_appender = tracing_appender::rolling::daily("logs", "app.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // 2. 格式化层（文件）：无颜色，带文件和行号
    let file_layer = fmt::layer()
        .with_ansi(false)
        .with_writer(non_blocking)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(false);

    // 3. 格式化层（控制台）：带颜色
    let stdout_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true);

    // 4. 注册
    registry()
        .with(EnvFilter::new(log_level))
        .with(stdout_layer)
        .with(file_layer)
        .init();

    guard
}
