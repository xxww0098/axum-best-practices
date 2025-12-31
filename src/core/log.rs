use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt, layer::SubscriberExt, registry, util::SubscriberInitExt, EnvFilter,
};

pub fn init(log_level: &str) -> WorkerGuard {
    // 1. 文件输出层：按天轮询，存放在 logs 文件夹下
    let file_appender = tracing_appender::rolling::daily("logs", "app.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // 2. 格式化层（文件）- 不带颜色，包含详细代码位置
    let file_layer = fmt::layer()
        .with_ansi(false)
        .with_writer(non_blocking)
        .with_file(true)        // ✅ 显示文件名
        .with_line_number(true) // ✅ 显示行号
        .with_thread_ids(true)  // (可选) 显示线程ID，方便排查并发问题
        .with_target(false);    // (可选) 关闭 target (通常是模块路径)，只看文件名更清爽，看个人喜好

    // 3. 格式化层（控制台）- 带颜色，包含详细代码位置
    let stdout_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_file(true)        // ✅ 显示文件名
        .with_line_number(true) // ✅ 显示行号
        .with_thread_ids(true); // (可选)

    // 4. 注册所有层
    registry()
        .with(EnvFilter::new(log_level))
        .with(stdout_layer)
        .with(file_layer)
        .init();

    guard
}