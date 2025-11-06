use std::sync::Arc;

/// Logger trait for flexible logging support
pub trait SecuroLogger: Send + Sync {
    fn info(&self, msg: &str);
    fn warn(&self, msg: &str);
    fn error(&self, msg: &str);
    fn debug(&self, msg: &str);
    fn trace(&self, msg: &str);
}

/// Null logger that does nothing (used when no logger is provided)
pub struct NullLogger;

impl SecuroLogger for NullLogger {
    fn info(&self, _msg: &str) {}
    fn warn(&self, _msg: &str) {}
    fn error(&self, _msg: &str) {}
    fn debug(&self, _msg: &str) {}
    fn trace(&self, _msg: &str) {}
}

/// Tracing integration logger
pub struct TracingLogger;

impl SecuroLogger for TracingLogger {
    fn info(&self, msg: &str) {
        tracing::info!("{}", msg);
    }
    fn warn(&self, msg: &str) {
        tracing::warn!("{}", msg);
    }
    fn error(&self, msg: &str) {
        tracing::error!("{}", msg);
    }
    fn debug(&self, msg: &str) {
        tracing::debug!("{}", msg);
    }
    fn trace(&self, msg: &str) {
        tracing::trace!("{}", msg);
    }
}

/// Internal logger holder
pub struct LoggerHandle {
    logger: Arc<dyn SecuroLogger>,
}

impl LoggerHandle {
    /// Create a new logger handle
    pub fn new<L: SecuroLogger + 'static>(logger: L) -> Self {
        LoggerHandle {
            logger: Arc::new(logger),
        }
    }

    /// Create a null logger (no logging)
    pub fn null() -> Self {
        LoggerHandle {
            logger: Arc::new(NullLogger),
        }
    }

    /// Create a tracing logger
    pub fn tracing() -> Self {
        LoggerHandle {
            logger: Arc::new(TracingLogger),
        }
    }

    pub fn info(&self, msg: &str) {
        self.logger.info(msg);
    }

    pub fn warn(&self, msg: &str) {
        self.logger.warn(msg);
    }

    pub fn error(&self, msg: &str) {
        self.logger.error(msg);
    }

    pub fn debug(&self, msg: &str) {
        self.logger.debug(msg);
    }

    pub fn trace(&self, msg: &str) {
        self.logger.trace(msg);
    }
}

/// Convenient macros for logging with format arguments
/// Usage: linfo!(logger, "Message: {}", value);
#[macro_export]
macro_rules! linfo {
    ($logger:expr, $($arg:tt)*) => {
        $logger.info(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! lwarn {
    ($logger:expr, $($arg:tt)*) => {
        $logger.warn(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! lerror {
    ($logger:expr, $($arg:tt)*) => {
        $logger.error(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! ldebug {
    ($logger:expr, $($arg:tt)*) => {
        $logger.debug(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! ltrace {
    ($logger:expr, $($arg:tt)*) => {
        $logger.trace(&format!($($arg)*))
    };
}

impl Clone for LoggerHandle {
    fn clone(&self) -> Self {
        LoggerHandle {
            logger: self.logger.clone(),
        }
    }
}
