use std::sync::Arc;

/// Logger trait for flexible logging support
#[allow(unused)]
trait SecuroLogger: Send + Sync {
    fn info(&self, msg: &str);
    fn debug(&self, msg: &str);
    fn warn(&self, msg: &str);
    fn error(&self, msg: &str);
    fn trace(&self, msg: &str);
}

/// Null logger that does nothing (used when no logger is provided)
struct NullLogger;

impl SecuroLogger for NullLogger {
    fn info(&self, _msg: &str) {}
    fn warn(&self, _msg: &str) {}
    fn error(&self, _msg: &str) {}
    fn debug(&self, _msg: &str) {}
    fn trace(&self, _msg: &str) {}
}

/// Tracing integration logger
struct TracingLogger;

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

#[allow(unused)]
impl LoggerHandle {
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

    pub(crate) fn info(&self, msg: &str) {
        self.logger.info(msg);
    }

    pub(crate) fn warn(&self, msg: &str) {
        self.logger.warn(msg);
    }

    pub(crate) fn error(&self, msg: &str) {
        self.logger.error(msg);
    }

    pub(crate) fn debug(&self, msg: &str) {
        self.logger.debug(msg);
    }

    pub(crate) fn trace(&self, msg: &str) {
        self.logger.trace(msg);
    }
}

/// Convenient macros for logging with format arguments
macro_rules! linfo {
    ($logger:expr, $($arg:tt)*) => {
        $logger.info(&format!($($arg)*))
    };
}

macro_rules! ldebug {
    ($logger:expr, $($arg:tt)*) => {
        $logger.debug(&format!($($arg)*))
    };
}

#[allow(unused)]
macro_rules! lwarn {
    ($logger:expr, $($arg:tt)*) => {
        $logger.warn(&format!($($arg)*))
    };
}

#[allow(unused)]
macro_rules! lerror {
    ($logger:expr, $($arg:tt)*) => {
        $logger.error(&format!($($arg)*))
    };
}

#[allow(unused)]
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

pub(crate) use linfo;
pub(crate) use ldebug;
#[allow(unused)]
pub(crate) use lwarn;
#[allow(unused)]
pub(crate) use lerror;
#[allow(unused)]
pub(crate) use ltrace;