//! Pluggable outbound mailer.
//!
//! Default impl is [`NoopMailer`]. The real Mailgun HTTP API impl lives behind
//! the `mailgun` feature flag and is configured at runtime; when no real
//! mailer is wired and `INTELLIPILOT_ENV=development`, callers are expected to
//! surface tokens directly in API responses (handled at the HTTP layer).

use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MailError {
    #[error("mailer not configured")]
    NotConfigured,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("invalid recipient: {0}")]
    InvalidRecipient(String),
}

#[derive(Debug, Clone)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
}

#[async_trait]
pub trait Mailer: Send + Sync + 'static {
    async fn send(&self, email: &Email) -> Result<(), MailError>;
    fn is_configured(&self) -> bool;
}

/// Default mailer: always reports `NotConfigured`. Used when the deployment
/// has not opted into outbound email.
#[derive(Debug, Default)]
pub struct NoopMailer;

#[async_trait]
impl Mailer for NoopMailer {
    async fn send(&self, _email: &Email) -> Result<(), MailError> {
        Err(MailError::NotConfigured)
    }
    fn is_configured(&self) -> bool {
        false
    }
}

/// Dev mailer: logs the email instead of sending. Useful with
/// `INTELLIPILOT_ENV=development`.
#[derive(Debug, Default)]
pub struct LoggingMailer;

#[async_trait]
impl Mailer for LoggingMailer {
    async fn send(&self, email: &Email) -> Result<(), MailError> {
        tracing::info!(to = %email.to, subject = %email.subject, "outbound email (logged, not sent)");
        Ok(())
    }
    fn is_configured(&self) -> bool {
        true
    }
}
