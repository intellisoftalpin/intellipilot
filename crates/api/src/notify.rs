//! Outbound notification transports driven by `notification_settings`.
//!
//! Two email providers (SMTP via `lettre`, Mailgun via HTTP) and two chat
//! channels (Matrix, Telegram). Each function takes the current settings and
//! returns a human-readable error string suitable for surfacing in the admin
//! "test" dialog.

use intellipilot_db::notification_settings::NotificationSettings;
use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use url::Url;

/// Whether the email channel is enabled and minimally configured.
#[must_use]
pub fn mail_ready(s: &NotificationSettings) -> bool {
    if !s.mail_enabled || s.mail_from_address.is_empty() {
        return false;
    }
    match s.mail_provider.as_str() {
        "smtp" => !s.smtp_host.is_empty(),
        "mailgun" => !s.mailgun_domain.is_empty() && !s.mailgun_api_key.is_empty(),
        _ => false,
    }
}

/// Send an email via the configured provider. `html` is the message body.
pub async fn send_email(
    s: &NotificationSettings,
    to: &str,
    subject: &str,
    html: &str,
) -> Result<(), String> {
    match s.mail_provider.as_str() {
        "smtp" => send_smtp(s, to, subject, html).await,
        "mailgun" => send_mailgun(s, to, subject, html).await,
        other => Err(format!("unknown mail provider '{other}'")),
    }
}

async fn send_smtp(
    s: &NotificationSettings,
    to: &str,
    subject: &str,
    html: &str,
) -> Result<(), String> {
    let from_addr = s
        .mail_from_address
        .parse()
        .map_err(|e| format!("invalid from address: {e}"))?;
    let from = Mailbox::new(
        (!s.mail_from_name.is_empty()).then(|| s.mail_from_name.clone()),
        from_addr,
    );
    let to_mbox: Mailbox = to.parse().map_err(|e| format!("invalid recipient: {e}"))?;

    let message = Message::builder()
        .from(from)
        .to(to_mbox)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(html.to_owned())
        .map_err(|e| format!("building message: {e}"))?;

    let mut tls_builder = TlsParameters::builder(s.smtp_host.clone());
    if s.smtp_skip_tls_verify {
        tls_builder = tls_builder.dangerous_accept_invalid_certs(true);
    }
    let tls = tls_builder.build().map_err(|e| format!("TLS setup: {e}"))?;

    let port = u16::try_from(s.smtp_port).map_err(|_| "invalid SMTP port".to_owned())?;
    let mut builder = if s.smtp_use_starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&s.smtp_host)
            .map_err(|e| format!("SMTP connect: {e}"))?
            .tls(Tls::Required(tls))
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&s.smtp_host)
            .map_err(|e| format!("SMTP connect: {e}"))?
            .tls(Tls::Wrapper(tls))
    }
    .port(port);

    if !s.smtp_username.is_empty() {
        builder = builder.credentials(Credentials::new(
            s.smtp_username.clone(),
            s.smtp_password.clone(),
        ));
    }

    builder
        .build()
        .send(message)
        .await
        .map(|_| ())
        .map_err(|e| format!("SMTP send failed: {e}"))
}

async fn send_mailgun(
    s: &NotificationSettings,
    to: &str,
    subject: &str,
    html: &str,
) -> Result<(), String> {
    let base = s.mailgun_base_url.trim_end_matches('/');
    let url = format!("{base}/v3/{}/messages", s.mailgun_domain);
    let from = if s.mail_from_name.is_empty() {
        s.mail_from_address.clone()
    } else {
        format!("{} <{}>", s.mail_from_name, s.mail_from_address)
    };
    let resp = reqwest::Client::new()
        .post(&url)
        .basic_auth("api", Some(&s.mailgun_api_key))
        .form(&[
            ("from", from.as_str()),
            ("to", to),
            ("subject", subject),
            ("html", html),
        ])
        .send()
        .await
        .map_err(|e| format!("Mailgun request failed: {e}"))?;
    ensure_ok("Mailgun", resp).await
}

/// Whether the Matrix channel is enabled and minimally configured.
#[must_use]
pub fn matrix_ready(s: &NotificationSettings) -> bool {
    s.matrix_enabled
        && !s.matrix_homeserver.is_empty()
        && !s.matrix_room_id.is_empty()
        && !s.matrix_access_token.is_empty()
}

/// Post a plain-text message to the configured Matrix room.
pub async fn send_matrix(s: &NotificationSettings, body: &str) -> Result<(), String> {
    let mut url =
        Url::parse(&s.matrix_homeserver).map_err(|e| format!("invalid homeserver URL: {e}"))?;
    url.path_segments_mut()
        .map_err(|()| "invalid homeserver URL".to_owned())?
        .extend(&[
            "_matrix",
            "client",
            "r0",
            "rooms",
            &s.matrix_room_id,
            "send",
            "m.room.message",
        ]);
    url.query_pairs_mut()
        .append_pair("access_token", &s.matrix_access_token);

    let resp = reqwest::Client::new()
        .post(url)
        .json(&serde_json::json!({ "msgtype": "m.text", "body": body }))
        .send()
        .await
        .map_err(|e| format!("Matrix request failed: {e}"))?;
    ensure_ok("Matrix", resp).await
}

/// Whether the Telegram channel is enabled and minimally configured.
#[must_use]
pub fn telegram_ready(s: &NotificationSettings) -> bool {
    s.telegram_enabled && !s.telegram_bot_token.is_empty() && !s.telegram_chat_id.is_empty()
}

/// Send a message to the configured Telegram chat via the Bot API.
pub async fn send_telegram(s: &NotificationSettings, text: &str) -> Result<(), String> {
    let url = format!(
        "https://api.telegram.org/bot{}/sendMessage",
        s.telegram_bot_token
    );
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({
            "chat_id": s.telegram_chat_id,
            "text": text,
        }))
        .send()
        .await
        .map_err(|e| format!("Telegram request failed: {e}"))?;
    ensure_ok("Telegram", resp).await
}

/// Turn a non-2xx HTTP response into a descriptive error including the body.
async fn ensure_ok(label: &str, resp: reqwest::Response) -> Result<(), String> {
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let body = resp.text().await.unwrap_or_default();
    let snippet: String = body.chars().take(300).collect();
    Err(format!("{label} returned {status}: {snippet}"))
}
