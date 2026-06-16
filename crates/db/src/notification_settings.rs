//! Single-row outbound notification configuration, edited by a superadmin via
//! the admin UI. Two independent channels — email (SMTP or Mailgun) and Matrix.
//!
//! Secrets (`smtp_password`, `mailgun_api_key`, `matrix_access_token`) are
//! stored here so the server can send. The API never returns them; on update,
//! a `None` secret keeps the stored value (write-only fields).

use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct NotificationSettings {
    pub mail_enabled: bool,
    pub mail_provider: String,
    pub mail_from_address: String,
    pub mail_from_name: String,
    pub smtp_host: String,
    pub smtp_port: i32,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_use_starttls: bool,
    pub smtp_skip_tls_verify: bool,
    pub mailgun_api_key: String,
    pub mailgun_domain: String,
    pub mailgun_base_url: String,
    pub matrix_enabled: bool,
    pub matrix_homeserver: String,
    pub matrix_room_id: String,
    pub matrix_access_token: String,
    pub telegram_enabled: bool,
    pub telegram_bot_token: String,
    pub telegram_chat_id: String,
    pub mail_on_login: bool,
    pub mail_on_issue_created: bool,
    pub mail_on_issue_resolved: bool,
    pub mail_on_daily_report: bool,
    pub msg_on_login: bool,
    pub msg_on_issue_created: bool,
    pub msg_on_issue_resolved: bool,
    pub msg_on_daily_report: bool,
    pub updated_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
}

/// Mutable fields. Secret fields are `Option`: `None` keeps the stored value.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct NotificationSettingsUpdate {
    pub mail_enabled: bool,
    pub mail_provider: String,
    pub mail_from_address: String,
    pub mail_from_name: String,
    pub smtp_host: String,
    pub smtp_port: i32,
    pub smtp_username: String,
    pub smtp_password: Option<String>,
    pub smtp_use_starttls: bool,
    pub smtp_skip_tls_verify: bool,
    pub mailgun_api_key: Option<String>,
    pub mailgun_domain: String,
    pub mailgun_base_url: String,
    pub matrix_enabled: bool,
    pub matrix_homeserver: String,
    pub matrix_room_id: String,
    pub matrix_access_token: Option<String>,
    pub telegram_enabled: bool,
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: String,
    pub mail_on_login: bool,
    pub mail_on_issue_created: bool,
    pub mail_on_issue_resolved: bool,
    pub mail_on_daily_report: bool,
    pub msg_on_login: bool,
    pub msg_on_issue_created: bool,
    pub msg_on_issue_resolved: bool,
    pub msg_on_daily_report: bool,
}

const COLS: &str = "mail_enabled, mail_provider, mail_from_address, mail_from_name, \
                    smtp_host, smtp_port, smtp_username, smtp_password, smtp_use_starttls, \
                    smtp_skip_tls_verify, mailgun_api_key, mailgun_domain, mailgun_base_url, \
                    matrix_enabled, matrix_homeserver, matrix_room_id, matrix_access_token, \
                    telegram_enabled, telegram_bot_token, telegram_chat_id, \
                    mail_on_login, mail_on_issue_created, mail_on_issue_resolved, \
                    mail_on_daily_report, msg_on_login, msg_on_issue_created, \
                    msg_on_issue_resolved, msg_on_daily_report, \
                    updated_at, updated_by";

fn row_to_settings(row: &tokio_postgres::Row) -> NotificationSettings {
    NotificationSettings {
        mail_enabled: row.get("mail_enabled"),
        mail_provider: row.get("mail_provider"),
        mail_from_address: row.get("mail_from_address"),
        mail_from_name: row.get("mail_from_name"),
        smtp_host: row.get("smtp_host"),
        smtp_port: row.get("smtp_port"),
        smtp_username: row.get("smtp_username"),
        smtp_password: row.get("smtp_password"),
        smtp_use_starttls: row.get("smtp_use_starttls"),
        smtp_skip_tls_verify: row.get("smtp_skip_tls_verify"),
        mailgun_api_key: row.get("mailgun_api_key"),
        mailgun_domain: row.get("mailgun_domain"),
        mailgun_base_url: row.get("mailgun_base_url"),
        matrix_enabled: row.get("matrix_enabled"),
        matrix_homeserver: row.get("matrix_homeserver"),
        matrix_room_id: row.get("matrix_room_id"),
        matrix_access_token: row.get("matrix_access_token"),
        telegram_enabled: row.get("telegram_enabled"),
        telegram_bot_token: row.get("telegram_bot_token"),
        telegram_chat_id: row.get("telegram_chat_id"),
        mail_on_login: row.get("mail_on_login"),
        mail_on_issue_created: row.get("mail_on_issue_created"),
        mail_on_issue_resolved: row.get("mail_on_issue_resolved"),
        mail_on_daily_report: row.get("mail_on_daily_report"),
        msg_on_login: row.get("msg_on_login"),
        msg_on_issue_created: row.get("msg_on_issue_created"),
        msg_on_issue_resolved: row.get("msg_on_issue_resolved"),
        msg_on_daily_report: row.get("msg_on_daily_report"),
        updated_at: row.get("updated_at"),
        updated_by: row.get("updated_by"),
    }
}

/// Fetch the single settings row. The migration guarantees it exists.
pub async fn get(client: &deadpool_postgres::Client) -> Result<NotificationSettings, DbError> {
    let row = client
        .query_one(
            &format!("SELECT {COLS} FROM notification_settings WHERE id = 1"),
            &[],
        )
        .await?;
    Ok(row_to_settings(&row))
}

/// Replace all mutable fields, recording the actor. A `None` secret keeps the
/// currently-stored value (via `COALESCE`).
pub async fn set(
    client: &deadpool_postgres::Client,
    upd: &NotificationSettingsUpdate,
    updated_by: Uuid,
) -> Result<NotificationSettings, DbError> {
    let row = client
        .query_one(
            &format!(
                "UPDATE notification_settings SET \
                   mail_enabled = $1, mail_provider = $2, mail_from_address = $3, \
                   mail_from_name = $4, smtp_host = $5, smtp_port = $6, smtp_username = $7, \
                   smtp_password = COALESCE($8, smtp_password), smtp_use_starttls = $9, \
                   smtp_skip_tls_verify = $10, \
                   mailgun_api_key = COALESCE($11, mailgun_api_key), mailgun_domain = $12, \
                   mailgun_base_url = $13, matrix_enabled = $14, matrix_homeserver = $15, \
                   matrix_room_id = $16, \
                   matrix_access_token = COALESCE($17, matrix_access_token), \
                   telegram_enabled = $18, \
                   telegram_bot_token = COALESCE($19, telegram_bot_token), \
                   telegram_chat_id = $20, \
                   mail_on_login = $21, mail_on_issue_created = $22, \
                   mail_on_issue_resolved = $23, mail_on_daily_report = $24, \
                   msg_on_login = $25, msg_on_issue_created = $26, \
                   msg_on_issue_resolved = $27, msg_on_daily_report = $28, \
                   updated_at = now(), updated_by = $29 \
                 WHERE id = 1 RETURNING {COLS}"
            ),
            &[
                &upd.mail_enabled,
                &upd.mail_provider,
                &upd.mail_from_address,
                &upd.mail_from_name,
                &upd.smtp_host,
                &upd.smtp_port,
                &upd.smtp_username,
                &upd.smtp_password,
                &upd.smtp_use_starttls,
                &upd.smtp_skip_tls_verify,
                &upd.mailgun_api_key,
                &upd.mailgun_domain,
                &upd.mailgun_base_url,
                &upd.matrix_enabled,
                &upd.matrix_homeserver,
                &upd.matrix_room_id,
                &upd.matrix_access_token,
                &upd.telegram_enabled,
                &upd.telegram_bot_token,
                &upd.telegram_chat_id,
                &upd.mail_on_login,
                &upd.mail_on_issue_created,
                &upd.mail_on_issue_resolved,
                &upd.mail_on_daily_report,
                &upd.msg_on_login,
                &upd.msg_on_issue_created,
                &upd.msg_on_issue_resolved,
                &upd.msg_on_daily_report,
                &updated_by,
            ],
        )
        .await?;
    Ok(row_to_settings(&row))
}
