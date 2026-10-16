use tracing::{info, warn};

pub struct EmailService {
    host: String,
    port: u16,
    username: String,
    password: String,
    from: String,
    use_tls: bool,
    base_url: String,
}

impl EmailService {
    /// Builds the service from process environment variables.
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Builds the service from an arbitrary variable source.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let var = |key: &str| lookup(key).unwrap_or_default();

        let port_str = lookup("SMTP_PORT").unwrap_or_else(|| "587".to_string());
        let port = port_str.parse().unwrap_or(587);
        let tls_str = lookup("SMTP_TLS").unwrap_or_else(|| "true".to_string());
        let use_tls = !matches!(tls_str.to_lowercase().as_str(), "false" | "0");

        EmailService {
            host: var("SMTP_HOST"),
            port,
            username: var("SMTP_USERNAME"),
            password: var("SMTP_PASSWORD"),
            from: var("SMTP_FROM"),
            use_tls,
            base_url: var("BASE_URL").trim_end_matches('/').to_string(),
        }
    }

    /// A service with no SMTP host configured; every send becomes a no-op.
    pub fn disabled() -> Self {
        Self::from_lookup(|_| None)
    }

    pub fn is_configured(&self) -> bool {
        !self.host.is_empty() && !self.from.is_empty()
    }

    /// Test SMTP connectivity by sending a test email to the given address.
    pub async fn test_connection(&self, to_email: &str) -> Result<(), String> {
        if !self.is_configured() {
            return Err("SMTP not configured (host or from address missing)".to_string());
        }
        let subject = "cpmesh SMTP Test";
        let body = r#"<!DOCTYPE html>
<html><body style="font-family: sans-serif; padding: 20px;">
<h2 style="color: #6366f1;">cpmesh SMTP Test</h2>
<p>If you receive this email, your SMTP configuration is working correctly.</p>
</body></html>"#;
        self.send_html(to_email, subject, body).await
    }

    pub async fn send_verification_email(
        &self,
        to_email: &str,
        full_name: &str,
        token: &str,
    ) -> Result<(), String> {
        if !self.is_configured() {
            warn!("SMTP not configured, skipping verification email");
            return Ok(());
        }

        let verify_url = format!("{}/api/auth/verify-email?token={}", self.base_url, token);

        let subject = "Verify your email address - cpmesh";
        let body = format!(
            r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <div style="text-align: center; margin-bottom: 30px;">
    <h1 style="color: #6366f1;">cpmesh</h1>
  </div>
  <p>Hi {},</p>
  <p>Thanks for signing up! Please verify your email address by clicking the button below:</p>
  <div style="text-align: center; margin: 30px 0;">
    <a href="{}" style="background-color: #6366f1; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Verify Email</a>
  </div>
  <p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:</p>
  <p style="color: #666; font-size: 14px; word-break: break-all;">{}</p>
  <p style="color: #666; font-size: 14px;">This link expires in 24 hours.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">If you didn't create an account, you can safely ignore this email.</p>
</body>
</html>"#,
            escape_html(full_name),
            verify_url,
            verify_url
        );

        self.send_html(to_email, subject, &body).await
    }

    pub async fn send_duplicate_registration_notice(
        &self,
        to_email: &str,
        name: &str,
    ) -> Result<(), String> {
        if !self.is_configured() {
            return Ok(());
        }

        let subject = "Registration attempt - cpmesh";
        let body = format!(
            r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <div style="text-align: center; margin-bottom: 30px;">
    <h1 style="color: #6366f1;">cpmesh</h1>
  </div>
  <p>Hi {},</p>
  <p>Someone (possibly you) tried to create a new account using this email address. You already have an account.</p>
  <p>If this was you, please log in instead. If you've forgotten your password, you can reset it from the login page.</p>
  <p>If you didn't make this request, you can safely ignore this email.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">If you're concerned about unauthorized access, consider changing your password.</p>
</body>
</html>"#,
            escape_html(name)
        );
        self.send_html(to_email, subject, &body).await
    }

    /// Sends the code that confirms an account before it sets up two-factor
    /// authentication. Unlike notices, this fails when SMTP is not configured.
    pub async fn send_mfa_email_code(
        &self,
        to_email: &str,
        name: &str,
        code: &str,
    ) -> Result<(), String> {
        if !self.is_configured() {
            return Err("SMTP not configured".to_string());
        }
        let body = format!(
            r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h1 style="font-size: 20px;">cpmesh</h1>
  <p>Hi {name},</p>
  <p>Use this code to confirm it's you and set up two-factor authentication:</p>
  <p style="font-size: 28px; font-weight: bold; letter-spacing: 6px; font-family: monospace;">{code}</p>
  <p style="color: #666; font-size: 14px;">The code expires in 10 minutes.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">If you did not just sign in to cpmesh, someone knows your password. Change it now.</p>
</body>
</html>"#,
            name = escape_html(name),
            code = escape_html(code),
        );
        self.send_html(to_email, "Your cpmesh confirmation code", &body)
            .await
    }

    /// Tells a user about a change to their account's security (2FA, sessions, status).
    pub async fn send_security_notice(
        &self,
        to_email: &str,
        name: &str,
        subject: &str,
        message: &str,
    ) -> Result<(), String> {
        if !self.is_configured() {
            return Ok(());
        }
        let body = format!(
            r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h1 style="font-size: 20px;">cpmesh</h1>
  <p>Hi {name},</p>
  <p>{message}</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">If this wasn't you, change your password and contact your administrator.</p>
</body>
</html>"#,
            name = escape_html(name),
            message = escape_html(message),
        );
        self.send_html(to_email, &format!("{subject} - cpmesh"), &body)
            .await
    }

    async fn send_html(&self, to: &str, subject: &str, html_body: &str) -> Result<(), String> {
        use lettre::message::header::ContentType;
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{Message, SmtpTransport, Transport};

        let email = Message::builder()
            .from(
                self.from
                    .parse()
                    .map_err(|e| format!("invalid from: {e}"))?,
            )
            .to(to.parse().map_err(|e| format!("invalid to: {e}"))?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string())
            .map_err(|e| format!("build email: {e}"))?;

        let creds = Credentials::new(self.username.clone(), self.password.clone());

        let mailer = if self.use_tls && self.port == 465 {
            SmtpTransport::relay(&self.host)
                .map_err(|e| format!("SMTP relay: {e}"))?
                .port(self.port)
                .credentials(creds)
                .timeout(Some(std::time::Duration::from_secs(20)))
                .build()
        } else if self.use_tls {
            SmtpTransport::starttls_relay(&self.host)
                .map_err(|e| format!("SMTP STARTTLS: {e}"))?
                .port(self.port)
                .credentials(creds)
                .timeout(Some(std::time::Duration::from_secs(20)))
                .build()
        } else {
            SmtpTransport::builder_dangerous(&self.host)
                .port(self.port)
                .credentials(creds)
                .timeout(Some(std::time::Duration::from_secs(20)))
                .build()
        };

        crate::blocking::run(crate::blocking::Work::Mail, move || {
            mailer.send(&email).map_err(|e| format!("SMTP send: {e}"))?;
            Ok(())
        })
        .await?;
        info!("Email \"{subject}\" sent");
        Ok(())
    }
}

/// Escapes text for HTML element content.
fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn service_from(vars: &[(&str, &str)]) -> EmailService {
        let map: HashMap<&str, &str> = vars.iter().copied().collect();
        EmailService::from_lookup(|k| map.get(k).map(|v| v.to_string()))
    }

    #[test]
    fn disabled_service_is_not_configured() {
        let svc = EmailService::disabled();
        assert!(!svc.is_configured());
        assert_eq!(svc.port, 587);
        assert!(svc.use_tls);
        assert_eq!(svc.base_url, "");
    }

    #[test]
    fn requires_both_host_and_from_to_be_configured() {
        assert!(!service_from(&[("SMTP_HOST", "smtp.example")]).is_configured());
        assert!(!service_from(&[("SMTP_FROM", "noreply@example")]).is_configured());
        assert!(
            service_from(&[
                ("SMTP_HOST", "smtp.example"),
                ("SMTP_FROM", "noreply@example")
            ])
            .is_configured()
        );
    }

    #[test]
    fn parses_port_tls_and_base_url() {
        let svc = service_from(&[
            ("SMTP_HOST", "smtp.example"),
            ("SMTP_PORT", "465"),
            ("SMTP_USERNAME", "user"),
            ("SMTP_PASSWORD", "pw"),
            ("SMTP_FROM", "noreply@example"),
            ("SMTP_TLS", "FALSE"),
            ("BASE_URL", "https://cpmesh.example/"),
        ]);
        assert_eq!(svc.host, "smtp.example");
        assert_eq!(svc.port, 465);
        assert_eq!(svc.username, "user");
        assert_eq!(svc.password, "pw");
        assert_eq!(svc.from, "noreply@example");
        assert!(!svc.use_tls);
        assert_eq!(svc.base_url, "https://cpmesh.example");

        assert!(!service_from(&[("SMTP_TLS", "0")]).use_tls);
        assert!(service_from(&[("SMTP_TLS", "yes")]).use_tls);
        assert_eq!(service_from(&[("SMTP_PORT", "not-a-port")]).port, 587);
    }

    #[tokio::test]
    async fn sending_without_configuration_is_a_noop() {
        let svc = EmailService::disabled();
        svc.send_verification_email("a@example.com", "Alice", "tok")
            .await
            .unwrap();
        svc.send_duplicate_registration_notice("a@example.com", "Alice")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_connection_without_configuration_is_an_error() {
        let err = EmailService::disabled()
            .test_connection("a@example.com")
            .await
            .unwrap_err();
        assert!(err.contains("not configured"), "{err}");
    }

    #[tokio::test]
    async fn security_emails_without_configuration() {
        let svc = EmailService::disabled();
        // Notices are best effort; the confirmation code must not silently vanish
        svc.send_security_notice("a@example.com", "Alice", "Subject", "Body")
            .await
            .unwrap();
        assert!(
            svc.send_mfa_email_code("a@example.com", "Alice", "123456")
                .await
                .unwrap_err()
                .contains("not configured")
        );
    }

    #[test]
    fn html_is_escaped() {
        assert_eq!(
            escape_html(r#"<b>"Tom" & 'Jerry'</b>"#),
            "&lt;b&gt;&quot;Tom&quot; &amp; &#39;Jerry&#39;&lt;/b&gt;"
        );
        assert_eq!(escape_html("plain"), "plain");
    }

    #[tokio::test]
    async fn invalid_addresses_fail_before_any_network_io() {
        let svc = service_from(&[
            ("SMTP_HOST", "smtp.invalid"),
            ("SMTP_FROM", "definitely not an address"),
        ]);
        let err = svc
            .send_verification_email("a@example.com", "Alice", "tok")
            .await
            .unwrap_err();
        assert!(err.starts_with("invalid from"), "{err}");

        let svc = service_from(&[
            ("SMTP_HOST", "smtp.invalid"),
            ("SMTP_FROM", "ok@example.com"),
        ]);
        let err = svc
            .send_duplicate_registration_notice("<<not valid>>", "Alice")
            .await
            .unwrap_err();
        assert!(err.starts_with("invalid to"), "{err}");
    }
}
