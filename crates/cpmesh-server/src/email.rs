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
    pub fn from_env() -> Self {
        let port_str = std::env::var("SMTP_PORT").unwrap_or_else(|_| "587".to_string());
        let port = port_str.parse().unwrap_or(587);
        let tls_str = std::env::var("SMTP_TLS").unwrap_or_else(|_| "true".to_string());
        let use_tls = !matches!(tls_str.to_lowercase().as_str(), "false" | "0");

        EmailService {
            host: std::env::var("SMTP_HOST").unwrap_or_default(),
            port,
            username: std::env::var("SMTP_USERNAME").unwrap_or_default(),
            password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
            from: std::env::var("SMTP_FROM").unwrap_or_default(),
            use_tls,
            base_url: std::env::var("BASE_URL")
                .unwrap_or_default()
                .trim_end_matches('/')
                .to_string(),
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.host.is_empty() && !self.from.is_empty()
    }

    /// Test SMTP connectivity by sending a test email to the given address.
    pub fn test_connection(&self, to_email: &str) -> Result<(), String> {
        if !self.is_configured() {
            return Err("SMTP not configured (host or from address missing)".to_string());
        }
        let subject = "cpmesh SMTP Test";
        let body = r#"<!DOCTYPE html>
<html><body style="font-family: sans-serif; padding: 20px;">
<h2 style="color: #6366f1;">cpmesh SMTP Test</h2>
<p>If you receive this email, your SMTP configuration is working correctly.</p>
</body></html>"#;
        self.send_html(to_email, subject, body)
    }

    pub fn send_verification_email(
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
            full_name, verify_url, verify_url
        );

        self.send_html(to_email, subject, &body)
    }

    pub fn send_duplicate_registration_notice(
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
            name
        );
        self.send_html(to_email, subject, &body)
    }

    fn send_html(&self, to: &str, subject: &str, html_body: &str) -> Result<(), String> {
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
                .build()
        } else if self.use_tls {
            SmtpTransport::starttls_relay(&self.host)
                .map_err(|e| format!("SMTP STARTTLS: {e}"))?
                .port(self.port)
                .credentials(creds)
                .build()
        } else {
            SmtpTransport::builder_dangerous(&self.host)
                .port(self.port)
                .credentials(creds)
                .build()
        };

        mailer.send(&email).map_err(|e| format!("SMTP send: {e}"))?;
        info!("Verification email sent to {to}");
        Ok(())
    }
}
