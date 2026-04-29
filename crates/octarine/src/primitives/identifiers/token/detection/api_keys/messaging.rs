//! Messaging and communication API key detection (Telegram, Discord, Slack, Twilio, SendGrid).

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is a Telegram bot token
///
/// Telegram bot tokens have the format `{numeric_id}:{secret}` where
/// the numeric ID is 8-10 digits and the secret is 35 alphanumeric/dash/underscore characters.
#[must_use]
pub fn is_telegram_bot_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_TELEGRAM.is_match(trimmed)
}

/// Check if value is a Discord bot token
///
/// Discord bot tokens have three base64-encoded segments separated by dots.
/// The first segment starts with M or N (base64 encoding of numeric user IDs).
#[must_use]
pub fn is_discord_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_DISCORD_BOT.is_match(trimmed)
}

/// Check if value is a Discord webhook URL
///
/// Discord webhook URLs match `https://discord(app)?.com/api/webhooks/{id}/{token}`
#[must_use]
pub fn is_discord_webhook(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_DISCORD_WEBHOOK.is_match(trimmed)
}

/// Check if value is a Slack token (any format)
///
/// Matches bot (xoxb-), user (xoxp-), app (xapp-), config (xoxe.xoxp-),
/// and legacy (xoxs-, xoxa-) token formats.
#[must_use]
pub fn is_slack_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_SLACK.is_match(trimmed)
}

/// Check if value is a Slack webhook URL
///
/// Matches `https://hooks.slack.com/services/T.../B.../...` format.
#[must_use]
pub fn is_slack_webhook(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_SLACK_WEBHOOK.is_match(trimmed)
}

/// Check if value is a Twilio Account SID
///
/// Twilio Account SIDs start with "AC" followed by 32 lowercase hex characters (34 total).
#[must_use]
pub fn is_twilio_account_sid(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_TWILIO_SID.is_match(trimmed)
}

/// Check if value is a Twilio API Key SID
///
/// Twilio API Key SIDs start with "SK" followed by 32 lowercase hex characters (34 total).
#[must_use]
pub fn is_twilio_api_key_sid(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_TWILIO_API_KEY.is_match(trimmed)
}

/// Check if value is a SendGrid API key
///
/// SendGrid keys start with "SG." followed by two base64-like segments
/// (22 chars, dot, 43 chars).
#[must_use]
pub fn is_sendgrid_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_SENDGRID.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_telegram_bot_token() {
        // Valid: 8-digit ID + 35-char secret
        assert!(is_telegram_bot_token(&format!(
            "12345678:{}",
            "A".repeat(35)
        )));
        // Valid: 10-digit ID + 35-char secret
        assert!(is_telegram_bot_token(&format!(
            "1234567890:{}",
            "ABCDEFghij_-klmnopqrstuv01234567890"
        )));
        // Invalid: numeric prefix too short (7 digits)
        assert!(!is_telegram_bot_token(&format!(
            "1234567:{}",
            "A".repeat(35)
        )));
        // Invalid: numeric prefix too long (11 digits)
        assert!(!is_telegram_bot_token(&format!(
            "12345678901:{}",
            "A".repeat(35)
        )));
        // Invalid: secret too short
        assert!(!is_telegram_bot_token(&format!(
            "12345678:{}",
            "A".repeat(34)
        )));
        // Invalid: no colon separator
        assert!(!is_telegram_bot_token("not-a-telegram-token"));
    }

    #[test]
    fn test_is_discord_token() {
        // Valid: starts with M, 24+ chars, dot, 6 chars, dot, 27+ chars
        assert!(is_discord_token(&format!(
            "M{}.{}.{}",
            "A".repeat(23),
            "AbCdEf",
            "a".repeat(27)
        )));
        // Valid: starts with N
        assert!(is_discord_token(&format!(
            "N{}.{}.{}",
            "B".repeat(25),
            "X1y2Z3",
            "b".repeat(30)
        )));
        // Invalid: starts with A (not M or N)
        assert!(!is_discord_token(&format!(
            "A{}.{}.{}",
            "A".repeat(23),
            "AbCdEf",
            "a".repeat(27)
        )));
        // Invalid: middle segment too short
        assert!(!is_discord_token(&format!(
            "M{}.{}.{}",
            "A".repeat(23),
            "Ab",
            "a".repeat(27)
        )));
        // Invalid: last segment too short
        assert!(!is_discord_token(&format!(
            "M{}.{}.{}",
            "A".repeat(23),
            "AbCdEf",
            "a".repeat(5)
        )));
        assert!(!is_discord_token("not-a-discord-token"));
    }

    #[test]
    fn test_is_discord_webhook() {
        // Valid webhook URL
        assert!(is_discord_webhook(
            "https://discord.com/api/webhooks/123456789/abcdefABCDEF_-0123456789"
        ));
        // Valid with discordapp.com
        assert!(is_discord_webhook(
            "https://discordapp.com/api/webhooks/987654321/tokenvalue123"
        ));
        // Invalid: wrong domain
        assert!(!is_discord_webhook(
            "https://example.com/api/webhooks/123/abc"
        ));
        // Invalid: not a webhook path
        assert!(!is_discord_webhook("https://discord.com/api/users/123"));
        assert!(!is_discord_webhook("not-a-url"));
    }

    #[test]
    fn test_is_slack_token() {
        // Valid: bot token (xoxb-)
        assert!(is_slack_token(&format!(
            "xoxb-{}-{}",
            "1".repeat(12),
            "A".repeat(24)
        )));
        // Valid: user token (xoxp-)
        assert!(is_slack_token(&format!(
            "xoxp-{}-{}",
            "2".repeat(12),
            "b".repeat(32)
        )));
        // Valid: app token (xapp-)
        assert!(is_slack_token(&format!(
            "xapp-{}-{}",
            "3".repeat(10),
            "c".repeat(20)
        )));
        // Invalid: wrong prefix
        assert!(!is_slack_token("xoxz-1234567890-abcdef"));
        // Invalid: too short after prefix
        assert!(!is_slack_token("xoxb-short"));
        assert!(!is_slack_token("not-a-slack-token"));
    }

    #[test]
    fn test_is_slack_webhook() {
        // Valid webhook
        assert!(is_slack_webhook(&format!(
            "https://hooks.slack.com/services/T{}/B{}/{}",
            "A".repeat(10),
            "B".repeat(10),
            "c".repeat(24)
        )));
        // Invalid: wrong domain
        assert!(!is_slack_webhook(
            "https://example.com/services/TABC/BBCD/xyz"
        ));
        // Invalid: not a webhook path
        assert!(!is_slack_webhook("https://hooks.slack.com/api/users"));
        assert!(!is_slack_webhook("not-a-url"));
    }

    #[test]
    fn test_is_twilio_account_sid() {
        // Valid: AC + 32 hex chars
        assert!(is_twilio_account_sid(&format!("AC{}", "a".repeat(32))));
        assert!(is_twilio_account_sid(&format!(
            "AC{}",
            "0123456789abcdef".repeat(2)
        )));
        // Invalid: wrong prefix
        assert!(!is_twilio_account_sid(&format!("AB{}", "a".repeat(32))));
        // Invalid: uppercase hex (pattern requires lowercase)
        assert!(!is_twilio_account_sid(&format!("AC{}", "A".repeat(32))));
        // Invalid: too short
        assert!(!is_twilio_account_sid(&format!("AC{}", "a".repeat(31))));
        // Invalid: too long
        assert!(!is_twilio_account_sid(&format!("AC{}", "a".repeat(33))));
        assert!(!is_twilio_account_sid("not-a-twilio-sid"));
    }

    #[test]
    fn test_is_twilio_api_key_sid() {
        // Valid: SK + 32 hex chars
        assert!(is_twilio_api_key_sid(&format!("SK{}", "a".repeat(32))));
        // Invalid: wrong prefix
        assert!(!is_twilio_api_key_sid(&format!("SL{}", "a".repeat(32))));
        // Invalid: too short
        assert!(!is_twilio_api_key_sid(&format!("SK{}", "a".repeat(31))));
        assert!(!is_twilio_api_key_sid("not-a-twilio-key"));
    }

    #[test]
    fn test_is_sendgrid_key() {
        // Valid: SG. + 22 chars + . + 43 chars
        assert!(is_sendgrid_key(&format!(
            "SG.{}.{}",
            "A".repeat(22),
            "b".repeat(43)
        )));
        // Valid: with underscores and dashes
        assert!(is_sendgrid_key(&format!(
            "SG.{}.{}",
            "Ab_-Cd0123456789012345", "abcdefghijklmnopqrstuvwxyz01234567890123456"
        )));
        // Invalid: wrong prefix
        assert!(!is_sendgrid_key(&format!(
            "XX.{}.{}",
            "A".repeat(22),
            "b".repeat(43)
        )));
        // Invalid: first segment too short
        assert!(!is_sendgrid_key(&format!(
            "SG.{}.{}",
            "A".repeat(21),
            "b".repeat(43)
        )));
        // Invalid: second segment too short
        assert!(!is_sendgrid_key(&format!(
            "SG.{}.{}",
            "A".repeat(22),
            "b".repeat(42)
        )));
        assert!(!is_sendgrid_key("not-a-sendgrid-key"));
    }
}
