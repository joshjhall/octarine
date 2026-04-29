//! Microsoft Azure API key detection (storage keys, connection strings).

use super::super::super::super::common::patterns;
use super::MAX_AZURE_KEY_LENGTH;

/// Check if value is an Azure Storage Account Key
///
/// Azure keys are typically 88 base64 characters in AccountKey=... format
#[must_use]
pub fn is_azure_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_AZURE_KEY_LENGTH {
        return false;
    }
    patterns::network::API_KEY_AZURE.is_match(trimmed)
}

/// Check if value is an Azure connection string (any supported type)
///
/// Detects Azure Storage, Service Bus, Cosmos DB, SQL, and App Configuration
/// connection strings that contain embedded credentials.
#[must_use]
pub fn is_azure_connection_string(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_AZURE_KEY_LENGTH {
        return false;
    }
    patterns::network::AZURE_STORAGE_CONN.is_match(trimmed)
        || patterns::network::AZURE_SERVICE_BUS_CONN.is_match(trimmed)
        || patterns::network::AZURE_COSMOS_CONN.is_match(trimmed)
        || patterns::network::AZURE_SQL_CONN.is_match(trimmed)
        || patterns::network::AZURE_APP_CONFIG_CONN.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_azure_key() {
        assert!(is_azure_key(
            "AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuvwx=="
        ));
        assert!(!is_azure_key("AccountKey=short"));
    }

    #[test]
    fn test_is_azure_connection_string_storage() {
        let key88 = "a".repeat(86) + "==";
        let conn = format!(
            "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey={key88};EndpointSuffix=core.windows.net"
        );
        assert!(is_azure_connection_string(&conn));
    }

    #[test]
    fn test_is_azure_connection_string_service_bus() {
        let key44 = "a".repeat(42) + "==";
        let conn = format!(
            "Endpoint=sb://mybus.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey={key44}"
        );
        assert!(is_azure_connection_string(&conn));
    }

    #[test]
    fn test_is_azure_connection_string_cosmos() {
        let key88 = "a".repeat(86) + "==";
        let conn =
            format!("AccountEndpoint=https://mydb.documents.azure.com:443/;AccountKey={key88}");
        assert!(is_azure_connection_string(&conn));
    }

    #[test]
    fn test_is_azure_connection_string_sql() {
        let conn = "Server=tcp:myserver.database.windows.net,1433;Initial Catalog=mydb;Persist Security Info=False;User ID=admin;Password=secret123;MultipleActiveResultSets=False;Encrypt=True";
        assert!(is_azure_connection_string(conn));
    }

    #[test]
    fn test_is_azure_connection_string_app_config() {
        let secret = "a".repeat(40) + "==";
        let conn = format!("Endpoint=https://myconfig.azconfig.io;Id=abc123;Secret={secret}");
        assert!(is_azure_connection_string(&conn));
    }

    #[test]
    fn test_is_azure_connection_string_rejects_invalid() {
        assert!(!is_azure_connection_string("not a connection string"));
        assert!(!is_azure_connection_string(
            "DefaultEndpointsProtocol=https;AccountName=x"
        ));
        assert!(!is_azure_connection_string(""));
    }
}
