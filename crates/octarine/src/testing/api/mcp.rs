//! MCP (Model Context Protocol) Testing Utilities
//!
//! Helpers for testing MCP servers and clients.
//!
//! MCP is a protocol for communication between AI models and tools.
//! This module provides utilities for mocking MCP interactions.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// MCP request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    /// JSON-RPC version
    pub jsonrpc: String,
    /// Request ID
    pub id: u64,
    /// Method name
    pub method: String,
    /// Parameters
    #[serde(default)]
    pub params: Value,
}

impl McpRequest {
    /// Create a new MCP request
    pub fn new(id: u64, method: &str, params: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.to_string(),
            params,
        }
    }

    /// Create an initialize request
    pub fn initialize(id: u64) -> Self {
        Self::new(
            id,
            "initialize",
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }),
        )
    }

    /// Create a tools/list request
    pub fn list_tools(id: u64) -> Self {
        Self::new(id, "tools/list", serde_json::json!({}))
    }

    /// Create a tools/call request
    pub fn call_tool(id: u64, name: &str, arguments: Value) -> Self {
        Self::new(
            id,
            "tools/call",
            serde_json::json!({
                "name": name,
                "arguments": arguments
            }),
        )
    }

    /// Create a resources/list request
    pub fn list_resources(id: u64) -> Self {
        Self::new(id, "resources/list", serde_json::json!({}))
    }

    /// Create a resources/read request
    pub fn read_resource(id: u64, uri: &str) -> Self {
        Self::new(
            id,
            "resources/read",
            serde_json::json!({
                "uri": uri
            }),
        )
    }
}

/// MCP response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    /// JSON-RPC version
    pub jsonrpc: String,
    /// Request ID
    pub id: u64,
    /// Result (success case)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error (failure case)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpError>,
}

/// MCP error structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
    /// Additional data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl McpResponse {
    /// Create a success response
    pub fn success(id: u64, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(id: u64, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(McpError {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }

    /// Create an initialize response
    pub fn initialize_response(id: u64) -> Self {
        Self::success(
            id,
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {}
                },
                "serverInfo": {
                    "name": "test-server",
                    "version": "1.0.0"
                }
            }),
        )
    }

    /// Create a tools/list response
    pub fn tools_list_response(id: u64, tools: Vec<McpTool>) -> Self {
        Self::success(id, serde_json::json!({ "tools": tools }))
    }

    /// Create a tools/call response
    pub fn tool_result(id: u64, content: Vec<McpContent>) -> Self {
        Self::success(id, serde_json::json!({ "content": content }))
    }
}

/// MCP Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    /// Tool name
    pub name: String,
    /// Tool description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Input schema (JSON Schema)
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

impl McpTool {
    /// Create a new tool definition
    pub fn new(name: &str, description: &str, input_schema: Value) -> Self {
        Self {
            name: name.to_string(),
            description: Some(description.to_string()),
            input_schema,
        }
    }

    /// Create a simple tool with no parameters
    pub fn simple(name: &str, description: &str) -> Self {
        Self::new(
            name,
            description,
            serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        )
    }
}

/// MCP Content block
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum McpContent {
    /// Text content
    #[serde(rename = "text")]
    Text {
        /// The text content
        text: String,
    },
    /// Image content
    #[serde(rename = "image")]
    Image {
        /// Base64-encoded image data
        data: String,
        /// MIME type of the image
        mime_type: String,
    },
    /// Resource content
    #[serde(rename = "resource")]
    Resource {
        /// The resource content
        resource: McpResourceContent,
    },
}

/// MCP Resource content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResourceContent {
    /// Resource URI
    pub uri: String,
    /// MIME type
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Text content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl McpContent {
    /// Create text content
    pub fn text(text: &str) -> Self {
        Self::Text {
            text: text.to_string(),
        }
    }
}

/// Mock MCP server for testing
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::api::mcp::MockMcpServer;
///
/// let mut server = MockMcpServer::new();
///
/// server.register_tool(McpTool::simple("hello", "Say hello"));
/// server.register_handler("hello", |_params| {
///     Ok(vec![McpContent::text("Hello, world!")])
/// });
///
/// let request = McpRequest::call_tool(1, "hello", serde_json::json!({}));
/// let response = server.handle(request);
/// ```
pub struct MockMcpServer {
    tools: Vec<McpTool>,
    handlers: HashMap<String, Box<dyn Fn(Value) -> Result<Vec<McpContent>, String>>>,
}

impl Default for MockMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl MockMcpServer {
    /// Create a new mock MCP server
    pub fn new() -> Self {
        Self {
            tools: Vec::new(),
            handlers: HashMap::new(),
        }
    }

    /// Register a tool
    pub fn register_tool(&mut self, tool: McpTool) {
        self.tools.push(tool);
    }

    /// Register a tool handler
    pub fn register_handler<F>(&mut self, name: &str, handler: F)
    where
        F: Fn(Value) -> Result<Vec<McpContent>, String> + 'static,
    {
        self.handlers.insert(name.to_string(), Box::new(handler));
    }

    /// Handle an MCP request
    pub fn handle(&self, request: McpRequest) -> McpResponse {
        match request.method.as_str() {
            "initialize" => McpResponse::initialize_response(request.id),

            "tools/list" => McpResponse::tools_list_response(request.id, self.tools.clone()),

            "tools/call" => {
                let name = request
                    .params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let arguments = request.params.get("arguments").cloned().unwrap_or_default();

                if let Some(handler) = self.handlers.get(name) {
                    match handler(arguments) {
                        Ok(content) => McpResponse::tool_result(request.id, content),
                        Err(e) => McpResponse::error(request.id, -32000, &e),
                    }
                } else {
                    McpResponse::error(request.id, -32601, &format!("Tool not found: {}", name))
                }
            }

            _ => McpResponse::error(
                request.id,
                -32601,
                &format!("Method not found: {}", request.method),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_mcp_request_initialize() {
        let req = McpRequest::initialize(1);
        assert_eq!(req.method, "initialize");
        assert_eq!(req.id, 1);
    }

    #[test]
    fn test_mcp_request_call_tool() {
        let req = McpRequest::call_tool(2, "my_tool", serde_json::json!({"arg": "value"}));
        assert_eq!(req.method, "tools/call");
        assert_eq!(req.params.get("name").expect("should have name"), "my_tool");
    }

    #[test]
    fn test_mcp_response_success() {
        let resp = McpResponse::success(1, serde_json::json!({"result": "ok"}));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_mcp_response_error() {
        let resp = McpResponse::error(1, -32600, "Invalid request");
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        assert_eq!(
            resp.error.as_ref().expect("Error should be present").code,
            -32600
        );
    }

    #[test]
    fn test_mock_server_initialize() {
        let server = MockMcpServer::new();
        let req = McpRequest::initialize(1);
        let resp = server.handle(req);

        assert!(resp.result.is_some());
        assert_eq!(
            resp.result
                .as_ref()
                .expect("Result should be present")
                .get("protocolVersion")
                .expect("should have protocolVersion"),
            "2024-11-05"
        );
    }

    #[test]
    fn test_mock_server_tools_list() {
        let mut server = MockMcpServer::new();
        server.register_tool(McpTool::simple("test_tool", "A test tool"));

        let req = McpRequest::list_tools(1);
        let resp = server.handle(req);

        let tools = resp
            .result
            .as_ref()
            .expect("Result should be present")
            .get("tools")
            .expect("should have tools");
        assert_eq!(tools.as_array().expect("Tools should be an array").len(), 1);
        assert_eq!(
            tools
                .as_array()
                .expect("tools is array")
                .first()
                .expect("should have tool 0")
                .get("name")
                .expect("tool should have name"),
            "test_tool"
        );
    }

    #[test]
    fn test_mock_server_tool_call() {
        let mut server = MockMcpServer::new();
        server.register_tool(McpTool::simple("greet", "Greet someone"));
        server.register_handler("greet", |params| {
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("World");
            Ok(vec![McpContent::text(&format!("Hello, {}!", name))])
        });

        let req = McpRequest::call_tool(1, "greet", serde_json::json!({"name": "Alice"}));
        let resp = server.handle(req);

        let content = resp
            .result
            .as_ref()
            .expect("Result should be present")
            .get("content")
            .expect("should have content");
        assert_eq!(
            content
                .as_array()
                .expect("content is array")
                .first()
                .expect("should have content item 0")
                .get("text")
                .expect("content should have text"),
            "Hello, Alice!"
        );
    }

    #[test]
    fn test_mock_server_unknown_tool() {
        let server = MockMcpServer::new();
        let req = McpRequest::call_tool(1, "unknown", serde_json::json!({}));
        let resp = server.handle(req);

        assert!(resp.error.is_some());
        assert!(
            resp.error
                .as_ref()
                .expect("Error should be present")
                .message
                .contains("not found")
        );
    }
}
