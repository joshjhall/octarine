//! XML parsing primitives
//!
//! Pure XML parsing with no security checks. For safe parsing with
//! XXE prevention, use `security::formats` or `runtime::formats`.

use std::collections::HashMap;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::primitives::types::{Problem, Result};

// ============================================================================
// XML Document Types
// ============================================================================

/// Represents a parsed XML document
#[derive(Debug, Clone, PartialEq)]
pub struct XmlDocument {
    /// The root element
    pub root: Option<XmlNode>,
    /// XML declaration version (e.g., "1.0")
    pub version: Option<String>,
    /// XML encoding (e.g., "UTF-8")
    pub encoding: Option<String>,
}

impl XmlDocument {
    /// Create an empty XML document
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: None,
            version: None,
            encoding: None,
        }
    }

    /// Check if the document has a root element
    #[must_use]
    pub fn is_root_present(&self) -> bool {
        self.root.is_some()
    }
}

impl Default for XmlDocument {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents an XML element node
#[derive(Debug, Clone, PartialEq)]
pub struct XmlNode {
    /// Element tag name
    pub name: String,
    /// Element attributes
    pub attributes: HashMap<String, String>,
    /// Child nodes
    pub children: Vec<XmlNode>,
    /// Text content (if any)
    pub text: Option<String>,
}

impl XmlNode {
    /// Create a new XML node with the given name
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            attributes: HashMap::new(),
            children: Vec::new(),
            text: None,
        }
    }

    /// Get an attribute value
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }

    /// Find child elements by name
    #[must_use]
    pub fn find_children(&self, name: &str) -> Vec<&XmlNode> {
        self.children.iter().filter(|c| c.name == name).collect()
    }

    /// Find the first child element by name
    #[must_use]
    pub fn find_child(&self, name: &str) -> Option<&XmlNode> {
        self.children.iter().find(|c| c.name == name)
    }
}

// ============================================================================
// Parsing Functions
// ============================================================================

/// Parse XML string into an XmlDocument
///
/// This is a pure parsing operation with no security checks.
/// For untrusted input, use `runtime::formats::SecureXmlReader`.
///
/// # Warning
///
/// This parser does NOT prevent XXE attacks. For untrusted input,
/// always use the security module's validation first.
pub(crate) fn parse_xml(input: &str) -> Result<XmlDocument> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(true);

    let mut doc = XmlDocument::new();
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Decl(decl)) => {
                if let Ok(version) = decl.version() {
                    doc.version = Some(String::from_utf8_lossy(&version).to_string());
                }
                if let Some(Ok(encoding)) = decl.encoding() {
                    doc.encoding = Some(String::from_utf8_lossy(&encoding).to_string());
                }
            }
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let mut node = XmlNode::new(name);

                // Parse attributes
                for attr in e.attributes().flatten() {
                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                    let value = String::from_utf8_lossy(&attr.value).to_string();
                    node.attributes.insert(key, value);
                }

                stack.push(node);
            }
            Ok(Event::End(_)) => {
                if let Some(completed) = stack.pop() {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(completed);
                    } else {
                        doc.root = Some(completed);
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let mut node = XmlNode::new(name);

                // Parse attributes
                for attr in e.attributes().flatten() {
                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                    let value = String::from_utf8_lossy(&attr.value).to_string();
                    node.attributes.insert(key, value);
                }

                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    doc.root = Some(node);
                }
            }
            Ok(Event::Text(ref e)) => {
                // quick-xml 0.38+: unescape() replaced with decode()
                let text = e.decode().map_err(|e| Problem::Parse(e.to_string()))?;
                let trimmed = text.trim();
                if !trimmed.is_empty()
                    && let Some(current) = stack.last_mut()
                {
                    current.text = Some(trimmed.to_string());
                }
            }
            Ok(Event::CData(ref e)) => {
                let text = String::from_utf8_lossy(e.as_ref()).to_string();
                if let Some(current) = stack.last_mut() {
                    current.text = Some(text);
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {} // Ignore comments, PI, etc.
            Err(e) => {
                return Err(Problem::Parse(format!(
                    "XML parse error at position {}: {}",
                    reader.error_position(),
                    e
                )));
            }
        }
        buf.clear();
    }

    Ok(doc)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_parse_simple_xml() {
        let xml = r#"<?xml version="1.0"?><root><child>text</child></root>"#;
        let doc = parse_xml(xml).expect("valid xml");

        assert_eq!(doc.version, Some("1.0".to_string()));
        assert!(doc.root.is_some());

        let root = doc.root.as_ref().expect("has root");
        assert_eq!(root.name, "root");
        assert_eq!(root.children.len(), 1);

        let child = root
            .children
            .first()
            .expect("root should have at least 1 child");
        assert_eq!(child.name, "child");
        assert_eq!(child.text, Some("text".to_string()));
    }

    #[test]
    fn test_parse_xml_with_attributes() {
        let xml = r#"<root attr1="value1" attr2="value2"/>"#;
        let doc = parse_xml(xml).expect("valid xml");

        let root = doc.root.as_ref().expect("has root");
        assert_eq!(root.attribute("attr1"), Some("value1"));
        assert_eq!(root.attribute("attr2"), Some("value2"));
    }

    #[test]
    fn test_parse_xml_nested() {
        let xml = r#"<a><b><c>deep</c></b></a>"#;
        let doc = parse_xml(xml).expect("valid xml");

        let root = doc.root.as_ref().expect("has root");
        assert_eq!(root.name, "a");

        let b = root.find_child("b").expect("has b");
        let c = b.find_child("c").expect("has c");
        assert_eq!(c.text, Some("deep".to_string()));
    }

    #[test]
    fn test_parse_invalid_xml() {
        // quick_xml is lenient with unclosed tags, so test with malformed XML
        let xml = "<root><</invalid";
        let result = parse_xml(xml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_element() {
        let xml = "<root/>";
        let doc = parse_xml(xml).expect("valid xml");
        assert!(doc.root.is_some());
    }

    #[test]
    fn test_xml_node_find_children() {
        let xml = r#"<root><item>1</item><item>2</item><other>3</other></root>"#;
        let doc = parse_xml(xml).expect("valid xml");

        let root = doc.root.as_ref().expect("has root");
        let items = root.find_children("item");
        assert_eq!(items.len(), 2);
    }
}
