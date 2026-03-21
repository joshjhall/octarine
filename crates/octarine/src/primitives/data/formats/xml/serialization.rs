//! XML serialization primitives
//!
//! Pure XML serialization operations.

use quick_xml::Writer;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};

use crate::primitives::types::{Problem, Result};

use super::parsing::{XmlDocument, XmlNode};

/// Serialize an XmlDocument to an XML string
pub(crate) fn serialize_xml(doc: &XmlDocument) -> Result<String> {
    let mut writer = Writer::new(Vec::new());

    // Write XML declaration if present
    if doc.version.is_some() || doc.encoding.is_some() {
        let version = doc.version.as_deref().unwrap_or("1.0");
        let encoding = doc.encoding.as_deref();
        let decl = BytesDecl::new(version, encoding, None);
        writer
            .write_event(Event::Decl(decl))
            .map_err(|e| Problem::Parse(e.to_string()))?;
    }

    // Write root element if present
    if let Some(ref root) = doc.root {
        write_node(&mut writer, root)?;
    }

    let bytes = writer.into_inner();
    String::from_utf8(bytes).map_err(|e| Problem::Parse(e.to_string()))
}

/// Write a single XML node recursively
fn write_node(writer: &mut Writer<Vec<u8>>, node: &XmlNode) -> Result<()> {
    let mut elem = BytesStart::new(&node.name);

    // Add attributes
    for (key, value) in &node.attributes {
        elem.push_attribute((key.as_str(), value.as_str()));
    }

    // Check if this is an empty element (no children, no text)
    if node.children.is_empty() && node.text.is_none() {
        writer
            .write_event(Event::Empty(elem))
            .map_err(|e| Problem::Parse(e.to_string()))?;
    } else {
        // Write start tag
        writer
            .write_event(Event::Start(elem))
            .map_err(|e| Problem::Parse(e.to_string()))?;

        // Write text content
        if let Some(ref text) = node.text {
            writer
                .write_event(Event::Text(BytesText::new(text)))
                .map_err(|e| Problem::Parse(e.to_string()))?;
        }

        // Write children
        for child in &node.children {
            write_node(writer, child)?;
        }

        // Write end tag
        writer
            .write_event(Event::End(BytesEnd::new(&node.name)))
            .map_err(|e| Problem::Parse(e.to_string()))?;
    }

    Ok(())
}

/// Escape special XML characters in text
#[must_use]
#[allow(dead_code)]
pub(crate) fn escape_xml_text(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '&' => result.push_str("&amp;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&apos;"),
            _ => result.push(c),
        }
    }
    result
}

/// Escape special XML characters in attribute values
#[must_use]
#[allow(dead_code)]
pub(crate) fn escape_xml_attribute(input: &str) -> String {
    // Same escaping as text, but also handle newlines/tabs
    let mut result = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '&' => result.push_str("&amp;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&apos;"),
            '\n' => result.push_str("&#10;"),
            '\r' => result.push_str("&#13;"),
            '\t' => result.push_str("&#9;"),
            _ => result.push(c),
        }
    }
    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_serialize_simple() {
        let mut doc = XmlDocument::new();
        doc.root = Some(XmlNode::new("root"));

        let result = serialize_xml(&doc).expect("valid");
        assert_eq!(result, "<root/>");
    }

    #[test]
    fn test_serialize_with_declaration() {
        let mut doc = XmlDocument::new();
        doc.version = Some("1.0".to_string());
        doc.encoding = Some("UTF-8".to_string());
        doc.root = Some(XmlNode::new("root"));

        let result = serialize_xml(&doc).expect("valid");
        assert!(result.contains("<?xml"));
        assert!(result.contains("version=\"1.0\""));
        assert!(result.contains("encoding=\"UTF-8\""));
    }

    #[test]
    fn test_serialize_with_text() {
        let mut doc = XmlDocument::new();
        let mut root = XmlNode::new("root");
        root.text = Some("content".to_string());
        doc.root = Some(root);

        let result = serialize_xml(&doc).expect("valid");
        assert_eq!(result, "<root>content</root>");
    }

    #[test]
    fn test_serialize_with_attributes() {
        let mut doc = XmlDocument::new();
        let mut root = XmlNode::new("root");
        root.attributes.insert("id".to_string(), "123".to_string());
        doc.root = Some(root);

        let result = serialize_xml(&doc).expect("valid");
        assert!(result.contains("id=\"123\""));
    }

    #[test]
    fn test_serialize_nested() {
        let mut doc = XmlDocument::new();
        let mut root = XmlNode::new("root");
        let child = XmlNode::new("child");
        root.children.push(child);
        doc.root = Some(root);

        let result = serialize_xml(&doc).expect("valid");
        assert!(result.contains("<root>"));
        assert!(result.contains("<child/>"));
        assert!(result.contains("</root>"));
    }

    #[test]
    fn test_escape_xml_text() {
        assert_eq!(escape_xml_text("hello"), "hello");
        assert_eq!(escape_xml_text("<script>"), "&lt;script&gt;");
        assert_eq!(escape_xml_text("a & b"), "a &amp; b");
        assert_eq!(escape_xml_text("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_escape_xml_attribute() {
        assert_eq!(escape_xml_attribute("line1\nline2"), "line1&#10;line2");
        assert_eq!(escape_xml_attribute("tab\there"), "tab&#9;here");
    }
}
