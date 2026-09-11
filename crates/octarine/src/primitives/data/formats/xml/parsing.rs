//! XML parsing primitives
//!
//! Pure XML parsing with no security checks. For safe parsing with
//! XXE prevention, use `security::formats` or `runtime::formats`.

use std::collections::HashMap;

use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

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
/// # Entity references
///
/// In text content **and in attribute values** alike, only the five predefined
/// entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`) and numeric
/// character references (`&#N;`, `&#xN;`) are resolved. Any other reference is
/// rejected with [`Problem::Parse`] rather than being silently dropped. Any
/// character the XML 1.0 `Char` production forbids — NUL and the other C0
/// controls, U+FFFE, U+FFFF — is likewise rejected, whether it arrives through
/// a reference or as a literal byte in text, CDATA or an attribute value. No
/// DTD is consulted and no declared entity is ever expanded,
/// so entity-expansion amplification (billion laughs) terminates here on the
/// first undeclared name instead of recursing.
///
/// # Mixed content
///
/// [`XmlNode`] holds one `text` field, so it cannot represent where character
/// data sat relative to child elements. When an element has both, its text
/// runs are joined with a single space: `<root>before<child/>after</root>`
/// yields `Some("before after")`. A run containing a CDATA section keeps its
/// whitespace verbatim; its siblings are still trimmed. Use the child nodes
/// themselves when the interleaving matters.
///
/// Trimming cannot tell a literal space from one written `&#32;`, so leading
/// and trailing whitespace is dropped either way — `<root>&#32;a&#32;</root>`
/// yields `Some("a")`. Wrap whitespace that must survive in a CDATA section.
///
/// Only a child element starts a new run. A comment or processing instruction
/// does not interrupt character data in XML, so `<root>a<!-- c -->b</root>`
/// yields `Some("ab")`, matching how a conforming parser reads it.
///
/// # Warning
///
/// This parser does NOT prevent XXE attacks. For untrusted input,
/// always use the security module's validation first.
pub(crate) fn parse_xml(input: &str) -> Result<XmlDocument> {
    // Trimming is deliberately NOT enabled on the reader: quick-xml trims each
    // `Text` event independently, which would destroy the whitespace around an
    // entity reference (the reference splits one text run into two events).
    // Text is accumulated raw per element and trimmed once when it closes.
    let mut reader = Reader::from_str(input);

    let mut doc = XmlDocument::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Decl(decl)) => {
                if let Ok(version) = decl.version() {
                    doc.version = Some(version.into_owned());
                }
                if let Some(Ok(encoding)) = decl.encoding() {
                    doc.encoding = Some(encoding.into_owned());
                }
            }
            Ok(Event::Start(ref e)) => {
                stack.push(Frame::new(build_node(e)?));
            }
            Ok(Event::End(_)) => {
                if let Some(frame) = stack.pop() {
                    let completed = frame.finish()?;
                    if let Some(parent) = stack.last_mut() {
                        parent.push_child(completed);
                    } else {
                        doc.root = Some(completed);
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                let node = build_node(e)?;
                if let Some(parent) = stack.last_mut() {
                    parent.push_child(node);
                } else {
                    doc.root = Some(node);
                }
            }
            Ok(Event::Text(ref e)) => {
                // quick-xml 0.42+: events store `Cow<str>`, so content is
                // already `&str` via `Deref` — `decode()` was removed.
                match stack.last_mut() {
                    Some(current) => current.push_text(e),
                    // Prolog/epilog content has no node to belong to and is
                    // discarded, but it is still validated: dropping it
                    // unchecked would let an illegal byte be the difference
                    // between an error and a silent `Ok`.
                    None => validate_xml_chars(e)?,
                }
            }
            Ok(Event::CData(ref e)) => match stack.last_mut() {
                Some(current) => current.push_cdata(e),
                None => validate_xml_chars(e)?,
            },
            Ok(Event::GeneralRef(ref e)) => {
                let resolved = resolve_entity_ref(e)?;
                if let Some(current) = stack.last_mut() {
                    current.push_char(resolved);
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

/// An element that is open on the parse stack, with its accumulated text.
///
/// Character data arrives in pieces — a run split by an entity reference
/// yields several `Text` events plus a `GeneralRef` between them — so text is
/// gathered raw and finalized once at the closing tag rather than per event.
///
/// Pieces are grouped into **runs**: everything between two child elements is
/// one run. `XmlNode` has no representation for mixed content, so the runs of
/// an element that also has children are joined with a single space; without
/// that boundary `<root>before<child/>after</root>` would read as the single
/// word `beforeafter`.
struct Frame {
    /// The element being built
    node: XmlNode,
    /// Character-data runs, split at child-element boundaries
    runs: Vec<Run>,
}

/// One uninterrupted stretch of character data within an element
struct Run {
    /// Raw, untrimmed content
    text: String,
    /// Whether any of it came from a CDATA section
    ///
    /// Tracked per run, not per element: a CDATA section makes *its own* run
    /// verbatim, while sibling runs on the other side of a child element are
    /// still ordinary character data and are trimmed and separated normally.
    is_cdata: bool,
}

impl Frame {
    /// Open a frame for a freshly started element
    fn new(node: XmlNode) -> Self {
        Self {
            node,
            runs: vec![Run::new()],
        }
    }

    /// Append character data to the run currently being read
    fn push_text(&mut self, text: &str) {
        if let Some(run) = self.runs.last_mut() {
            run.text.push_str(text);
        }
    }

    /// Append CDATA content to the run currently being read
    ///
    /// Marks the run verbatim: CDATA whitespace is significant content, so the
    /// trim applied when the element closes must not touch this run.
    fn push_cdata(&mut self, text: &str) {
        if let Some(run) = self.runs.last_mut() {
            run.text.push_str(text);
            run.is_cdata = true;
        }
    }

    /// Append a single resolved character to the run currently being read
    fn push_char(&mut self, ch: char) {
        if let Some(run) = self.runs.last_mut() {
            run.text.push(ch);
        }
    }

    /// Attach a finished child, ending the current run
    ///
    /// Text appearing after the child belongs to a new run, so it is never
    /// concatenated onto the text that preceded the child.
    fn push_child(&mut self, child: XmlNode) {
        self.node.children.push(child);
        self.runs.push(Run::new());
    }

    /// Close the frame, attaching finalized text to the node
    ///
    /// This is the single place every piece of character data passes through,
    /// so it is where the XML 1.0 `Char` production is enforced — covering
    /// literal bytes in text and CDATA as well as resolved references.
    ///
    /// Validation runs on the **raw** text, before any trimming. `str::trim`
    /// strips by `char::is_whitespace`, a set that includes VT (U+000B) and FF
    /// (U+000C) — both of which XML forbids. Trimming first would silently
    /// discard exactly the bytes this check exists to reject.
    fn finish(self) -> Result<XmlNode> {
        let Self { mut node, runs } = self;

        for run in &runs {
            validate_xml_chars(&run.text)?;
        }

        let finalized = runs
            .iter()
            .map(Run::finalize)
            .filter(|run| !run.is_empty())
            .collect::<Vec<_>>()
            .join(" ");

        if !finalized.is_empty() {
            node.text = Some(finalized);
        }
        Ok(node)
    }
}

impl Run {
    /// Start an empty run of ordinary character data
    fn new() -> Self {
        Self {
            text: String::new(),
            is_cdata: false,
        }
    }

    /// The run's content as it should appear in the node
    ///
    /// A run carrying CDATA is verbatim; ordinary character data is trimmed
    /// once, here, rather than per event.
    fn finalize(&self) -> &str {
        if self.is_cdata {
            self.text.as_str()
        } else {
            self.text.trim()
        }
    }
}

/// Build an XmlNode from a start or empty-element event
///
/// Attribute values are normalized the same way text content is: predefined
/// and numeric references resolve, and an undeclared one is an error rather
/// than a value carrying a raw `&name;` the caller would mistake for content.
///
/// Names and attribute keys are validated alongside values: quick-xml does not
/// enforce the XML `Name` production either, so without this a control byte
/// smuggled into a tag name would survive into `XmlNode` while the identical
/// byte in the element's text was rejected.
///
/// A malformed or duplicated attribute is an error, not a silent omission.
/// quick-xml parses attributes lazily, so `Event::Start` arrives intact and
/// each attribute surfaces its own `Err`; discarding those would leave the
/// caller a node quietly missing data — and for a duplicate, one that silently
/// picks a winner. Disagreeing over which of `x="1" x="2"` wins is a classic
/// parser-differential used to slip past attribute-based checks.
fn build_node(e: &BytesStart<'_>) -> Result<XmlNode> {
    let name = e.name().into_inner().to_string();
    validate_xml_chars(&name)?;
    let mut node = XmlNode::new(name);

    for attr in e.attributes() {
        let attr = attr.map_err(|err| {
            Problem::Parse(format!("Invalid XML attribute in '{}': {err}", node.name))
        })?;
        let key = attr.key.into_inner().to_string();
        validate_xml_chars(&key)?;
        let value = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|err| {
                Problem::Parse(format!("Invalid XML attribute value for '{key}': {err}"))
            })?;
        validate_xml_chars(&value)?;
        node.attributes.insert(key, value.into_owned());
    }

    Ok(node)
}

/// Reject characters the XML 1.0 `Char` production forbids
///
/// quick-xml is a non-validating parser: it rejects only `&#0;`, and it copies
/// literal bytes below 0x20 straight through from text, CDATA and names.
/// Any of those routes would otherwise put characters into `XmlNode` that are
/// structurally impossible in well-formed XML and that callers downstream — a
/// log writer, a terminal, an FFI boundary — are entitled to assume absent.
///
/// Every route is checked, so the same byte is not accepted when typed
/// literally and rejected when spelled `&#1;`. Callers must pass **untrimmed**
/// text: `Frame::finish` validates each run's raw content precisely because
/// `str::trim` would otherwise strip VT and FF (which `char::is_whitespace`
/// counts but XML forbids) before this function ever saw them. `build_node`
/// likewise passes the normalized-but-untrimmed attribute value, the element
/// name, and each attribute key.
fn validate_xml_chars(text: &str) -> Result<()> {
    if let Some(ch) = text.chars().find(|c| !is_xml_char(*c)) {
        return Err(Problem::Parse(format!(
            "XML content contains U+{:04X}, which is not permitted in XML 1.0",
            ch as u32
        )));
    }
    Ok(())
}

/// Whether a character is allowed by the XML 1.0 `Char` production
///
/// The production is
/// `#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]`.
/// Rust's `char` already excludes surrogates (`#xD800-#xDFFF`) and
/// out-of-range scalars, leaving two exclusions to enforce: the C0 controls
/// apart from tab, LF and CR, and the BMP noncharacters U+FFFE and U+FFFF —
/// which the grammar drops by stopping that range at `#xFFFD`. The
/// higher-plane noncharacters are inside `[#x10000-#x10FFFF]` and so remain
/// permitted.
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && !matches!(c, '\u{FFFE}' | '\u{FFFF}'))
}

/// Resolve an entity reference to the character it denotes
///
/// Handles numeric character references (`&#N;` and `&#xN;`) and the five
/// entities XML predefines. Any other name is undeclared as far as this
/// parser is concerned — it is rejected rather than dropped, so corrupted
/// content can never be returned as `Ok`.
fn resolve_entity_ref(e: &BytesRef<'_>) -> Result<char> {
    match e.resolve_char_ref() {
        Ok(Some(ch)) => {
            if !is_xml_char(ch) {
                return Err(Problem::Parse(format!(
                    "XML character reference '&{}' resolves to U+{:04X}, \
                     which is not permitted in XML 1.0",
                    e.as_ref(),
                    ch as u32
                )));
            }
            return Ok(ch);
        }
        Ok(None) => {}
        Err(err) => {
            return Err(Problem::Parse(format!(
                "Invalid XML character reference '&{}': {}",
                e.as_ref(),
                err
            )));
        }
    }

    match e.as_ref() {
        "amp" => Ok('&'),
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "quot" => Ok('"'),
        "apos" => Ok('\''),
        name => Err(Problem::Parse(format!(
            "Unresolved XML entity reference '&{name};' \
             (only the predefined entities and numeric references are supported)"
        ))),
    }
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

    /// The bug fixed by #728: an entity reference used to be dropped along
    /// with the text preceding it.
    ///
    /// quick-xml emits a reference as its own `Event::GeneralRef`, splitting
    /// one text run into two `Text` events around it. Before the fix the
    /// catch-all arm swallowed the reference and each `Text` event overwrote
    /// the last, so `<root>a &amp; b</root>` parsed to `Some("b")`.
    #[test]
    fn test_parse_entity_reference_resolves() {
        let xml = "<root>a &amp; b</root>";
        let doc = parse_xml(xml).expect("valid xml");
        let root = doc.root.as_ref().expect("has root");

        assert_eq!(root.text, Some("a & b".to_string()));
    }

    #[test]
    fn test_parse_all_predefined_entities() {
        let xml = "<root>&lt;tag&gt; &quot;quoted&quot; &apos;q&apos; &amp; more</root>";
        let doc = parse_xml(xml).expect("valid xml");
        let root = doc.root.as_ref().expect("has root");

        assert_eq!(root.text, Some("<tag> \"quoted\" 'q' & more".to_string()));
    }

    #[test]
    fn test_parse_numeric_character_references() {
        // Decimal and hex forms of 'A', each embedded mid-run so the fix's
        // accumulation and its resolution have to compose.
        let doc = parse_xml("<root>x&#65;y</root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("xAy".to_string())
        );

        let doc = parse_xml("<root>x&#x41;y</root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("xAy".to_string())
        );
    }

    #[test]
    fn test_parse_unknown_entity_is_rejected() {
        // Undeclared entities fail closed rather than silently corrupting the
        // document. This is also what stops entity-expansion amplification:
        // no DTD is consulted, so nothing recurses.
        let result = parse_xml("<root>a &custom; b</root>");
        assert!(
            matches!(result, Err(Problem::Parse(_))),
            "expected Problem::Parse, got {result:?}"
        );
    }

    #[test]
    fn test_parse_entity_at_text_boundaries() {
        // Leading and trailing references are the cases the old per-event
        // trim destroyed entirely.
        let doc = parse_xml("<root>&amp;x</root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("&x".to_string())
        );

        let doc = parse_xml("<root>x&amp;</root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("x&".to_string())
        );
    }

    #[test]
    fn test_parse_surrounding_whitespace_is_trimmed_once() {
        // Text is accumulated raw and trimmed once per element, so interior
        // spacing around an entity survives while the outer padding does not.
        let doc = parse_xml("<root>   a &amp; b   </root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("a & b".to_string())
        );
    }

    #[test]
    fn test_parse_whitespace_only_text_yields_none() {
        // Guards the removal of reader-level `trim_text`: indentation between
        // child elements must not become text content.
        let xml = "<root>\n  <child>v</child>\n</root>";
        let doc = parse_xml(xml).expect("valid xml");
        let root = doc.root.as_ref().expect("has root");

        assert_eq!(root.text, None);
        assert_eq!(
            root.find_child("child").expect("has child").text,
            Some("v".to_string())
        );
    }

    #[test]
    fn test_parse_declaration_encoding() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?><root/>"#;
        let doc = parse_xml(xml).expect("valid xml");

        assert_eq!(doc.version, Some("1.0".to_string()));
        assert_eq!(doc.encoding, Some("UTF-8".to_string()));
    }

    #[test]
    fn test_parse_cdata_section() {
        let xml = "<root><![CDATA[raw <text> & stuff]]></root>";
        let doc = parse_xml(xml).expect("valid xml");

        let root = doc.root.as_ref().expect("has root");
        assert_eq!(root.text, Some("raw <text> & stuff".to_string()));
    }

    #[test]
    fn test_parse_cdata_preserves_whitespace() {
        // CDATA content is verbatim, so the per-run trim must not apply.
        let xml = "<root><![CDATA[  padded  ]]></root>";
        let doc = parse_xml(xml).expect("valid xml");
        let root = doc.root.as_ref().expect("has root");

        assert_eq!(root.text, Some("  padded  ".to_string()));
    }

    #[test]
    fn test_entity_round_trips_through_serialize() {
        use super::super::serialization::serialize_xml;

        let doc = parse_xml("<root>a &amp; b</root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("a & b".to_string())
        );

        // The serializer escapes on the way out, so the raw '&' becomes
        // '&amp;' again and a second parse lands on the same document.
        let serialized = serialize_xml(&doc).expect("serializes");
        assert_eq!(serialized, "<root>a &amp; b</root>");
        assert_eq!(parse_xml(&serialized).expect("valid xml"), doc);
    }

    #[test]
    fn test_parse_attribute_entities_are_resolved() {
        // Attribute values go through the same resolution as text content —
        // before the fix they carried the raw `&amp;` through verbatim.
        let doc =
            parse_xml(r#"<root a="x &amp; y" b="&#65;" c="&lt;tag&gt;"/>"#).expect("valid xml");
        let root = doc.root.as_ref().expect("has root");

        assert_eq!(root.attribute("a"), Some("x & y"));
        assert_eq!(root.attribute("b"), Some("A"));
        assert_eq!(root.attribute("c"), Some("<tag>"));
    }

    #[test]
    fn test_parse_unknown_attribute_entity_is_rejected() {
        let result = parse_xml(r#"<root a="&custom;"/>"#);
        assert!(
            matches!(result, Err(Problem::Parse(_))),
            "expected Problem::Parse, got {result:?}"
        );
    }

    #[test]
    fn test_parse_mixed_content_keeps_runs_separate() {
        // Text before and after a child must not be glued into one word.
        let doc = parse_xml("<root>before<child>x</child>after</root>").expect("valid xml");
        let root = doc.root.as_ref().expect("has root");

        assert_eq!(root.text, Some("before after".to_string()));
        assert_eq!(
            root.find_child("child").expect("has child").text,
            Some("x".to_string())
        );
    }

    #[test]
    fn test_parse_control_character_reference_is_rejected() {
        // quick-xml rejects only `&#0;`; the other C0 controls are equally
        // illegal in XML 1.0 and must not reach XmlNode.
        for xml in [
            "<root>a&#0;b</root>",
            "<root>a&#1;b</root>",
            "<root>a&#x7;b</root>",
        ] {
            let result = parse_xml(xml);
            assert!(
                matches!(result, Err(Problem::Parse(_))),
                "expected Problem::Parse for {xml}, got {result:?}"
            );
        }

        // Tab, LF and CR are the permitted exceptions.
        let doc = parse_xml("<root>a&#9;b</root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("a\tb".to_string())
        );
    }

    #[test]
    fn test_parse_malformed_numeric_reference_is_rejected() {
        // Exercises resolve_char_ref's Err branch, distinct from an unknown name.
        let result = parse_xml("<root>a&#xZZ;b</root>");
        assert!(
            matches!(result, Err(Problem::Parse(_))),
            "expected Problem::Parse, got {result:?}"
        );
    }

    #[test]
    fn test_parse_cdata_mixed_with_text_keeps_whitespace() {
        // The run carrying the CDATA is verbatim, so the plain-text
        // whitespace that shares that run survives with it.
        let doc = parse_xml("<root>  <![CDATA[x]]>  </root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("  x  ".to_string())
        );
    }

    #[test]
    fn test_parse_cdata_beside_child_still_separates_runs() {
        // A CDATA section makes its OWN run verbatim; runs on the far side of
        // a child element are still separated. Tracking CDATA per element
        // instead of per run silently re-glued these into "xYZ".
        let doc = parse_xml("<root>x<![CDATA[Y]]><child/>Z</root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("xY Z".to_string())
        );
    }

    #[test]
    fn test_parse_literal_control_byte_is_rejected() {
        // quick-xml copies raw bytes below 0x20 straight through, so the same
        // character must be rejected whether typed literally or written as a
        // reference — in text, in CDATA, and in an attribute value.
        for xml in [
            "<root>a\u{1}b</root>",
            "<root><![CDATA[a\u{1}b]]></root>",
            "<root attr=\"a\u{1}b\"/>",
        ] {
            let result = parse_xml(xml);
            assert!(
                matches!(result, Err(Problem::Parse(_))),
                "expected Problem::Parse for {xml:?}, got {result:?}"
            );
        }
    }

    #[test]
    fn test_parse_noncharacter_reference_is_rejected() {
        // XML 1.0's Char production stops the BMP range at #xFFFD, so the two
        // noncharacters are excluded even though Rust's `char` permits them.
        for xml in ["<root>a&#xFFFE;b</root>", "<root>a&#xFFFF;b</root>"] {
            let result = parse_xml(xml);
            assert!(
                matches!(result, Err(Problem::Parse(_))),
                "expected Problem::Parse for {xml}, got {result:?}"
            );
        }

        // U+FFFD itself, and the higher-plane noncharacters, stay legal.
        let doc = parse_xml("<root>a&#xFFFD;b</root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("a\u{FFFD}b".to_string())
        );
    }

    #[test]
    fn test_parse_attribute_control_and_malformed_refs_are_rejected() {
        // The attribute-side rejection paths, which had no coverage.
        for xml in [
            r#"<root a="&#1;"/>"#,
            r#"<root a="&#0;"/>"#,
            r#"<root a="&#xZZ;"/>"#,
        ] {
            let result = parse_xml(xml);
            assert!(
                matches!(result, Err(Problem::Parse(_))),
                "expected Problem::Parse for {xml}, got {result:?}"
            );
        }
    }

    #[test]
    fn test_parse_whitespace_control_bytes_are_rejected_not_trimmed() {
        // VT and FF are Unicode whitespace, so `str::trim` strips them — but
        // XML forbids both. Validating after trimming would silently drop the
        // very bytes the check exists to reject.
        for xml in [
            "<root>\u{B}</root>",
            "<root>\u{B}text</root>",
            "<root>text\u{C}</root>",
            "<root>a\u{B}b</root>",
        ] {
            let result = parse_xml(xml);
            assert!(
                matches!(result, Err(Problem::Parse(_))),
                "expected Problem::Parse for {xml:?}, got {result:?}"
            );
        }
    }

    #[test]
    fn test_parse_illegal_byte_outside_root_is_rejected() {
        // Prolog/epilog character data is discarded, but discarding it
        // unchecked would make an illegal byte the difference between an
        // error and a silent Ok.
        let result = parse_xml("<root/>\u{1}");
        assert!(
            matches!(result, Err(Problem::Parse(_))),
            "expected Problem::Parse, got {result:?}"
        );
    }

    #[test]
    fn test_parse_reference_produced_boundary_space_is_trimmed() {
        // Documents a real limitation: once resolved, `&#32;` is an ordinary
        // space and the per-run trim cannot tell it from literal padding.
        let doc = parse_xml("<root>&#32;a&#32;</root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("a".to_string())
        );

        // CDATA is the escape hatch for whitespace that must survive.
        let doc = parse_xml("<root><![CDATA[ a ]]></root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some(" a ".to_string())
        );
    }

    #[test]
    fn test_parse_illegal_byte_in_names_is_rejected() {
        // quick-xml does not enforce the `Name` production, so without an
        // explicit check a control byte in a tag or attribute name would
        // survive into XmlNode while the same byte in text was rejected.
        for xml in ["<ro\u{1}ot/>", "<root a\u{1}b=\"v\"/>"] {
            let result = parse_xml(xml);
            assert!(
                matches!(result, Err(Problem::Parse(_))),
                "expected Problem::Parse for {xml:?}, got {result:?}"
            );
        }
    }

    #[test]
    fn test_parse_comment_does_not_split_text_run() {
        // A comment or PI is not a child element and does not interrupt
        // character data, so the surrounding text stays one run — unlike the
        // child-element case, which is deliberately separated.
        let doc = parse_xml("<root>a<!-- c -->b</root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("ab".to_string())
        );

        let doc = parse_xml("<root>a<?pi x?>b</root>").expect("valid xml");
        assert_eq!(
            doc.root.as_ref().expect("has root").text,
            Some("ab".to_string())
        );
    }

    #[test]
    fn test_parse_epilog_entity_reference() {
        // A reference after the root closes has no node to land in and is
        // discarded, but an illegal numeric one still errors via
        // resolve_entity_ref's own check.
        let doc = parse_xml("<root/>&amp;").expect("valid xml");
        assert_eq!(doc.root.as_ref().expect("has root").name, "root");

        let result = parse_xml("<root/>&#1;");
        assert!(
            matches!(result, Err(Problem::Parse(_))),
            "expected Problem::Parse, got {result:?}"
        );
    }

    #[test]
    fn test_parse_duplicate_attribute_is_rejected() {
        // Silently keeping the first of `x="1" x="2"` makes this parser
        // disagree with others about which value wins — the classic
        // parser-differential used to slip past attribute-based checks.
        let result = parse_xml(r#"<root x="1" x="2"/>"#);
        assert!(
            matches!(result, Err(Problem::Parse(_))),
            "expected Problem::Parse, got {result:?}"
        );
    }

    #[test]
    fn test_parse_malformed_attribute_is_rejected() {
        // A bare `key` with no value used to vanish from the node entirely,
        // handing the caller a document quietly missing data.
        let result = parse_xml(r#"<root key another="v"/>"#);
        assert!(
            matches!(result, Err(Problem::Parse(_))),
            "expected Problem::Parse, got {result:?}"
        );
    }

    #[test]
    fn test_parse_prolog_entity_reference() {
        // The prolog counterpart of test_parse_epilog_entity_reference: the
        // stack is empty before the root starts, too.
        let doc = parse_xml("&amp;<root/>").expect("valid xml");
        assert_eq!(doc.root.as_ref().expect("has root").name, "root");

        let result = parse_xml("&#1;<root/>");
        assert!(
            matches!(result, Err(Problem::Parse(_))),
            "expected Problem::Parse, got {result:?}"
        );
    }
}
