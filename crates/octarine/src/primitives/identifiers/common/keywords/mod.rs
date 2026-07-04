//! Per-language context keyword dictionaries for identifier confidence scoring.
//!
//! Each identifier type can carry context keywords in multiple languages. The
//! data lives in one file per language (`en.rs`, `de.rs`, …) mirroring
//! Presidio's per-language YAML layout, each declaring a `KEYWORDS` table of
//! `(IdentifierType, &[keyword])`. [`KeywordLanguage`] selects the table.
//!
//! # Design
//!
//! - **No logging / no dependencies** — pure static data (Layer 1 rules).
//! - **Lowercase invariant** — every keyword is lowercase; the analyzer
//!   lowercases the text window before matching.
//! - **Additive** — a language table only lists the identifier types it covers;
//!   an absent type resolves to an empty slice, never a panic.

mod ar;
mod de;
mod en;
mod es;
mod fi;
mod fr;
mod hi;
mod it;
mod ja;
mod ko;
mod pl;
mod sv;
mod th;
mod tr;
mod zh_hans;
mod zh_hant;

/// A language for which context keywords may be defined.
///
/// Covers Presidio's 12 supported languages plus the CJK / Arabic / Hindi
/// scripts octarine already ships for `ApiKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeywordLanguage {
    /// English
    En,
    /// German
    De,
    /// Spanish
    Es,
    /// Finnish
    Fi,
    /// French
    Fr,
    /// Italian
    It,
    /// Japanese
    Ja,
    /// Korean
    Ko,
    /// Polish
    Pl,
    /// Swedish
    Sv,
    /// Thai
    Th,
    /// Turkish
    Tr,
    /// Arabic
    Ar,
    /// Hindi
    Hi,
    /// Chinese (Simplified)
    ZhHans,
    /// Chinese (Traditional)
    ZhHant,
}

impl KeywordLanguage {
    /// Every supported language, in a stable order.
    ///
    /// Used to scan across all languages when no language hint is supplied,
    /// preserving the pre-refactor behavior of matching any known keyword.
    pub const ALL: [KeywordLanguage; 16] = [
        KeywordLanguage::En,
        KeywordLanguage::De,
        KeywordLanguage::Es,
        KeywordLanguage::Fi,
        KeywordLanguage::Fr,
        KeywordLanguage::It,
        KeywordLanguage::Ja,
        KeywordLanguage::Ko,
        KeywordLanguage::Pl,
        KeywordLanguage::Sv,
        KeywordLanguage::Th,
        KeywordLanguage::Tr,
        KeywordLanguage::Ar,
        KeywordLanguage::Hi,
        KeywordLanguage::ZhHans,
        KeywordLanguage::ZhHant,
    ];

    /// Iterate over every supported language.
    pub fn all() -> impl Iterator<Item = KeywordLanguage> {
        Self::ALL.into_iter()
    }

    /// The keyword table for this language.
    ///
    /// Returns `(IdentifierType, &[keyword])` pairs; identifier types absent
    /// from the language resolve to an empty slice in
    /// [`context_keywords`](crate::primitives::identifiers::confidence::context_keywords).
    #[must_use]
    pub(crate) fn keywords(
        self,
    ) -> &'static [(
        crate::primitives::identifiers::IdentifierType,
        &'static [&'static str],
    )] {
        match self {
            KeywordLanguage::En => en::KEYWORDS,
            KeywordLanguage::De => de::KEYWORDS,
            KeywordLanguage::Es => es::KEYWORDS,
            KeywordLanguage::Fi => fi::KEYWORDS,
            KeywordLanguage::Fr => fr::KEYWORDS,
            KeywordLanguage::It => it::KEYWORDS,
            KeywordLanguage::Ja => ja::KEYWORDS,
            KeywordLanguage::Ko => ko::KEYWORDS,
            KeywordLanguage::Pl => pl::KEYWORDS,
            KeywordLanguage::Sv => sv::KEYWORDS,
            KeywordLanguage::Th => th::KEYWORDS,
            KeywordLanguage::Tr => tr::KEYWORDS,
            KeywordLanguage::Ar => ar::KEYWORDS,
            KeywordLanguage::Hi => hi::KEYWORDS,
            KeywordLanguage::ZhHans => zh_hans::KEYWORDS,
            KeywordLanguage::ZhHant => zh_hant::KEYWORDS,
        }
    }
}
