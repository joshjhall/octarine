//! Korean (`ko`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/ko`
//! files and language YAMLs with attribution. Keywords are lowercase — the
//! analyzer lowercases the text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Korean context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &["주민등록번호", "주민번호", "사회보장번호", "납세자번호"],
    ),
    (
        IdentifierType::CreditCard,
        &["신용카드", "카드번호", "카드 번호", "체크카드"],
    ),
    (
        IdentifierType::Email,
        &["이메일", "이메일 주소", "전자우편"],
    ),
    (
        IdentifierType::PhoneNumber,
        &["전화번호", "휴대전화", "휴대폰 번호", "핸드폰"],
    ),
    (
        IdentifierType::BankAccount,
        &[
            "은행 계좌",
            "계좌 번호",
            "계좌번호",
            "계좌",
            "iban",
            "swift",
            "bic",
        ],
    ),
    (IdentifierType::RoutingNumber, &["은행 코드", "지점 코드"]),
    (
        IdentifierType::DriverLicense,
        &["운전면허증", "운전면허", "면허번호"],
    ),
    (IdentifierType::Passport, &["여권", "여권번호", "여권 번호"]),
    (IdentifierType::Birthdate, &["생년월일", "생일", "출생일"]),
    (
        IdentifierType::IpAddress,
        &["ip 주소", "아이피 주소", "네트워크 주소"],
    ),
    (IdentifierType::ApiKey, &["api키", "인증", "토큰", "비밀키"]),
    (
        IdentifierType::PersonalName,
        &["이름", "성명", "성함", "전체 이름"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "국제 계좌번호", "bic", "swift"],
    ),
    (
        IdentifierType::KoreaRrn,
        &["주민등록번호", "주민번호", "주민등록", "등록번호"],
    ),
];
