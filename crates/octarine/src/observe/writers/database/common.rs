//! Shared logic for SQL database backends
//!
//! Both the SQLite and PostgreSQL backends build the same WHERE clauses,
//! parse the same enum column values, and assemble the same [`Event`] from a
//! fetched row. Only the SQL dialect and the row-extraction types differ, so
//! that shared logic lives here and each backend supplies just its own
//! dialect and column coercion.
//!
//! This module is compiled only when at least one SQL backend feature is
//! enabled, and every item is `pub(super)` — none of it is public API.

use crate::observe::types::{Event, EventContext, EventType, Severity, TenantId, UserId};

use super::query::AuditQuery;
use super::traits::QueryResult;

/// SQL dialect differences that affect WHERE-clause construction
///
/// The two backends differ in exactly two ways when building a clause:
/// how a bind placeholder is spelled, and how a boolean `true` is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SqlDialect {
    /// SQLite — bare `?` placeholders, booleans stored as `INTEGER`
    Sqlite,
    /// PostgreSQL — `$N` positional placeholders, native `BOOLEAN`
    Postgres,
}

impl SqlDialect {
    /// The literal this dialect uses for a true boolean column value
    ///
    /// SQLite has no boolean type — the schema declares these columns
    /// `INTEGER`, so a `= TRUE` predicate would not match stored rows.
    fn true_literal(self) -> &'static str {
        match self {
            Self::Sqlite => "1",
            Self::Postgres => "TRUE",
        }
    }
}

/// Allocates bind placeholders in the dialect's spelling
///
/// Postgres placeholders are positional (`$1`, `$2`, ...) so the index must
/// advance across every bound value, including each element of a multi-value
/// `IN` expansion. SQLite's are anonymous and bound in order, so it ignores
/// the index entirely.
struct PlaceholderAllocator {
    dialect: SqlDialect,
    next_index: usize,
}

impl PlaceholderAllocator {
    fn new(dialect: SqlDialect) -> Self {
        Self {
            dialect,
            next_index: 1,
        }
    }

    /// Produce the next placeholder, advancing the positional index
    fn next(&mut self) -> String {
        match self.dialect {
            SqlDialect::Sqlite => "?".to_string(),
            SqlDialect::Postgres => {
                let placeholder = format!("${}", self.next_index);
                self.next_index = self.next_index.saturating_add(1);
                placeholder
            }
        }
    }
}

/// Build the WHERE clause and bind values from a query
///
/// Returns a `(sql, params)` tuple. The SQL uses `dialect`-appropriate
/// placeholders for every caller-supplied value; the caller must chain
/// `.bind()` over `params` in the same order before executing. Enum- and
/// boolean-constrained conditions are interpolated directly because they are
/// not attacker-influenced.
pub(super) fn build_where_clause(query: &AuditQuery, dialect: SqlDialect) -> (String, Vec<String>) {
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();
    let mut placeholders = PlaceholderAllocator::new(dialect);

    if let Some(since) = query.since {
        conditions.push(format!("timestamp >= {}", placeholders.next()));
        params.push(since.to_rfc3339());
    }

    if let Some(until) = query.until {
        conditions.push(format!("timestamp < {}", placeholders.next()));
        params.push(until.to_rfc3339());
    }

    if let Some(ref types) = query.event_types {
        let expanded: Vec<String> = types.iter().map(|_| placeholders.next()).collect();
        conditions.push(format!("event_type IN ({})", expanded.join(", ")));
        for t in types {
            params.push(format!("{t:?}"));
        }
    }

    if let Some(min_severity) = query.min_severity {
        // Map severity to numeric for comparison
        let severity_val = match min_severity {
            Severity::Debug => 0,
            Severity::Info => 1,
            Severity::Warning => 2,
            Severity::Error => 3,
            Severity::Critical => 4,
        };
        conditions.push(format!(
            "CASE severity \
             WHEN 'Debug' THEN 0 \
             WHEN 'Info' THEN 1 \
             WHEN 'Warning' THEN 2 \
             WHEN 'Error' THEN 3 \
             WHEN 'Critical' THEN 4 \
             ELSE 0 END >= {severity_val}"
        ));
    }

    if let Some(ref tenant) = query.tenant_id {
        conditions.push(format!("tenant_id = {}", placeholders.next()));
        params.push(tenant.clone());
    }

    if let Some(ref user) = query.user_id {
        conditions.push(format!("user_id = {}", placeholders.next()));
        params.push(user.clone());
    }

    if let Some(corr) = query.correlation_id {
        conditions.push(format!("correlation_id = {}", placeholders.next()));
        params.push(corr.to_string());
    }

    if let Some(ref resource_type) = query.resource_type {
        conditions.push(format!("resource_type = {}", placeholders.next()));
        params.push(resource_type.clone());
    }

    if let Some(ref resource_id) = query.resource_id {
        conditions.push(format!("resource_id = {}", placeholders.next()));
        params.push(resource_id.clone());
    }

    let true_literal = dialect.true_literal();

    if query.security_relevant_only {
        conditions.push(format!("security_relevant = {true_literal}"));
    }

    if query.contains_pii_only {
        conditions.push(format!("contains_pii = {true_literal}"));
    }

    if query.contains_phi_only {
        conditions.push(format!("contains_phi = {true_literal}"));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    (where_clause, params)
}

/// The two SQL statements and bind values needed to serve one [`AuditQuery`]
///
/// Both statements share the same WHERE clause and the same ordered bind
/// values, so they are built together and bound identically by the caller.
pub(super) struct QueryPlan {
    /// `SELECT` returning the page of matching events
    pub select_sql: String,
    /// `SELECT COUNT(*)` returning the unpaginated total
    pub count_sql: String,
    /// Bind values, in the order the placeholders appear in both statements
    pub params: Vec<String>,
}

/// Build the SELECT and COUNT statements for a query
///
/// `ORDER BY`, `LIMIT`, and `OFFSET` are interpolated rather than bound:
/// the direction comes from a bool and the two bounds are `usize`, so none of
/// them can carry caller-supplied text. Every actual value is a placeholder.
pub(super) fn build_query_plan(query: &AuditQuery, dialect: SqlDialect) -> QueryPlan {
    let (where_clause, params) = build_where_clause(query, dialect);

    let order = if query.ascending { "ASC" } else { "DESC" };
    let limit_clause = query
        .limit
        .map(|l| format!("LIMIT {l}"))
        .unwrap_or_default();
    let offset_clause = query
        .offset
        .map(|o| format!("OFFSET {o}"))
        .unwrap_or_default();

    QueryPlan {
        select_sql: format!(
            "SELECT * FROM audit_events {where_clause} ORDER BY timestamp {order} {limit_clause} {offset_clause}"
        ),
        count_sql: format!("SELECT COUNT(*) as count FROM audit_events {where_clause}"),
        params,
    }
}

/// Assemble the final [`QueryResult`] from a fetched page and total count
///
/// `has_more` is inferred from the page being full: if the caller asked for a
/// limit and got at least that many rows, another page may exist. A limit of
/// zero is excluded — `events.len() >= 0` holds vacuously, which would report
/// a further page for a query that asked for no rows at all.
pub(super) fn assemble_query_result(
    events: Vec<Event>,
    total_count: i64,
    query: &AuditQuery,
) -> QueryResult {
    let has_more = query.limit.is_some_and(|l| l > 0 && events.len() >= l);

    QueryResult {
        events,
        total_count: Some(total_count as usize),
        has_more,
        parse_errors: Vec::new(),
    }
}

/// Parse a stored `event_type` column value back into an [`EventType`]
///
/// Values are written with `format!("{:?}", event_type)`. An unrecognised
/// value degrades to [`EventType::Info`] rather than failing the read — an
/// audit row from a newer schema is still worth surfacing.
pub(super) fn parse_event_type(s: &str) -> EventType {
    match s {
        "ValidationError" => EventType::ValidationError,
        "ConversionError" => EventType::ConversionError,
        "SanitizationError" => EventType::SanitizationError,
        "AuthenticationError" => EventType::AuthenticationError,
        "AuthorizationError" => EventType::AuthorizationError,
        "SystemError" => EventType::SystemError,
        "ValidationSuccess" => EventType::ValidationSuccess,
        "AuthenticationSuccess" => EventType::AuthenticationSuccess,
        "LoginSuccess" => EventType::LoginSuccess,
        "LoginFailure" => EventType::LoginFailure,
        "ResourceCreated" => EventType::ResourceCreated,
        "ResourceUpdated" => EventType::ResourceUpdated,
        "ResourceDeleted" => EventType::ResourceDeleted,
        "SystemStartup" => EventType::SystemStartup,
        "SystemShutdown" => EventType::SystemShutdown,
        "HealthCheck" => EventType::HealthCheck,
        "Debug" => EventType::Debug,
        "Warning" => EventType::Warning,
        _ => EventType::Info,
    }
}

/// Parse a stored `severity` column value back into a [`Severity`]
///
/// An unrecognised value degrades to [`Severity::Info`], matching
/// [`parse_event_type`].
pub(super) fn parse_severity(s: &str) -> Severity {
    match s {
        "Debug" => Severity::Debug,
        "Info" => Severity::Info,
        "Warning" => Severity::Warning,
        "Error" => Severity::Error,
        "Critical" => Severity::Critical,
        _ => Severity::Info,
    }
}

/// One `audit_events` row with every column already coerced to its native type
///
/// Each backend extracts columns using its own row type and coercion rules
/// (SQLite parses UUIDs and timestamps from `TEXT` and booleans from
/// `INTEGER`; PostgreSQL reads them natively), then hands the results here so
/// the [`Event`] assembly itself is written once.
pub(super) struct EventRow {
    /// Event identifier (`id` column)
    pub id: uuid::Uuid,
    /// When the event occurred (`timestamp` column)
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Raw `event_type` column value, parsed by [`parse_event_type`]
    pub event_type: String,
    /// Raw `severity` column value, parsed by [`parse_severity`]
    pub severity: String,
    /// Human-readable event message
    pub message: String,
    /// Operation that produced the event
    pub operation: String,
    /// Owning tenant, if the deployment is multi-tenant
    pub tenant_id: Option<String>,
    /// Acting user, if known
    pub user_id: Option<String>,
    /// Correlation identifier tying related events together
    pub correlation_id: uuid::Uuid,
    /// Type of the resource acted upon
    pub resource_type: Option<String>,
    /// Identifier of the resource acted upon
    pub resource_id: Option<String>,
    /// Module path of the emitting call site
    pub module_path: String,
    /// Source file of the emitting call site
    pub file: String,
    /// Source line of the emitting call site
    pub line: u32,
    /// Whether the event payload contains PII
    pub contains_pii: bool,
    /// Whether the event payload contains PHI
    pub contains_phi: bool,
    /// Whether the event is security-relevant
    pub security_relevant: bool,
    /// Free-form metadata stored as JSON
    pub metadata: Option<serde_json::Value>,
}

/// Assemble a fetched row into an [`Event`]
///
/// Fields that are not persisted by the `audit_events` schema (session id,
/// span parent, IP context, environment, PII type list) are left at their
/// defaults.
pub(super) fn assemble_event(row: EventRow) -> Event {
    let context = EventContext {
        operation: row.operation,
        tenant_id: row.tenant_id.and_then(|s| TenantId::new(&s).ok()),
        user_id: row.user_id.and_then(|s| UserId::new(&s).ok()),
        session_id: None,
        correlation_id: row.correlation_id,
        parent_span_id: None,
        resource_type: row.resource_type,
        resource_id: row.resource_id,
        module_path: row.module_path,
        file: row.file,
        line: row.line,
        local_ip: None,
        source_ip: None,
        source_ip_chain: Vec::new(),
        environment: None,
        contains_pii: row.contains_pii,
        contains_phi: row.contains_phi,
        security_relevant: row.security_relevant,
        pii_types: Vec::new(),
        compliance: Default::default(),
    };

    Event {
        id: row.id,
        timestamp: row.timestamp,
        event_type: parse_event_type(&row.event_type),
        severity: parse_severity(&row.severity),
        message: row.message,
        context,
        metadata: row
            .metadata
            .and_then(|v| v.as_object().cloned())
            .map(|m| m.into_iter().collect())
            .unwrap_or_default(),
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // =========================================================================
    // Enum column parsing
    //
    // Round-trip contract: values are written with `format!("{:?}", ..)`, so a
    // known variant name must map back to that variant, and anything else must
    // degrade to the Info default rather than error.
    // =========================================================================

    #[test]
    fn test_parse_event_type() {
        assert!(matches!(
            parse_event_type("ValidationError"),
            EventType::ValidationError
        ));
        assert!(matches!(parse_event_type("Info"), EventType::Info));
        assert!(matches!(parse_event_type("Unknown"), EventType::Info));
    }

    #[test]
    fn test_parse_event_type_is_case_sensitive() {
        // Column values come from Debug formatting, which is always exact
        // PascalCase. A lowercased value is not a known variant and must take
        // the Info fallback rather than matching loosely.
        assert!(matches!(
            parse_event_type("validationerror"),
            EventType::Info
        ));
    }

    #[test]
    fn test_parse_severity() {
        assert!(matches!(parse_severity("Debug"), Severity::Debug));
        assert!(matches!(parse_severity("Critical"), Severity::Critical));
        assert!(matches!(parse_severity("Unknown"), Severity::Info));
    }

    // =========================================================================
    // WHERE-clause construction (pure logic, no database required)
    //
    // `build_where_clause` turns an AuditQuery into a parameterised SQL
    // fragment plus ordered bind values. Getting placeholder numbering and
    // bind ordering right is the core of safe query building, so it is worth
    // exercising directly rather than only through a live DB. Expected output
    // is derived from the SQL semantics (1-based $N placeholders for Postgres,
    // anonymous `?` for SQLite, one bind per dynamic value, booleans inlined),
    // not pasted from current output.
    // =========================================================================

    #[test]
    fn test_where_clause_empty_query() {
        // No filters => no WHERE clause and no bind params, in either dialect.
        for dialect in [SqlDialect::Postgres, SqlDialect::Sqlite] {
            let (clause, params) = build_where_clause(&AuditQuery::default(), dialect);
            assert_eq!(clause, "", "dialect {dialect:?}");
            assert!(params.is_empty(), "dialect {dialect:?}");
        }
    }

    #[test]
    fn test_where_clause_tenant_and_user_number_sequentially() {
        let query = AuditQuery {
            tenant_id: Some("acme".to_string()),
            user_id: Some("u-1".to_string()),
            ..Default::default()
        };
        let (clause, params) = build_where_clause(&query, SqlDialect::Postgres);

        // Two string filters => $1 and $2 in declaration order, WHERE-joined
        // with AND, and two binds in the same order.
        assert!(clause.starts_with("WHERE "));
        assert!(clause.contains("tenant_id = $1"));
        assert!(clause.contains("user_id = $2"));
        assert!(clause.contains(" AND "));
        assert_eq!(params, vec!["acme".to_string(), "u-1".to_string()]);
    }

    #[test]
    fn test_where_clause_sqlite_uses_anonymous_placeholders() {
        let query = AuditQuery {
            tenant_id: Some("acme".to_string()),
            user_id: Some("u-1".to_string()),
            ..Default::default()
        };
        let (clause, params) = build_where_clause(&query, SqlDialect::Sqlite);

        // SQLite binds positionally against bare `?` — a numbered placeholder
        // would be a different (and for sqlx, differently-bound) form.
        assert!(clause.contains("tenant_id = ?"), "clause: {clause}");
        assert!(clause.contains("user_id = ?"), "clause: {clause}");
        assert!(
            !clause.contains('$'),
            "SQLite clause must not use $N placeholders: {clause}"
        );
        // Bind order still matches declaration order.
        assert_eq!(params, vec!["acme".to_string(), "u-1".to_string()]);
    }

    #[test]
    fn test_where_clause_event_types_expand_placeholders() {
        let query = AuditQuery {
            event_types: Some(vec![EventType::LoginFailure, EventType::SystemError]),
            ..Default::default()
        };
        let (clause, params) = build_where_clause(&query, SqlDialect::Postgres);

        // An N-element IN list must expand to N sequential placeholders and N
        // binds (one per type), each rendered via Debug.
        assert!(
            clause.contains("event_type IN ($1, $2)"),
            "clause was: {clause}"
        );
        assert_eq!(
            params,
            vec![
                format!("{:?}", EventType::LoginFailure),
                format!("{:?}", EventType::SystemError),
            ]
        );
    }

    #[test]
    fn test_where_clause_sqlite_event_types_expand_placeholders() {
        let query = AuditQuery {
            event_types: Some(vec![EventType::LoginFailure, EventType::SystemError]),
            ..Default::default()
        };
        let (clause, params) = build_where_clause(&query, SqlDialect::Sqlite);

        // Same N-for-N expansion, spelled with anonymous placeholders.
        assert!(
            clause.contains("event_type IN (?, ?)"),
            "clause was: {clause}"
        );
        assert_eq!(
            params,
            vec![
                format!("{:?}", EventType::LoginFailure),
                format!("{:?}", EventType::SystemError),
            ]
        );
    }

    #[test]
    fn test_where_clause_boolean_flags_inlined_not_bound() {
        let query = AuditQuery {
            security_relevant_only: true,
            contains_pii_only: true,
            contains_phi_only: true,
            ..Default::default()
        };
        let (clause, params) = build_where_clause(&query, SqlDialect::Postgres);

        // Boolean-only filters are inlined as literal predicates; they add no
        // bind parameters (nothing user-controlled to parameterise).
        assert!(clause.contains("security_relevant = TRUE"));
        assert!(clause.contains("contains_pii = TRUE"));
        assert!(clause.contains("contains_phi = TRUE"));
        assert!(
            params.is_empty(),
            "boolean flags must not produce bind params, got {params:?}"
        );
    }

    #[test]
    fn test_where_clause_sqlite_boolean_flags_use_integer_literal() {
        let query = AuditQuery {
            security_relevant_only: true,
            contains_pii_only: true,
            contains_phi_only: true,
            ..Default::default()
        };
        let (clause, params) = build_where_clause(&query, SqlDialect::Sqlite);

        // SQLite's schema stores these columns as INTEGER, so `= TRUE` would
        // match no rows. The dialect must emit the integer literal.
        assert!(clause.contains("security_relevant = 1"), "clause: {clause}");
        assert!(clause.contains("contains_pii = 1"), "clause: {clause}");
        assert!(clause.contains("contains_phi = 1"), "clause: {clause}");
        assert!(
            !clause.contains("TRUE"),
            "SQLite clause must not use the TRUE keyword: {clause}"
        );
        assert!(params.is_empty(), "got {params:?}");
    }

    #[test]
    fn test_where_clause_placeholder_numbering_after_multivalue() {
        // A time bound ($1), then a 2-element type list ($2,$3), then a tenant
        // filter must correctly continue at $4 — verifying the running index
        // advances past the multi-value IN expansion.
        let query = AuditQuery {
            since: Some(chrono::Utc::now()),
            event_types: Some(vec![EventType::Info, EventType::Warning]),
            tenant_id: Some("acme".to_string()),
            ..Default::default()
        };
        let (clause, params) = build_where_clause(&query, SqlDialect::Postgres);

        assert!(clause.contains("timestamp >= $1"), "clause: {clause}");
        assert!(
            clause.contains("event_type IN ($2, $3)"),
            "clause: {clause}"
        );
        assert!(clause.contains("tenant_id = $4"), "clause: {clause}");
        // Binds: since (rfc3339), two event types, tenant.
        assert_eq!(params.len(), 4);
        assert_eq!(params.get(3), Some(&"acme".to_string()));
    }

    #[test]
    fn test_where_clause_sqlite_bind_order_matches_placeholder_order() {
        // SQLite placeholders carry no position, so correctness rests entirely
        // on `params` being in the same left-to-right order as the `?`s.
        let query = AuditQuery {
            since: Some(chrono::Utc::now()),
            event_types: Some(vec![EventType::Info, EventType::Warning]),
            tenant_id: Some("acme".to_string()),
            ..Default::default()
        };
        let (clause, params) = build_where_clause(&query, SqlDialect::Sqlite);

        assert!(clause.contains("timestamp >= ?"), "clause: {clause}");
        assert!(clause.contains("event_type IN (?, ?)"), "clause: {clause}");
        assert!(clause.contains("tenant_id = ?"), "clause: {clause}");
        // One `?` per bind, and the tenant value is bound last.
        assert_eq!(
            clause.matches('?').count(),
            params.len(),
            "placeholder count must equal bind count: {clause} / {params:?}"
        );
        assert_eq!(params.len(), 4);
        assert_eq!(params.get(3), Some(&"acme".to_string()));
    }

    #[test]
    fn test_where_clause_min_severity_is_dialect_independent() {
        // The CASE mapping is plain SQL with an inlined numeric and no binds,
        // so both dialects must produce byte-identical output.
        let query = AuditQuery {
            min_severity: Some(Severity::Warning),
            ..Default::default()
        };
        let (pg_clause, pg_params) = build_where_clause(&query, SqlDialect::Postgres);
        let (sqlite_clause, sqlite_params) = build_where_clause(&query, SqlDialect::Sqlite);

        assert_eq!(pg_clause, sqlite_clause);
        assert!(pg_clause.contains(">= 2"), "clause: {pg_clause}");
        assert!(pg_params.is_empty());
        assert!(sqlite_params.is_empty());
    }

    #[test]
    fn test_where_clause_covers_every_scalar_filter() {
        // Each of these four fields was previously untested in isolation. All
        // nine scalar conditions set at once must produce nine sequential
        // placeholders and nine binds in declaration order — which is what
        // proves the running index does not skip or reuse a slot.
        let corr = uuid::Uuid::from_u128(7);
        let query = AuditQuery {
            since: Some(chrono::Utc::now()),
            until: Some(chrono::Utc::now()),
            event_types: Some(vec![EventType::Info]),
            tenant_id: Some("tenant".to_string()),
            user_id: Some("user".to_string()),
            correlation_id: Some(corr),
            resource_type: Some("rtype".to_string()),
            resource_id: Some("rid".to_string()),
            ..Default::default()
        };
        let (clause, params) = build_where_clause(&query, SqlDialect::Postgres);

        assert!(clause.contains("timestamp >= $1"), "clause: {clause}");
        assert!(clause.contains("timestamp < $2"), "clause: {clause}");
        assert!(clause.contains("event_type IN ($3)"), "clause: {clause}");
        assert!(clause.contains("tenant_id = $4"), "clause: {clause}");
        assert!(clause.contains("user_id = $5"), "clause: {clause}");
        assert!(clause.contains("correlation_id = $6"), "clause: {clause}");
        assert!(clause.contains("resource_type = $7"), "clause: {clause}");
        assert!(clause.contains("resource_id = $8"), "clause: {clause}");

        // Bind order must match placeholder order: the correlation UUID is
        // sixth, and the two resource values follow it.
        assert_eq!(params.len(), 8);
        assert_eq!(params.get(5), Some(&corr.to_string()));
        assert_eq!(params.get(6), Some(&"rtype".to_string()));
        assert_eq!(params.get(7), Some(&"rid".to_string()));
    }

    #[test]
    fn test_where_clause_resource_id_alone_takes_first_placeholder() {
        // resource_id is the last condition appended, so a bug that failed to
        // advance the index for it would be invisible in the all-fields test
        // above. Alone, it must still be $1.
        let query = AuditQuery {
            resource_id: Some("rid".to_string()),
            ..Default::default()
        };
        let (clause, params) = build_where_clause(&query, SqlDialect::Postgres);
        assert_eq!(clause, "WHERE resource_id = $1");
        assert_eq!(params, vec!["rid".to_string()]);
    }

    // =========================================================================
    // Query plan construction
    // =========================================================================

    #[test]
    fn test_query_plan_orders_and_paginates() {
        let query = AuditQuery {
            tenant_id: Some("acme".to_string()),
            limit: Some(10),
            offset: Some(20),
            ascending: true,
            ..Default::default()
        };
        let plan = build_query_plan(&query, SqlDialect::Postgres);

        assert!(plan.select_sql.contains("WHERE tenant_id = $1"));
        assert!(plan.select_sql.contains("ORDER BY timestamp ASC"));
        assert!(plan.select_sql.contains("LIMIT 10"));
        assert!(plan.select_sql.contains("OFFSET 20"));
        // The COUNT must share the WHERE clause but carry no pagination —
        // otherwise total_count would report the page size, not the total.
        assert!(plan.count_sql.contains("WHERE tenant_id = $1"));
        assert!(!plan.count_sql.contains("LIMIT"), "{}", plan.count_sql);
        assert!(!plan.count_sql.contains("OFFSET"), "{}", plan.count_sql);
        // Both statements bind the same values in the same order.
        assert_eq!(plan.params, vec!["acme".to_string()]);
    }

    #[test]
    fn test_query_plan_defaults_to_descending_and_unpaginated() {
        let plan = build_query_plan(&AuditQuery::default(), SqlDialect::Sqlite);
        assert!(plan.select_sql.contains("ORDER BY timestamp DESC"));
        assert!(!plan.select_sql.contains("LIMIT"), "{}", plan.select_sql);
        assert!(!plan.select_sql.contains("OFFSET"), "{}", plan.select_sql);
        assert!(plan.params.is_empty());
    }

    #[test]
    fn test_assemble_query_result_has_more_only_when_page_is_full() {
        let full = vec![
            Event::new(EventType::Info, "a"),
            Event::new(EventType::Info, "b"),
        ];
        let query = AuditQuery {
            limit: Some(2),
            ..Default::default()
        };
        let result = assemble_query_result(full, 5, &query);
        assert!(
            result.has_more,
            "a full page implies another page may exist"
        );
        assert_eq!(result.total_count, Some(5));

        // A short page means the result set is exhausted.
        let partial = vec![Event::new(EventType::Info, "a")];
        let result = assemble_query_result(partial, 1, &query);
        assert!(!result.has_more);

        // With no limit there is no paging at all, however many rows came back.
        let unlimited = AuditQuery::default();
        let result = assemble_query_result(vec![Event::new(EventType::Info, "a")], 1, &unlimited);
        assert!(!result.has_more);
    }

    #[test]
    fn test_assemble_query_result_zero_limit_reports_no_further_page() {
        // `events.len() >= 0` is vacuously true, so an unguarded comparison
        // would claim a further page exists for a query that asked for no
        // rows — and would do so even on an empty result set.
        let query = AuditQuery {
            limit: Some(0),
            ..Default::default()
        };
        let result = assemble_query_result(Vec::new(), 0, &query);
        assert!(
            !result.has_more,
            "a zero-row page cannot imply a further page"
        );
    }

    // =========================================================================
    // Event assembly
    // =========================================================================

    /// A row where every field carries a distinct, recognisable value, so a
    /// miswired field assignment shows up as a wrong value rather than a
    /// coincidental match.
    fn populated_row() -> EventRow {
        EventRow {
            id: uuid::Uuid::from_u128(1),
            timestamp: chrono::DateTime::parse_from_rfc3339("2020-01-02T03:04:05Z")
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .expect("fixture timestamp is valid RFC3339"),
            event_type: "LoginFailure".to_string(),
            severity: "Critical".to_string(),
            message: "row-message".to_string(),
            operation: "row-operation".to_string(),
            tenant_id: Some("tenant-a".to_string()),
            user_id: Some("user-b".to_string()),
            correlation_id: uuid::Uuid::from_u128(2),
            resource_type: Some("resource-type-c".to_string()),
            resource_id: Some("resource-id-d".to_string()),
            module_path: "module::path".to_string(),
            file: "some/file.rs".to_string(),
            line: 42,
            contains_pii: true,
            contains_phi: false,
            security_relevant: true,
            metadata: Some(serde_json::json!({ "k": "v" })),
        }
    }

    #[test]
    fn test_assemble_event_maps_every_column() {
        let event = assemble_event(populated_row());

        assert_eq!(event.id, uuid::Uuid::from_u128(1));
        assert_eq!(event.timestamp.to_rfc3339(), "2020-01-02T03:04:05+00:00");
        assert!(matches!(event.event_type, EventType::LoginFailure));
        assert!(matches!(event.severity, Severity::Critical));
        assert_eq!(event.message, "row-message");

        assert_eq!(event.context.operation, "row-operation");
        assert_eq!(
            event.context.tenant_id.as_ref().map(|t| t.as_str()),
            Some("tenant-a")
        );
        assert_eq!(
            event.context.user_id.as_ref().map(|u| u.as_str()),
            Some("user-b")
        );
        assert_eq!(event.context.correlation_id, uuid::Uuid::from_u128(2));
        assert_eq!(
            event.context.resource_type.as_deref(),
            Some("resource-type-c")
        );
        assert_eq!(event.context.resource_id.as_deref(), Some("resource-id-d"));
        assert_eq!(event.context.module_path, "module::path");
        assert_eq!(event.context.file, "some/file.rs");
        assert_eq!(event.context.line, 42);

        // The three booleans are distinct in the fixture, so a swap is visible.
        assert!(event.context.contains_pii);
        assert!(!event.context.contains_phi);
        assert!(event.context.security_relevant);

        assert_eq!(
            event.metadata.get("k").and_then(|v| v.as_str()),
            Some("v"),
            "metadata object must be flattened into the event map"
        );
    }

    #[test]
    fn test_assemble_event_handles_absent_optionals() {
        let row = EventRow {
            tenant_id: None,
            user_id: None,
            resource_type: None,
            resource_id: None,
            metadata: None,
            ..populated_row()
        };
        let event = assemble_event(row);

        assert!(event.context.tenant_id.is_none());
        assert!(event.context.user_id.is_none());
        assert!(event.context.resource_type.is_none());
        assert!(event.context.resource_id.is_none());
        assert!(event.metadata.is_empty());
    }

    #[test]
    fn test_assemble_event_drops_invalid_tenant_and_user_ids() {
        // A stored value that no longer satisfies TenantId/UserId validation
        // (legacy data, or a row written before a constraint tightened) is
        // dropped to None rather than failing the whole read. A space is
        // rejected by the alphanumeric + dash/underscore rule.
        let row = EventRow {
            tenant_id: Some("has a space".to_string()),
            user_id: Some("also invalid".to_string()),
            ..populated_row()
        };
        let event = assemble_event(row);

        assert!(
            event.context.tenant_id.is_none(),
            "an unvalidatable stored tenant_id must degrade to None"
        );
        assert!(
            event.context.user_id.is_none(),
            "an unvalidatable stored user_id must degrade to None"
        );
        // The rest of the event must still be intact — one bad column does
        // not discard the row.
        assert_eq!(event.message, "row-message");
        assert_eq!(event.context.operation, "row-operation");
    }

    #[test]
    fn test_assemble_event_drops_non_object_metadata() {
        // The metadata column is documented as a JSON object. A scalar cannot
        // be flattened into the event's key/value map, so it must yield an
        // empty map rather than panicking or inventing a key.
        let row = EventRow {
            metadata: Some(serde_json::json!("not-an-object")),
            ..populated_row()
        };
        assert!(assemble_event(row).metadata.is_empty());
    }
}
