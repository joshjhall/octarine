//! GraphQL schema handling
//!
//! Wrapper for parsed GraphQL schemas for validation.

use crate::primitives::types::Problem;
use graphql_parser::schema::{self as gql, Definition, TypeDefinition};

/// Parsed GraphQL schema for validation
///
/// This wraps the graphql-parser schema document and provides
/// validation methods.
#[derive(Debug, Clone)]
pub struct GraphqlSchema {
    /// The raw SDL source
    source: String,
    /// Type names defined in the schema
    type_names: Vec<String>,
    /// Whether the schema has a Query type
    has_query: bool,
    /// Whether the schema has a Mutation type
    has_mutation: bool,
    /// Whether the schema has a Subscription type
    has_subscription: bool,
}

impl GraphqlSchema {
    /// Parse a GraphQL schema from SDL
    ///
    /// # Arguments
    ///
    /// * `sdl` - The GraphQL schema definition language source
    ///
    /// # Returns
    ///
    /// A parsed schema or an error
    ///
    /// # Example
    ///
    /// ```ignore
    /// let schema = GraphqlSchema::parse(r#"
    ///     type Query {
    ///         user(id: ID!): User
    ///     }
    ///     type User {
    ///         id: ID!
    ///         name: String!
    ///     }
    /// "#)?;
    /// ```
    pub fn parse(sdl: &str) -> Result<Self, Problem> {
        if sdl.is_empty() {
            return Err(Problem::validation("GraphQL schema cannot be empty"));
        }

        // Parse using graphql-parser
        let document: gql::Document<'_, String> = gql::parse_schema(sdl)
            .map_err(|e| Problem::validation(format!("Invalid GraphQL schema: {e}")))?;

        // Extract type information
        let mut type_names = Vec::new();
        let mut has_query = false;
        let mut has_mutation = false;
        let mut has_subscription = false;

        for definition in &document.definitions {
            if let Definition::TypeDefinition(type_def) = definition {
                let name = match type_def {
                    TypeDefinition::Object(obj) => &obj.name,
                    TypeDefinition::Interface(iface) => &iface.name,
                    TypeDefinition::Union(union) => &union.name,
                    TypeDefinition::Enum(enum_def) => &enum_def.name,
                    TypeDefinition::InputObject(input) => &input.name,
                    TypeDefinition::Scalar(scalar) => &scalar.name,
                };

                type_names.push(name.clone());

                match name.as_str() {
                    "Query" => has_query = true,
                    "Mutation" => has_mutation = true,
                    "Subscription" => has_subscription = true,
                    _ => {}
                }
            }
        }

        Ok(Self {
            source: sdl.to_string(),
            type_names,
            has_query,
            has_mutation,
            has_subscription,
        })
    }

    /// Get the raw SDL source
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Get all type names defined in the schema
    #[must_use]
    pub fn type_names(&self) -> &[String] {
        &self.type_names
    }

    /// Check if a type is defined in the schema
    #[must_use]
    pub fn is_type_defined(&self, name: &str) -> bool {
        self.type_names.iter().any(|n| n == name)
    }

    /// Check if the schema has a Query type
    #[must_use]
    pub fn is_query_type_defined(&self) -> bool {
        self.has_query
    }

    /// Check if the schema has a Mutation type
    #[must_use]
    pub fn is_mutation_type_defined(&self) -> bool {
        self.has_mutation
    }

    /// Check if the schema has a Subscription type
    #[must_use]
    pub fn is_subscription_type_defined(&self) -> bool {
        self.has_subscription
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_schema() {
        let sdl = r"
            type Query {
                user(id: ID!): User
            }
            type User {
                id: ID!
                name: String!
            }
        ";
        let schema = GraphqlSchema::parse(sdl).expect("valid schema");

        // Verify types were extracted
        assert!(schema.is_query_type_defined());
        assert!(schema.is_type_defined("User"));
        assert!(schema.is_type_defined("Query"));
        assert!(!schema.is_type_defined("NotExist"));
    }

    #[test]
    fn test_parse_empty_schema() {
        let result = GraphqlSchema::parse("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_schema() {
        let result = GraphqlSchema::parse("not a schema");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_query_type_defined() {
        let sdl = "type Query { hello: String }";
        let schema = GraphqlSchema::parse(sdl).expect("valid schema");
        assert!(schema.is_query_type_defined());
        assert!(!schema.is_mutation_type_defined());
        assert!(!schema.is_subscription_type_defined());
    }

    #[test]
    fn test_full_schema_with_all_root_types() {
        let sdl = r"
            type Query {
                users: [User!]!
            }
            type Mutation {
                createUser(name: String!): User!
            }
            type Subscription {
                userCreated: User!
            }
            type User {
                id: ID!
                name: String!
            }
            enum Role {
                ADMIN
                USER
            }
            input CreateUserInput {
                name: String!
                role: Role!
            }
        ";
        let schema = GraphqlSchema::parse(sdl).expect("valid schema");

        assert!(schema.is_query_type_defined());
        assert!(schema.is_mutation_type_defined());
        assert!(schema.is_subscription_type_defined());
        assert!(schema.is_type_defined("User"));
        assert!(schema.is_type_defined("Role"));
        assert!(schema.is_type_defined("CreateUserInput"));

        // Verify type_names returns all types
        let types = schema.type_names();
        assert!(types.contains(&"Query".to_string()));
        assert!(types.contains(&"User".to_string()));
        assert!(types.contains(&"Role".to_string()));
    }

    #[test]
    fn test_parse_syntax_error() {
        let sdl = "type Query { field: }"; // Missing type
        let result = GraphqlSchema::parse(sdl);
        assert!(result.is_err());
    }
}
