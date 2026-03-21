//! Integration tests for the HTTP middleware module
//!
//! These tests verify end-to-end behavior of the HTTP middleware:
//! - RequestIdLayer: ID generation, preservation, propagation
//! - ContextLayer: Header extraction, source IP handling
//! - ProblemResponse: Status code mapping, JSON body structure
//! - Extractors: Context retrieval in handlers

#![cfg(feature = "http")]

mod http;
