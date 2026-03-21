//! Response compression presets
//!
//! Provides opinionated compression configurations for HTTP responses.
//!
//! # Security Note
//!
//! Be aware of the BREACH attack when using compression with secrets in responses.
//! Avoid compressing responses that contain both user-controlled input and secrets.
//!
//! # Example
//!
//! ```rust
//! use axum::Router;
//! use octarine::http::presets::compression;
//!
//! let app: Router = Router::new()
//!     .layer(compression::default_compression());
//! ```

pub use tower_http::compression::{CompressionLayer, CompressionLevel};
pub use tower_http::decompression::RequestDecompressionLayer;

/// Default compression layer (gzip, deflate, br, zstd).
///
/// Compresses responses using the best algorithm supported by the client.
/// Uses default compression level (balanced speed/size).
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::compression;
///
/// let app: Router = Router::new()
///     .layer(compression::default_compression());
/// ```
#[must_use]
pub fn default_compression() -> CompressionLayer {
    CompressionLayer::new()
}

/// Fast compression layer optimized for speed over size.
///
/// Uses fastest compression settings. Better for real-time APIs where
/// latency is more important than bandwidth.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::compression;
///
/// let app: Router = Router::new()
///     .layer(compression::fast_compression());
/// ```
#[must_use]
pub fn fast_compression() -> CompressionLayer {
    CompressionLayer::new().quality(CompressionLevel::Fastest)
}

/// Best compression layer optimized for size over speed.
///
/// Uses best compression settings. Better for static content or
/// bandwidth-constrained scenarios.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::compression;
///
/// let app: Router = Router::new()
///     .layer(compression::best_compression());
/// ```
#[must_use]
pub fn best_compression() -> CompressionLayer {
    CompressionLayer::new().quality(CompressionLevel::Best)
}

/// Gzip-only compression layer.
///
/// Only uses gzip compression. Useful when you need maximum compatibility
/// with older clients.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::compression;
///
/// let app: Router = Router::new()
///     .layer(compression::gzip_only());
/// ```
#[must_use]
pub fn gzip_only() -> CompressionLayer {
    CompressionLayer::new()
        .no_br()
        .no_deflate()
        .no_zstd()
        .gzip(true)
}

/// Request decompression layer.
///
/// Automatically decompresses incoming request bodies that are compressed
/// with gzip, deflate, br, or zstd.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::compression;
///
/// let app: Router = Router::new()
///     .layer(compression::request_decompression());
/// ```
#[must_use]
pub fn request_decompression() -> RequestDecompressionLayer {
    RequestDecompressionLayer::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_compression_creates_layer() {
        let _layer = default_compression();
    }

    #[test]
    fn test_fast_compression_creates_layer() {
        let _layer = fast_compression();
    }

    #[test]
    fn test_best_compression_creates_layer() {
        let _layer = best_compression();
    }

    #[test]
    fn test_gzip_only_creates_layer() {
        let _layer = gzip_only();
    }

    #[test]
    fn test_request_decompression_creates_layer() {
        let _layer = request_decompression();
    }
}
