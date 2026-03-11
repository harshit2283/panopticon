#![allow(dead_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompressionType {
    None,
    Gzip,
    Snappy,
    Zstd,
    Unknown(u8),
}

impl CompressionType {
    pub fn from_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "identity" | "" | "none" => CompressionType::None,
            "gzip" | "deflate" => CompressionType::Gzip,
            "snappy" => CompressionType::Snappy,
            "zstd" | "zstandard" => CompressionType::Zstd,
            _ => CompressionType::Unknown(0),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            CompressionType::None => "identity",
            CompressionType::Gzip => "gzip",
            CompressionType::Snappy => "snappy",
            CompressionType::Zstd => "zstd",
            CompressionType::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecompressionConfig {
    pub enabled: bool,
    pub max_decompressed_size: usize,
    pub enabled_types: Vec<CompressionType>,
    pub pii_sample_rate: f64,
}

impl Default for DecompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_decompressed_size: 10 * 1024 * 1024,
            enabled_types: vec![
                CompressionType::Gzip,
                CompressionType::Snappy,
                CompressionType::Zstd,
            ],
            pii_sample_rate: 0.01,
        }
    }
}

#[derive(Debug)]
pub enum DecompressionResult {
    Success(Vec<u8>),
    NotCompressed,
    UnsupportedType(CompressionType),
    Failed(String),
    SizeLimitExceeded { actual: usize, limit: usize },
}

pub fn decompress(
    data: &[u8],
    compression: CompressionType,
    config: &DecompressionConfig,
) -> DecompressionResult {
    let result = catch_unwind(AssertUnwindSafe(|| {
        decompress_inner(data, compression, config)
    }));

    match result {
        Ok(r) => r,
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic in decompression".to_string()
            };
            DecompressionResult::Failed(format!("Decompression panic: {}", msg))
        }
    }
}

fn decompress_inner(
    data: &[u8],
    compression: CompressionType,
    config: &DecompressionConfig,
) -> DecompressionResult {
    if matches!(compression, CompressionType::None) {
        return DecompressionResult::NotCompressed;
    }

    if !config.enabled {
        return DecompressionResult::UnsupportedType(compression);
    }

    if !config.enabled_types.contains(&compression) {
        return DecompressionResult::UnsupportedType(compression);
    }

    match compression {
        CompressionType::None => DecompressionResult::NotCompressed,
        CompressionType::Gzip => decompress_gzip(data, config),
        CompressionType::Snappy => decompress_snappy(data, config),
        CompressionType::Zstd => decompress_zstd(data, config),
        CompressionType::Unknown(code) => {
            DecompressionResult::UnsupportedType(CompressionType::Unknown(code))
        }
    }
}

#[cfg(feature = "compression")]
fn decompress_gzip(data: &[u8], config: &DecompressionConfig) -> DecompressionResult {
    use flate2::read::{GzDecoder, MultiGzDecoder};
    use std::io::Read;

    let mut decoder = MultiGzDecoder::new(data);
    let mut decompressed = Vec::with_capacity(data.len().min(config.max_decompressed_size));

    match decoder.read_to_end(&mut decompressed) {
        Ok(_) => {
            if decompressed.len() > config.max_decompressed_size {
                DecompressionResult::SizeLimitExceeded {
                    actual: decompressed.len(),
                    limit: config.max_decompressed_size,
                }
            } else {
                DecompressionResult::Success(decompressed)
            }
        }
        Err(e) => {
            let mut single_decoder = GzDecoder::new(data);
            let mut decompressed = Vec::with_capacity(data.len().min(config.max_decompressed_size));
            match single_decoder.read_to_end(&mut decompressed) {
                Ok(_) => {
                    if decompressed.len() > config.max_decompressed_size {
                        DecompressionResult::SizeLimitExceeded {
                            actual: decompressed.len(),
                            limit: config.max_decompressed_size,
                        }
                    } else {
                        DecompressionResult::Success(decompressed)
                    }
                }
                Err(_) => DecompressionResult::Failed(format!("gzip decompression failed: {}", e)),
            }
        }
    }
}

#[cfg(not(feature = "compression"))]
fn decompress_gzip(_data: &[u8], _config: &DecompressionConfig) -> DecompressionResult {
    DecompressionResult::UnsupportedType(CompressionType::Gzip)
}

#[cfg(feature = "compression")]
fn decompress_snappy(data: &[u8], config: &DecompressionConfig) -> DecompressionResult {
    use snap::read::FrameDecoder;
    use std::io::Read;

    let mut decoder = FrameDecoder::new(data);
    let mut decompressed = Vec::with_capacity(data.len().min(config.max_decompressed_size));

    match decoder.read_to_end(&mut decompressed) {
        Ok(_) => {
            if decompressed.len() > config.max_decompressed_size {
                DecompressionResult::SizeLimitExceeded {
                    actual: decompressed.len(),
                    limit: config.max_decompressed_size,
                }
            } else {
                DecompressionResult::Success(decompressed)
            }
        }
        Err(e) => {
            let decompressed = match snap::raw::Decoder::new().decompress_vec(data) {
                Ok(d) => d,
                Err(_) => {
                    return DecompressionResult::Failed(format!(
                        "snappy decompression failed: {}",
                        e
                    ));
                }
            };

            if decompressed.len() > config.max_decompressed_size {
                DecompressionResult::SizeLimitExceeded {
                    actual: decompressed.len(),
                    limit: config.max_decompressed_size,
                }
            } else {
                DecompressionResult::Success(decompressed)
            }
        }
    }
}

#[cfg(not(feature = "compression"))]
fn decompress_snappy(_data: &[u8], _config: &DecompressionConfig) -> DecompressionResult {
    DecompressionResult::UnsupportedType(CompressionType::Snappy)
}

#[cfg(feature = "compression")]
fn decompress_zstd(data: &[u8], config: &DecompressionConfig) -> DecompressionResult {
    let mut decompressed = Vec::with_capacity(data.len().min(config.max_decompressed_size));

    match zstd::stream::copy_decode(data, &mut decompressed) {
        Ok(_) => {
            if decompressed.len() > config.max_decompressed_size {
                DecompressionResult::SizeLimitExceeded {
                    actual: decompressed.len(),
                    limit: config.max_decompressed_size,
                }
            } else {
                DecompressionResult::Success(decompressed)
            }
        }
        Err(e) => DecompressionResult::Failed(format!("zstd decompression failed: {}", e)),
    }
}

#[cfg(not(feature = "compression"))]
fn decompress_zstd(_data: &[u8], _config: &DecompressionConfig) -> DecompressionResult {
    DecompressionResult::UnsupportedType(CompressionType::Zstd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_type_from_name() {
        assert_eq!(CompressionType::from_name("gzip"), CompressionType::Gzip);
        assert_eq!(CompressionType::from_name("GZIP"), CompressionType::Gzip);
        assert_eq!(CompressionType::from_name("deflate"), CompressionType::Gzip);
        assert_eq!(
            CompressionType::from_name("snappy"),
            CompressionType::Snappy
        );
        assert_eq!(
            CompressionType::from_name("SNAPPY"),
            CompressionType::Snappy
        );
        assert_eq!(CompressionType::from_name("zstd"), CompressionType::Zstd);
        assert_eq!(
            CompressionType::from_name("zstandard"),
            CompressionType::Zstd
        );
        assert_eq!(
            CompressionType::from_name("identity"),
            CompressionType::None
        );
        assert_eq!(CompressionType::from_name(""), CompressionType::None);
        assert_eq!(CompressionType::from_name("none"), CompressionType::None);
        assert!(matches!(
            CompressionType::from_name("unknown"),
            CompressionType::Unknown(_)
        ));
    }

    #[test]
    fn test_compression_type_name() {
        assert_eq!(CompressionType::None.name(), "identity");
        assert_eq!(CompressionType::Gzip.name(), "gzip");
        assert_eq!(CompressionType::Snappy.name(), "snappy");
        assert_eq!(CompressionType::Zstd.name(), "zstd");
        assert_eq!(CompressionType::Unknown(42).name(), "unknown");
    }

    #[test]
    fn test_decompression_config_default() {
        let config = DecompressionConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_decompressed_size, 10 * 1024 * 1024);
        assert_eq!(config.enabled_types.len(), 3);
        assert!(config.enabled_types.contains(&CompressionType::Gzip));
        assert!(config.enabled_types.contains(&CompressionType::Snappy));
        assert!(config.enabled_types.contains(&CompressionType::Zstd));
        assert!((config.pii_sample_rate - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn test_decompress_none() {
        let config = DecompressionConfig::default();
        let data = b"hello world";
        let result = decompress(data, CompressionType::None, &config);
        assert!(matches!(result, DecompressionResult::NotCompressed));
    }

    #[test]
    fn test_decompress_disabled_in_config() {
        let config = DecompressionConfig {
            enabled: false,
            ..Default::default()
        };
        let result = decompress(b"", CompressionType::Gzip, &config);
        assert!(matches!(result, DecompressionResult::UnsupportedType(_)));
    }

    #[test]
    fn test_decompress_type_not_enabled() {
        let config = DecompressionConfig {
            enabled_types: vec![CompressionType::Gzip],
            ..Default::default()
        };
        let result = decompress(b"", CompressionType::Snappy, &config);
        assert!(matches!(result, DecompressionResult::UnsupportedType(_)));
    }

    #[test]
    fn test_decompress_unknown_type() {
        let config = DecompressionConfig::default();
        let result = decompress(b"", CompressionType::Unknown(99), &config);
        assert!(matches!(result, DecompressionResult::UnsupportedType(_)));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_decompress_gzip_roundtrip() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;

        let original = b"Hello, World! This is a test of gzip compression.";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let config = DecompressionConfig::default();
        let result = decompress(&compressed, CompressionType::Gzip, &config);

        match result {
            DecompressionResult::Success(decompressed) => {
                assert_eq!(decompressed.as_slice(), original);
            }
            _ => panic!("Expected Success, got {:?}", result),
        }
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_decompress_snappy_roundtrip() {
        use snap::raw::Encoder;

        let original = b"Hello, World! This is a test of snappy compression.";
        let compressed = Encoder::new().compress_vec(original).unwrap();

        let config = DecompressionConfig::default();
        let result = decompress(&compressed, CompressionType::Snappy, &config);

        match result {
            DecompressionResult::Success(decompressed) => {
                assert_eq!(decompressed.as_slice(), original);
            }
            _ => panic!("Expected Success, got {:?}", result),
        }
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_decompress_zstd_roundtrip() {
        let original = b"Hello, World! This is a test of zstd compression.";
        let compressed = zstd::encode_all(original.as_slice(), 0).unwrap();

        let config = DecompressionConfig::default();
        let result = decompress(&compressed, CompressionType::Zstd, &config);

        match result {
            DecompressionResult::Success(decompressed) => {
                assert_eq!(decompressed.as_slice(), original);
            }
            _ => panic!("Expected Success, got {:?}", result),
        }
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_decompress_gzip_invalid_data() {
        let invalid_data = b"not valid gzip data";
        let config = DecompressionConfig::default();
        let result = decompress(invalid_data, CompressionType::Gzip, &config);
        assert!(matches!(result, DecompressionResult::Failed(_)));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_decompress_snappy_invalid_data() {
        let invalid_data = b"not valid snappy data";
        let config = DecompressionConfig::default();
        let result = decompress(invalid_data, CompressionType::Snappy, &config);
        assert!(matches!(result, DecompressionResult::Failed(_)));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_decompress_zstd_invalid_data() {
        let invalid_data = b"not valid zstd data";
        let config = DecompressionConfig::default();
        let result = decompress(invalid_data, CompressionType::Zstd, &config);
        assert!(matches!(result, DecompressionResult::Failed(_)));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_size_limit_exceeded() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;

        let original = vec![0u8; 1000];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        let config = DecompressionConfig {
            max_decompressed_size: 100,
            enabled_types: vec![CompressionType::Gzip],
            ..Default::default()
        };

        let result = decompress(&compressed, CompressionType::Gzip, &config);

        match result {
            DecompressionResult::SizeLimitExceeded { actual, limit } => {
                assert_eq!(actual, 1000);
                assert_eq!(limit, 100);
            }
            _ => panic!("Expected SizeLimitExceeded, got {:?}", result),
        }
    }

    #[test]
    fn test_panic_handling() {
        fn panic_decompress(_data: &[u8], _config: &DecompressionConfig) -> DecompressionResult {
            panic!("intentional test panic");
        }

        let config = DecompressionConfig::default();
        let result = catch_unwind(AssertUnwindSafe(|| panic_decompress(b"test", &config)));

        assert!(result.is_err());

        let caught_result = catch_unwind(AssertUnwindSafe(|| {
            let msg = "test panic message";
            panic!("{}", msg);
        }));

        let panic_info = caught_result.expect_err("Expected panic to be caught");

        if let Some(s) = panic_info.downcast_ref::<&str>() {
            assert!(s.contains("test panic message"));
        } else if let Some(s) = panic_info.downcast_ref::<String>() {
            assert!(s.contains("test panic message"));
        }
    }

    #[test]
    fn test_decompression_result_debug() {
        let success = DecompressionResult::Success(vec![1, 2, 3]);
        let not_compressed = DecompressionResult::NotCompressed;
        let unsupported = DecompressionResult::UnsupportedType(CompressionType::Gzip);
        let failed = DecompressionResult::Failed("error".to_string());
        let size_exceeded = DecompressionResult::SizeLimitExceeded {
            actual: 100,
            limit: 50,
        };

        assert!(format!("{:?}", success).contains("Success"));
        assert!(format!("{:?}", not_compressed).contains("NotCompressed"));
        assert!(format!("{:?}", unsupported).contains("UnsupportedType"));
        assert!(format!("{:?}", failed).contains("Failed"));
        assert!(format!("{:?}", size_exceeded).contains("SizeLimitExceeded"));
    }
}
