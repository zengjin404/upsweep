//! 候选文件元数据采集。
//!
//! 只对候选文件按需执行；普通文件不会触发 PE/签名/MSI 解析。

pub mod msi;
pub mod pe_version;

use std::path::Path;

use crate::models::{MetadataIssue, MsiMetadata, PeMetadata, SignatureInfo};

#[derive(Debug, Clone, Copy)]
pub struct MetadataOptions {
    pub include_metadata: bool,
    pub include_signature: bool,
    pub include_msi: bool,
}

impl Default for MetadataOptions {
    fn default() -> Self {
        Self {
            include_metadata: true,
            include_signature: true,
            include_msi: true,
        }
    }
}

#[derive(Debug, Default)]
pub struct CandidateMetadata {
    pub pe: Option<PeMetadata>,
    pub signature: Option<SignatureInfo>,
    pub msi: Option<MsiMetadata>,
    pub issues: Vec<MetadataIssue>,
}

pub fn collect(
    path: &Path,
    extension: Option<&str>,
    options: MetadataOptions,
) -> CandidateMetadata {
    let mut result = CandidateMetadata::default();
    if !options.include_metadata {
        return result;
    }

    let extension = extension.unwrap_or_default().to_ascii_lowercase();
    match extension.as_str() {
        "exe" => {
            let pe = pe_version::read(path);
            if let Some(error) = &pe.read_error {
                result.issues.push(MetadataIssue {
                    kind: "peVersion".to_string(),
                    message: error.clone(),
                });
            }
            result.pe = Some(pe);

            if options.include_signature {
                result.signature = Some(crate::signature::inspect(path, true));
            }
        }
        "msi" | "msp" => {
            if options.include_msi {
                let metadata = msi::read(path);
                if let Some(error) = &metadata.read_error {
                    result.issues.push(MetadataIssue {
                        kind: "msi".to_string(),
                        message: error.clone(),
                    });
                }
                result.msi = Some(metadata);
            }
            if options.include_signature {
                // MSI 的发布者优先使用 MSI Manufacturer；这里只做信任状态判定。
                result.signature = Some(crate::signature::inspect(path, false));
            }
        }
        _ => {}
    }

    result
}
