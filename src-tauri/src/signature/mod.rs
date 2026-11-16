//! Authenticode 签名状态与发布者信息。
//!
//! 信任判定使用 Windows `WinVerifyTrust`（不访问网络，仅使用本地缓存/证书）；
//! 发布者信息通过 Google `authenticode` 解析 PE 的 PKCS#7 结构，并按
//! SignerIdentifier（issuer + serial）匹配叶证书。匹配不到时返回 Unknown/无发布者，
//! 不会把证书集合中的第一个证书当作签名者。
//!
//! 本模块严格区分：
//! - 是否存在签名证书表；
//! - 证书表是否能解析为有效结构；
//! - WinVerifyTrust 的信任结果；
//! - 证书链状态；
//! - 发布者主题信息；
//! - 失败/信息不足原因。

use std::fs;
use std::path::Path;

use authenticode::{AttributeCertificateIterator, AuthenticodeSignature, PeTrait};
use cms::signed_data::SignerIdentifier;
use object::read::pe::{PeFile32, PeFile64};
use windows_sys::Win32::Foundation::{
    CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_REVOKED, CERT_E_UNTRUSTEDROOT, CERT_E_WRONG_USAGE,
    TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE,
    TRUST_E_SUBJECT_NOT_TRUSTED,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_EXECUTE,
    WinVerifyTrustEx,
};
use x509_cert::Certificate;
use x509_cert::der::asn1::{Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};
use x509_cert::name::Name;

use crate::models::{ChainStatus, SignatureInfo, SignatureStatus};
use crate::utils::windows_api::to_wide_null;

/// 解析签名结构时的文件大小上限。超过后仍可由 WinVerifyTrust 判定信任状态，
/// 但不读取发布者信息，避免把大型安装包整个载入内存。
const MAX_PARSE_BYTES: u64 = 256 * 1024 * 1024;

const OID_COMMON_NAME: &str = "2.5.4.3";
const OID_ORGANIZATION: &str = "2.5.4.10";

pub fn inspect(path: &Path, is_pe: bool) -> SignatureInfo {
    let trust = verify_trust(path);
    let mut signature = SignatureInfo {
        signature_present: None,
        structure_valid: None,
        signer_certificate_found: false,
        trust_status: trust.status,
        chain_status: chain_status(trust.status),
        signer_subject: None,
        signer_issuer: None,
        publisher_common_name: None,
        publisher_organization: None,
        is_self_signed: None,
        error_code: trust.error_code,
        diagnostic: trust.error_message.clone(),
    };

    if !is_pe {
        // MSI 未解析 PKCS#7 结构，但 WinVerifyTrust 的状态可以判断“是否有签名”。
        signature.signature_present = match trust.status {
            SignatureStatus::NotSigned => Some(false),
            SignatureStatus::Valid
            | SignatureStatus::Invalid
            | SignatureStatus::UntrustedRoot
            | SignatureStatus::Expired
            | SignatureStatus::Revoked => Some(true),
            SignatureStatus::Unknown | SignatureStatus::Unavailable => None,
        };
        append_diagnostic(
            &mut signature,
            "MSI 签名证书结构未解析；发布者请使用 MSI Manufacturer 字段".to_string(),
        );
        return signature;
    }

    // authenticode 的 certificates() 对非 Certificate CHOICE 会 panic；这里兜底，
    // 保证单个损坏签名不会让扫描 worker 崩溃。
    let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| read_pe_signature(path)));

    match parsed {
        Ok(Ok(result)) => {
            signature.signature_present = Some(result.present);
            signature.structure_valid = Some(result.structure_valid);
            if let Some(diagnostic) = result.diagnostic {
                append_diagnostic(&mut signature, diagnostic);
            }
            if let Some(signer) = result.signer {
                signature.signer_certificate_found = true;
                signature.signer_subject = Some(signer.subject);
                signature.signer_issuer = Some(signer.issuer);
                signature.publisher_common_name = signer.common_name;
                signature.publisher_organization = signer.organization;
                signature.is_self_signed = Some(signer.self_signed);
            }
        }
        Ok(Err(message)) => {
            signature.signature_present = None;
            signature.structure_valid = Some(false);
            append_diagnostic(&mut signature, format!("PE 签名结构解析失败: {message}"));
        }
        Err(_) => {
            signature.signature_present = None;
            signature.structure_valid = Some(false);
            append_diagnostic(
                &mut signature,
                "签名结构解析发生内部错误（已隔离）".to_string(),
            );
        }
    }

    signature
}

struct TrustResult {
    status: SignatureStatus,
    error_code: Option<i32>,
    error_message: Option<String>,
}

struct PeSignatureResult {
    present: bool,
    structure_valid: bool,
    signer: Option<SignerIdentity>,
    diagnostic: Option<String>,
}

struct SignerIdentity {
    subject: String,
    issuer: String,
    common_name: Option<String>,
    organization: Option<String>,
    self_signed: bool,
}

fn verify_trust(path: &Path) -> TrustResult {
    let wide_path = to_wide_null(path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide_path.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: std::ptr::null_mut(),
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: 结构体按 Windows SDK 布局初始化，路径在调用期间保持存活；
    // WinVerifyTrustEx 只读取这些指针，不保留它们。
    let status = unsafe { WinVerifyTrustEx(std::ptr::null_mut(), &mut action, &mut data) };

    // 释放 WinVerifyTrust 分配的状态数据。关闭调用的返回值不影响已经取得的判定结果。
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: 同一次验证使用的 WINTRUST_DATA，仍保持有效。
    let _ = unsafe { WinVerifyTrustEx(std::ptr::null_mut(), &mut action, &mut data) };

    if status == 0 {
        return TrustResult {
            status: SignatureStatus::Valid,
            error_code: None,
            error_message: None,
        };
    }

    TrustResult {
        status: map_status(status),
        error_code: Some(status),
        error_message: Some(format!("WinVerifyTrust 返回 0x{:08X}", status as u32)),
    }
}

fn map_status(status: i32) -> SignatureStatus {
    match status {
        0 => SignatureStatus::Valid,
        TRUST_E_NOSIGNATURE => SignatureStatus::NotSigned,
        CERT_E_UNTRUSTEDROOT | CERT_E_CHAINING => SignatureStatus::UntrustedRoot,
        CERT_E_EXPIRED => SignatureStatus::Expired,
        CERT_E_REVOKED => SignatureStatus::Revoked,
        TRUST_E_BAD_DIGEST
        | TRUST_E_EXPLICIT_DISTRUST
        | TRUST_E_SUBJECT_NOT_TRUSTED
        | CERT_E_WRONG_USAGE => SignatureStatus::Invalid,
        _ => SignatureStatus::Unknown,
    }
}

fn chain_status(status: SignatureStatus) -> ChainStatus {
    match status {
        SignatureStatus::Valid => ChainStatus::Valid,
        SignatureStatus::UntrustedRoot => ChainStatus::UntrustedRoot,
        SignatureStatus::Expired => ChainStatus::Expired,
        SignatureStatus::Revoked => ChainStatus::Revoked,
        SignatureStatus::Invalid => ChainStatus::Invalid,
        SignatureStatus::NotSigned => ChainStatus::NotChecked,
        SignatureStatus::Unknown | SignatureStatus::Unavailable => ChainStatus::Unknown,
    }
}

fn read_pe_signature(path: &Path) -> Result<PeSignatureResult, String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() > MAX_PARSE_BYTES {
        return Err(format!(
            "文件大小 {} 字节超过签名解析上限 {} 字节",
            metadata.len(),
            MAX_PARSE_BYTES
        ));
    }

    let data = fs::read(path).map_err(|error| error.to_string())?;

    // 安装程序大量是 PE32（32 位），不能只按 PE32+ 解析。
    if let Ok(pe) = PeFile64::parse(data.as_slice()) {
        return read_pe_signature_from_pe(&pe);
    }
    let pe = PeFile32::parse(data.as_slice()).map_err(|error| error.to_string())?;
    read_pe_signature_from_pe(&pe)
}

fn read_pe_signature_from_pe(pe: &dyn PeTrait) -> Result<PeSignatureResult, String> {
    let Some(iterator) =
        AttributeCertificateIterator::new(pe).map_err(|error| error.to_string())?
    else {
        return Ok(PeSignatureResult {
            present: false,
            structure_valid: false,
            signer: None,
            diagnostic: Some("PE 没有 Authenticode 证书表".to_string()),
        });
    };

    let mut last_error = None;
    for certificate in iterator {
        let certificate = match certificate {
            Ok(certificate) => certificate,
            Err(error) => {
                last_error = Some(format!("证书表条目无效: {error}"));
                continue;
            }
        };
        let signature = match certificate.get_authenticode_signature() {
            Ok(signature) => signature,
            Err(error) => {
                last_error = Some(format!("Authenticode 签名结构无效: {error}"));
                continue;
            }
        };

        match match_signer_certificate(&signature) {
            Ok(signer) => {
                return Ok(PeSignatureResult {
                    present: true,
                    structure_valid: true,
                    signer,
                    diagnostic: None,
                });
            }
            Err(reason) => {
                return Ok(PeSignatureResult {
                    present: true,
                    structure_valid: true,
                    signer: None,
                    diagnostic: Some(reason),
                });
            }
        }
    }

    Ok(PeSignatureResult {
        present: true,
        structure_valid: false,
        signer: None,
        diagnostic: last_error
            .or_else(|| Some("证书表中没有可解析的 Authenticode 签名".to_string())),
    })
}

fn match_signer_certificate(
    signature: &AuthenticodeSignature,
) -> Result<Option<SignerIdentity>, String> {
    let signer_info = signature.signer_info();
    match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(identifier) => {
            for certificate in signature.certificates() {
                if certificate.tbs_certificate.issuer == identifier.issuer
                    && certificate.tbs_certificate.serial_number == identifier.serial_number
                {
                    return Ok(Some(signer_identity(certificate)));
                }
            }
            Err(
                "未找到 SignerIdentifier（issuer + serial）对应的叶证书；拒绝猜测发布者"
                    .to_string(),
            )
        }
        SignerIdentifier::SubjectKeyIdentifier(_) => {
            Err("签名者使用 SubjectKeyIdentifier，当前未可靠匹配叶证书；发布者未知".to_string())
        }
    }
}

fn signer_identity(certificate: &Certificate) -> SignerIdentity {
    let subject = certificate.tbs_certificate.subject.to_string();
    let issuer = certificate.tbs_certificate.issuer.to_string();
    let self_signed = certificate.tbs_certificate.subject == certificate.tbs_certificate.issuer;
    SignerIdentity {
        common_name: name_value(&certificate.tbs_certificate.subject, OID_COMMON_NAME),
        organization: name_value(&certificate.tbs_certificate.subject, OID_ORGANIZATION),
        subject,
        issuer,
        self_signed,
    }
}

fn name_value(name: &Name, oid: &str) -> Option<String> {
    for rdn in &name.0 {
        for attribute in rdn.0.iter() {
            if attribute.oid.to_string() == oid
                && let Some(value) = any_to_string(&attribute.value)
            {
                return Some(value);
            }
        }
    }
    None
}

fn any_to_string(value: &x509_cert::der::asn1::Any) -> Option<String> {
    if let Ok(value) = value.decode_as::<Utf8StringRef>() {
        return Some(value.as_str().to_string());
    }
    if let Ok(value) = value.decode_as::<PrintableStringRef>() {
        return Some(value.as_str().to_string());
    }
    if let Ok(value) = value.decode_as::<Ia5StringRef>() {
        return Some(value.as_str().to_string());
    }
    if let Ok(value) = value.decode_as::<TeletexStringRef>() {
        return Some(value.as_str().to_string());
    }
    None
}

fn append_diagnostic(signature: &mut SignatureInfo, message: String) {
    match &mut signature.diagnostic {
        Some(existing) if !existing.is_empty() => {
            existing.push_str("; ");
            existing.push_str(&message);
        }
        Some(existing) => *existing = message,
        None => signature.diagnostic = Some(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("tests")
            .join("fixtures")
            .join("metadata")
            .join(name)
    }

    #[test]
    fn unsigned_fixture_is_not_signed() {
        let signature = inspect(&fixture("plain.exe"), true);
        assert_eq!(signature.trust_status, SignatureStatus::NotSigned);
        assert_eq!(signature.chain_status, ChainStatus::NotChecked);
        assert_eq!(signature.signature_present, Some(false));
        assert_eq!(signature.structure_valid, Some(false));
        assert!(!signature.signer_certificate_found);
        assert!(signature.signer_subject.is_none());
    }

    #[test]
    fn self_signed_fixture_is_parsed_but_not_trusted() {
        let signature = inspect(&fixture("signed-self.exe"), true);
        assert!(
            matches!(
                signature.trust_status,
                SignatureStatus::UntrustedRoot
                    | SignatureStatus::Invalid
                    | SignatureStatus::Unknown
            ),
            "自签名证书不应被判定为受信任: {signature:?}"
        );
        assert_eq!(signature.signature_present, Some(true));
        assert_eq!(signature.structure_valid, Some(true));
        assert!(signature.signer_certificate_found);
        assert!(matches!(
            signature.chain_status,
            ChainStatus::UntrustedRoot | ChainStatus::Invalid | ChainStatus::Unknown
        ));
        assert_eq!(signature.is_self_signed, Some(true));
        assert!(
            signature
                .publisher_common_name
                .as_deref()
                .is_some_and(|value| value.contains("UpSweep Fixture Signer"))
        );
        assert_eq!(
            signature.publisher_organization.as_deref(),
            Some("UpSweep Test")
        );
    }

    #[test]
    fn tampered_signed_fixture_is_invalid_but_structure_is_parsed() {
        let signature = inspect(&fixture("signed-tampered.exe"), true);
        assert_eq!(signature.signature_present, Some(true));
        assert_eq!(signature.structure_valid, Some(true));
        assert!(signature.signer_certificate_found);
        assert!(
            matches!(
                signature.trust_status,
                SignatureStatus::Invalid | SignatureStatus::Unknown
            ),
            "篡改后的签名不应被判定为有效: {signature:?}"
        );
    }

    #[test]
    fn corrupt_pe_does_not_panic() {
        let signature = inspect(&fixture("corrupt.exe"), true);
        assert_ne!(signature.trust_status, SignatureStatus::Valid);
        assert!(!signature.signer_certificate_found);
    }

    #[test]
    fn trusted_system_binary_has_valid_signature_when_available() {
        let path = Path::new(r"C:\Windows\System32\kernel32.dll");
        if !path.exists() {
            eprintln!("kernel32.dll 不存在，跳过受信任签名测试");
            return;
        }
        let signature = inspect(path, true);
        assert_eq!(
            signature.trust_status,
            SignatureStatus::Valid,
            "系统二进制应有受信任签名: {signature:?}"
        );
        assert_eq!(signature.chain_status, ChainStatus::Valid);
        assert_eq!(signature.signature_present, Some(true));
        assert_eq!(signature.structure_valid, Some(true));
        assert!(signature.signer_certificate_found);
        assert!(signature.publisher_common_name.is_some() || signature.signer_subject.is_some());
    }
}
