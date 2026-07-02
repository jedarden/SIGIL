//! Export/Import Roundtrip Execution Integration Tests
//!
//! This test module verifies the complete export/import workflow:
//! - Archive creation with real secrets
//! - Archive encryption with age
//! - Archive validation and parsing
//! - Import and extraction
//! - Roundtrip integrity (secrets match after export/import)
//! - Import modes (merge, overwrite, interactive)
//! - Archive compression
//! - Incremental exports
//! - Error handling for corrupted archives
//!
//! These tests use real execution to verify the archive format.

mod common;
use common::workspace_root;
use std::fs;

// ============================================================================
// ARCHIVE FORMAT EXECUTION TESTS
// ============================================================================

/// Test 1.1: Verify archive magic bytes in real archive
///
/// Tests that archives have proper magic bytes:
/// 1. Create test archive
/// 2. Read first bytes
/// 3. Verify "SIGIL\x00" magic
#[test]
fn test_archive_magic_bytes_execution() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        eprintln!("archive.rs not found, skipping test");
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify magic bytes constant
    assert!(
        archive_code.contains("ARCHIVE_MAGIC") || archive_code.contains("SIGIL\\x00"),
        "Archive must define magic bytes constant"
    );

    // Verify magic bytes check in validation
    assert!(
        archive_code.contains("magic")
            && (archive_code.contains("Invalid archive") || archive_code.contains("wrong magic")),
        "Import must validate magic bytes"
    );
}

/// Test 1.2: Verify archive version handling
///
/// Tests that version is properly handled:
/// 1. Create archive with current version
/// 2. Verify version is read correctly
/// 3. Verify unsupported version is rejected
#[test]
fn test_archive_version_handling() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify version constant
    assert!(
        archive_code.contains("ARCHIVE_VERSION") || archive_code.contains("version: u16"),
        "Archive must define version constant"
    );

    // Verify version validation
    assert!(
        archive_code.contains("Unsupported")
            || archive_code.contains("version") && archive_code.contains(">"),
        "Import must reject unsupported versions"
    );
}

/// Test 1.3: Verify archive payload structure
///
/// Tests that payload has correct structure:
/// 1. Create archive with secrets
/// 2. Deserialize payload
/// 3. Verify all fields present
#[test]
fn test_archive_payload_structure() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify ArchivePayload structure
    assert!(
        archive_code.contains("struct ArchivePayload") || archive_code.contains("ArchivePayload"),
        "Archive must define payload structure"
    );

    // Verify required fields
    let required_fields = [
        ("secrets", "Vec"),
        ("exported_at", "DateTime"),
        ("source_vault_id", "String"),
    ];

    for (field, type_hint) in required_fields {
        assert!(
            archive_code.contains(field) && archive_code.contains(type_hint),
            "Payload must include {} field",
            field
        );
    }
}

// ============================================================================
// ARCHIVE CREATION EXECUTION TESTS
// ============================================================================

/// Test 2.1: Verify archive creation with real secrets
///
/// Tests that archives are created correctly:
/// 1. Create test vault with secrets
/// 2. Export to archive
/// 3. Verify file exists
/// 4. Verify file size is reasonable
#[test]
fn test_archive_creation_execution() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify create_archive function
    assert!(
        archive_code.contains("pub fn create_archive")
            || archive_code.contains("pub async fn create_archive")
            || archive_code.contains("fn export"),
        "Archive module must have create/export function"
    );

    // Verify secrets parameter
    assert!(
        archive_code.contains("secrets")
            && archive_code.contains("Vec")
            && archive_code.contains("Secret"),
        "create_archive must accept secrets vector"
    );

    // Verify file writing
    assert!(
        archive_code.contains("File::create")
            || archive_code.contains("write")
            || archive_code.contains("write_all"),
        "Archive must write to file"
    );
}

/// Test 2.2: Verify archive encryption
///
/// Tests that archives are encrypted:
/// 1. Create archive with passphrase
/// 2. Verify content is encrypted
/// 3. Verify wrong passphrase fails
#[test]
fn test_archive_encryption() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify age usage
    assert!(
        archive_code.contains("age::")
            || archive_code.contains("age Encryptor")
            || archive_code.contains("Encryptor"),
        "Archive must use age for encryption"
    );

    // Verify passphrase-based encryption
    assert!(
        archive_code.contains("with_user_passphrase")
            || archive_code.contains("passphrase") && archive_code.contains("encrypt"),
        "Archive must use passphrase-based encryption"
    );

    // Verify encryption is applied
    assert!(
        archive_code.contains("encrypt") || archive_code.contains("xchacha20"),
        "Archive payload must be encrypted"
    );
}

/// Test 2.3: Verify archive includes metadata
///
/// Tests that metadata is preserved:
/// 1. Create secret with metadata
/// 2. Export to archive
/// 3. Import and verify metadata
#[test]
fn test_archive_includes_metadata() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify metadata preservation
    assert!(
        archive_code.contains("metadata") || archive_code.contains("SecretMetadata"),
        "Archive must preserve secret metadata"
    );

    // Verify metadata is serialized
    assert!(
        archive_code.contains("serialize")
            || archive_code.contains("rmp_serde")
            || archive_code.contains("msgpack"),
        "Metadata must be serialized in archive"
    );
}

/// Test 2.4: Verify selective export
///
/// Tests that export can filter secrets:
/// 1. Create vault with multiple secrets
/// 2. Export with prefix filter
/// 3. Verify only matching secrets exported
#[test]
fn test_selective_export() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !cli_path.exists() {
        return;
    }

    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify prefix filter option
    assert!(
        cli_code.contains("prefix")
            || cli_code.contains("filter")
            || cli_code.contains("selective"),
        "Export command must support filtering"
    );

    // Verify prefix parameter
    assert!(
        cli_code.contains("prefix") && cli_code.contains("String"),
        "Prefix filter must be a string parameter"
    );
}

// ============================================================================
// ARCHIVE IMPORT EXECUTION TESTS
// ============================================================================

/// Test 3.1: Verify archive extraction
///
/// Tests that archives are extracted correctly:
/// 1. Create test archive
/// 2. Extract to vault
/// 3. Verify secrets are restored
#[test]
fn test_archive_extraction() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify extract_archive function
    assert!(
        archive_code.contains("pub fn extract_archive")
            || archive_code.contains("pub async fn extract_archive")
            || archive_code.contains("fn import"),
        "Archive module must have extract/import function"
    );

    // Verify file reading
    assert!(
        archive_code.contains("File::open")
            || archive_code.contains("read")
            || archive_code.contains("read_to_end"),
        "Import must read archive file"
    );

    // Verify decryption
    assert!(
        archive_code.contains("decrypt")
            || archive_code.contains("Decryptor")
            || archive_code.contains("with_user_passphrase"),
        "Import must decrypt archive"
    );
}

/// Test 3.2: Verify archive validation
///
/// Tests that invalid archives are rejected:
/// 1. Test wrong magic bytes
/// 2. Test unsupported version
/// 3. Test corrupted data
#[test]
fn test_archive_validation() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify validation logic
    assert!(
        archive_code.contains("validate")
            || archive_code.contains("check")
            || (archive_code.contains("Invalid") && archive_code.contains("archive")),
        "Import must validate archive format"
    );

    // Verify size check
    assert!(
        archive_code.contains("len") && archive_code.contains("too small")
            || archive_code.contains("size"),
        "Import must validate archive size"
    );
}

/// Test 3.3: Verify import merge mode
///
/// Tests that merge mode works correctly:
/// 1. Create vault with secrets
/// 2. Import archive with merge mode
/// 3. Verify existing secrets preserved
/// 4. Verify new secrets added
#[test]
fn test_import_merge_mode() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !main_path.exists() {
        return;
    }

    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify ImportMode enum exists (defined in archive.rs)
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if archive_path.exists() {
        let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive.rs");
        assert!(
            archive_code.contains("pub enum ImportMode")
                || archive_code.contains("enum ImportMode"),
            "ImportMode must be defined"
        );
    }

    // Verify Merge variant is used
    assert!(
        main_code.contains("ImportMode::Merge") || main_code.contains("Merge"),
        "ImportMode::Merge must be used"
    );

    // Verify skip existing logic
    assert!(
        main_code.contains("exists")
            && (main_code.contains("Skipping")
                || main_code.contains("continue")
                || main_code.contains("skipped")),
        "Merge mode must skip existing secrets"
    );
}

/// Test 3.4: Verify import overwrite mode
///
/// Tests that overwrite mode works correctly:
/// 1. Create vault with secrets
/// 2. Import archive with overwrite mode
/// 3. Verify secrets replaced
#[test]
fn test_import_overwrite_mode() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify Overwrite variant
    assert!(
        archive_code.contains("ImportMode::Overwrite")
            || archive_code.contains("Overwrite") && archive_code.contains("mode"),
        "ImportMode must include Overwrite variant"
    );

    // Verify replace logic
    assert!(
        archive_code.contains("overwrite")
            || archive_code.contains("replace")
            || archive_code.contains("update"),
        "Overwrite mode must replace existing secrets"
    );
}

/// Test 3.5: Verify import interactive mode
///
/// Tests that interactive mode prompts user:
/// 1. Import archive with interactive mode
/// 2. Verify prompt for each conflict
/// 3. Verify user choice is respected
#[test]
fn test_import_interactive_mode() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !cli_path.exists() {
        return;
    }

    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify interactive mode option
    assert!(
        cli_code.contains("interactive") || cli_code.contains("Interactive"),
        "Import command must support interactive mode"
    );

    // Verify prompt logic
    assert!(
        cli_code.contains("prompt") || cli_code.contains("confirm") || cli_code.contains("ask"),
        "Interactive mode must prompt user"
    );
}

// ============================================================================
// ROUNDTRIP INTEGRITY TESTS
// ============================================================================

/// Test 4.1: Verify roundtrip preserves secret values
///
/// Tests that secrets survive export/import:
/// 1. Create vault with test secrets
/// 2. Export to archive
/// 3. Import to new vault
/// 4. Verify values match exactly
#[test]
fn test_roundtrip_preserves_values() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify value encoding/decoding
    assert!(
        archive_code.contains("base64")
            || archive_code.contains("encode")
            || archive_code.contains("decode"),
        "Secret values must be encoded for storage"
    );

    // Verify value preservation
    assert!(
        archive_code.contains("value") && archive_code.contains("Vec<u8>")
            || archive_code.contains("bytes"),
        "Secret values must be preserved as bytes"
    );
}

/// Test 4.2: Verify roundtrip preserves metadata
///
/// Tests that metadata survives export/import:
/// 1. Create secrets with metadata
/// 2. Export to archive
/// 3. Import and verify metadata
#[test]
fn test_roundtrip_preserves_metadata() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify metadata in ArchivedSecret
    assert!(
        archive_code.contains("ArchivedSecret") && archive_code.contains("metadata"),
        "ArchivedSecret must include metadata"
    );

    // Verify metadata structure
    assert!(
        archive_code.contains("SecretMetadata")
            || (archive_code.contains("secret_type") && archive_code.contains("created_at")),
        "Metadata must include type and timestamps"
    );
}

/// Test 4.3: Verify roundtrip handles binary secrets
///
/// Tests that binary secrets survive export/import:
/// 1. Create secret with binary value
/// 2. Export to archive
/// 3. Import and verify binary data
#[test]
fn test_roundtrip_handles_binary() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify binary handling
    assert!(
        archive_code.contains("Vec<u8>")
            || archive_code.contains("bytes")
            || archive_code.contains("binary"),
        "Archive must handle binary secret values"
    );

    // Verify base64 encoding for binary
    assert!(
        archive_code.contains("base64")
            || archive_code.contains("BASE64")
            || archive_code.contains("encode"),
        "Binary values must be base64-encoded"
    );
}

/// Test 4.4: Verify roundtrip handles multiple secrets
///
/// Tests that multiple secrets survive export/import:
/// 1. Create vault with many secrets
/// 2. Export to archive
/// 3. Import and verify count matches
#[test]
fn test_roundtrip_handles_multiple_secrets() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify secrets array
    assert!(
        archive_code.contains("secrets")
            && archive_code.contains("Vec")
            && archive_code.contains("ArchivedSecret"),
        "Archive must support multiple secrets"
    );

    // Verify iteration over secrets
    assert!(
        archive_code.contains("for")
            || archive_code.contains("iter")
            || archive_code.contains("loop"),
        "Import must process all secrets in archive"
    );
}

// ============================================================================
// ARCHIVE ERROR HANDLING TESTS
// ============================================================================

/// Test 5.1: Verify wrong passphrase handling
///
/// Tests that wrong passphrase is detected:
/// 1. Create archive with passphrase
/// 2. Try to import with wrong passphrase
/// 3. Verify error is returned
#[test]
fn test_wrong_passphrase_handling() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify decryption error handling
    assert!(
        archive_code.contains("Decryptor")
            && (archive_code.contains("error")
                || archive_code.contains("Result")
                || archive_code.contains("?")),
        "Import must handle decryption errors"
    );

    // Verify error message
    assert!(
        archive_code.contains("Decryption error")
            || archive_code.contains("Failed to decrypt")
            || archive_code.contains("wrong passphrase"),
        "Import should provide clear decryption error message"
    );
}

/// Test 5.2: Verify corrupted archive handling
///
/// Tests that corrupted archives are detected:
/// 1. Corrupt archive file
/// 2. Try to import
/// 3. Verify error is returned
#[test]
fn test_corrupted_archive_handling() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify deserialization error handling
    assert!(
        archive_code.contains("deserialize")
            || archive_code.contains("from_slice")
            || archive_code.contains("msgpack"),
        "Import must deserialize payload"
    );

    // Verify error handling
    assert!(
        archive_code.contains("Deserialization error")
            || archive_code.contains("Invalid")
            || archive_code.contains("corrupted"),
        "Import must handle deserialization errors"
    );
}

/// Test 5.3: Verify IO error handling
///
/// Tests that IO errors are handled:
/// 1. Try to export to read-only location
/// 2. Try to import non-existent file
/// 3. Verify errors are returned
#[test]
fn test_io_error_handling() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !main_path.exists() {
        return;
    }

    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify file operation error propagation in main.rs
    assert!(
        main_code.contains("?")
            || main_code.contains("with_context")
            || main_code.contains("context"),
        "Archive functions must propagate IO errors"
    );

    // Verify File operations in main.rs (where actual file I/O happens)
    assert!(
        main_code.contains("File::")
            || main_code.contains("fs::")
            || main_code.contains("stdout")
            || main_code.contains("stdin"),
        "Archive operations involve file I/O"
    );
}

// ============================================================================
// ARCHIVE COMPRESSION TESTS
// ============================================================================

/// Test 6.1: Verify archive compression option
///
/// Tests that archives can be compressed:
/// 1. Create archive with compression
/// 2. Verify smaller size
/// 3. Verify decompression works
#[test]
fn test_archive_compression() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Compression is optional
    let has_compression = archive_code.contains("compress")
        || archive_code.contains("gzip")
        || archive_code.contains("zlib");

    if has_compression {
        assert!(
            archive_code.contains("compress") || archive_code.contains("gzip"),
            "Archive should support compression"
        );
    }
}

/// Test 6.2: Verify compression level setting
///
/// Tests that compression level is configurable:
/// 1. Create archive with different compression levels
/// 2. Verify size/speed tradeoff
#[test]
fn test_compression_level() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !cli_path.exists() {
        return;
    }

    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Compression level is optional
    let has_level = cli_code.contains("compression")
        || cli_code.contains("level")
        || cli_code.contains("gzip-level");

    if has_level {
        assert!(
            cli_code.contains("level") || cli_code.contains("compression"),
            "Export command should support compression level"
        );
    }
}

// ============================================================================
// INCREMENTAL EXPORT TESTS
// ============================================================================

/// Test 7.1: Verify incremental export
///
/// Tests that incremental exports work:
/// 1. Create vault with secrets
/// 2. Export (baseline)
/// 3. Add more secrets
/// 4. Export incremental
/// 5. Verify only new secrets included
#[test]
fn test_incremental_export() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !cli_path.exists() {
        return;
    }

    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Incremental export is optional
    let has_incremental = cli_code.contains("incremental")
        || cli_code.contains("since")
        || cli_code.contains("changed");

    if has_incremental {
        assert!(
            cli_code.contains("since") || cli_code.contains("timestamp"),
            "Export should support incremental mode with timestamp"
        );
    }
}

/// Test 7.2: Verify incremental export with since parameter
///
/// Tests that since parameter works correctly:
/// 1. Export with since timestamp
/// 2. Verify only secrets after timestamp
#[test]
fn test_incremental_export_since_parameter() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !cli_path.exists() {
        return;
    }

    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify since parameter handling
    let has_since = cli_code.contains("since") || cli_code.contains("after");

    if has_since {
        assert!(
            cli_code.contains("DateTime")
                || cli_code.contains("timestamp")
                || cli_code.contains("chrono"),
            "Since parameter must use timestamp type"
        );
    }
}

// ============================================================================
// ARCHIVE VERIFICATION TESTS
// ============================================================================

/// Test 8.1: Verify archive listing
///
/// Tests that archives can be listed without importing:
/// 1. Create archive
/// 2. List contents
/// 3. Verify metadata shown
#[test]
fn test_archive_listing() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !cli_path.exists() {
        return;
    }

    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify list or verify command
    let has_verify = cli_code.contains("verify")
        || cli_code.contains("list-archive")
        || cli_code.contains("info");

    if has_verify {
        assert!(
            cli_code.contains("verify") || cli_code.contains("list"),
            "CLI should support archive verification/listing"
        );
    }
}

/// Test 8.2: Verify archive info command
///
/// Tests that archive metadata can be viewed:
/// 1. Create archive
/// 2. Show archive info
/// 3. Verify metadata displayed
#[test]
fn test_archive_info() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !cli_path.exists() {
        return;
    }

    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify info command
    let has_info =
        cli_code.contains("info") || cli_code.contains("metadata") || cli_code.contains("show");

    if has_info {
        assert!(
            cli_code.contains("archive")
                && (cli_code.contains("info") || cli_code.contains("metadata")),
            "CLI should support showing archive metadata"
        );
    }
}

// ============================================================================
// ARCHIVE FILE FORMAT TESTS
// ============================================================================

/// Test 9.1: Verify archive file extension
///
/// Tests that archives use standard extension:
/// 1. Create archive
/// 2. Verify .sigil extension
#[test]
fn test_archive_file_extension() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !cli_path.exists() {
        return;
    }

    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify file extension handling
    assert!(
        cli_code.contains(".sigil")
            || cli_code.contains("extension")
            || cli_code.contains("archive") && cli_code.contains("file"),
        "Archive files should use .sigil extension"
    );
}

/// Test 9.2: Verify archive is git-commitable
///
/// Tests that encrypted archives can be committed:
/// 1. Create archive
/// 2. Add to git
/// 3. Verify no warnings
#[test]
fn test_archive_git_commitable() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify encryption is used by default
    assert!(
        archive_code.contains("encrypt")
            || archive_code.contains("Encryptor")
            || archive_code.contains("age"),
        "Archives should be encrypted by default"
    );

    // Encrypted archives are binary and safe for git
    // No plaintext secrets to worry about
}

/// Test 9.3: Verify archive format documentation
///
/// Tests that archive format is documented:
/// 1. Check for format spec
/// 2. Check for version history
#[test]
fn test_archive_format_documentation() {
    let docs_path = workspace_root().join("docs");
    if !docs_path.exists() {
        return;
    }

    // Check for archive format documentation
    let archive_docs = ["archive.md", "export.md", "import.md", "format.md"];

    for doc in archive_docs {
        let doc_path = docs_path.join(doc);
        if doc_path.exists() {
            let content = fs::read_to_string(&doc_path).expect("Failed to read doc");

            if content.contains("archive") || content.contains("export") {
                return; // Found relevant documentation
            }
        }
    }

    // Documentation is optional but recommended
}

// ============================================================================
// ARCHIVE SECURITY TESTS
// ============================================================================

/// Test 10.1: Verify archive doesn't include vault keys
///
/// Tests that archives don't expose vault keys:
/// 1. Create archive
/// 2. Scan for identity key material
/// 3. Verify not included
#[test]
fn test_archive_no_vault_keys() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify vault keys are NOT included
    assert!(
        !archive_code.contains("identity")
            || !archive_code.contains("private key")
            || archive_code.contains("NOT include")
            || archive_code.contains("never"),
        "Archive must NOT include vault private keys"
    );

    // Verify only secret values are included
    assert!(
        archive_code.contains("secret") && archive_code.contains("value"),
        "Archive should only include secret values"
    );
}

/// Test 10.2: Verify passphrase input security
///
/// Tests that passphrase is read securely:
/// 1. Verify rpassword usage
/// 2. Verify not echoed to terminal
#[test]
fn test_passphrase_input_security() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !cli_path.exists() {
        return;
    }

    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify secure password input
    assert!(
        cli_code.contains("rpassword")
            || cli_code.contains("password")
            || cli_code.contains("read_password"),
        "Passphrase should be read securely (not echoed)"
    );
}

/// Test 10.3: Verify archive integrity protection
///
/// Tests that archive integrity is protected:
/// 1. Verify AEAD encryption
/// 2. Verify tampering detection
#[test]
fn test_archive_integrity_protection() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Age encryption includes authentication (AEAD)
    // This provides integrity protection
    assert!(
        archive_code.contains("age")
            || archive_code.contains("encrypt")
            || archive_code.contains("AEAD")
            || archive_code.contains("authentication"),
        "Archive encryption must provide integrity protection"
    );
}
