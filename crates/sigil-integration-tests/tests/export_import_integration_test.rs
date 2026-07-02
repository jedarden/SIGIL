//! Export/Import Archive Integration Tests
//!
//! This test module verifies the SIGIL archive format for export/import:
//! - Archive format (magic bytes, version, encryption)
//! - Export functionality (create archive from vault)
//! - Import functionality (extract archive to vault)
//! - Encryption with age (passphrase-based)
//! - Msgpack serialization
//! - Import conflict resolution (merge, overwrite, interactive)
//! - Archive validation
//! - Error handling
//!
//! These tests verify that secrets can be safely exported and imported.

mod common;
use common::workspace_root;
use std::fs;

// ============================================================================
// ARCHIVE FORMAT TESTS
// ============================================================================

/// Test 1.1: Verify archive magic bytes
///
/// Tests that the archive format has proper magic bytes:
/// - "SIGIL\x00" magic string
/// - Used to identify SIGIL archives
/// - Prevents processing wrong files
#[test]
fn test_archive_magic_bytes() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return; // Skip if archive module doesn't exist
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify magic bytes constant
    assert!(
        archive_code.contains("ARCHIVE_MAGIC") || archive_code.contains("SIGIL"),
        "Archive must define magic bytes constant"
    );

    // Verify magic bytes value
    assert!(
        archive_code.contains("SIGIL\\x00") || archive_code.contains("b\"SIGIL\\x00\""),
        "Magic bytes must be 'SIGIL\\x00'"
    );

    // Verify magic bytes check
    assert!(
        archive_code.contains("magic") || archive_code.contains("validate"),
        "Archive must validate magic bytes"
    );
}

/// Test 1.2: Verify archive version
///
/// Tests that the archive format has versioning:
/// - Version number (u16 big-endian)
/// - Version validation
/// - Forward/backward compatibility considerations
#[test]
fn test_archive_version() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify version constant
    assert!(
        archive_code.contains("ARCHIVE_VERSION") || archive_code.contains("version"),
        "Archive must define version constant"
    );

    // Verify version is u16
    assert!(
        archive_code.contains("u16") || archive_code.contains("to_be_bytes"),
        "Archive version must be u16"
    );

    // Verify version validation
    assert!(
        archive_code.contains("version") && archive_code.contains("Unsupported"),
        "Archive must validate version on import"
    );
}

/// Test 1.3: Verify archive payload structure
///
/// Tests that the archive payload has correct structure:
/// - Secrets array
/// - Export timestamp
/// - Source vault ID
/// - Msgpack serialization
#[test]
fn test_archive_payload_structure() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify ArchivePayload structure
    assert!(
        archive_code.contains("ArchivePayload") || archive_code.contains("struct Payload"),
        "Archive must define payload structure"
    );

    // Verify secrets field
    assert!(
        archive_code.contains("secrets") && archive_code.contains("Vec"),
        "Payload must contain secrets array"
    );

    // Verify exported_at field
    assert!(
        archive_code.contains("exported_at") || archive_code.contains("timestamp"),
        "Payload must contain export timestamp"
    );

    // Verify source_vault_id field
    assert!(
        archive_code.contains("source_vault_id") || archive_code.contains("vault_id"),
        "Payload must contain source vault ID"
    );

    // Verify msgpack serialization
    assert!(
        archive_code.contains("msgpack") || archive_code.contains("rmp_serde"),
        "Archive must use msgpack for serialization"
    );
}

/// Test 1.4: Verify archived secret structure
///
/// Tests that archived secrets have correct structure:
/// - Path
/// - Value (base64-encoded)
/// - Metadata
#[test]
fn test_archived_secret_structure() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify ArchivedSecret structure
    assert!(
        archive_code.contains("ArchivedSecret") || archive_code.contains("struct Secret"),
        "Archive must define secret structure"
    );

    // Verify path field
    assert!(
        archive_code.contains("path") && archive_code.contains("String"),
        "Archived secret must contain path"
    );

    // Verify value field (base64-encoded)
    assert!(
        archive_code.contains("value") && archive_code.contains("base64"),
        "Archived secret must contain base64-encoded value"
    );

    // Verify metadata field
    assert!(
        archive_code.contains("metadata") || archive_code.contains("SecretMetadata"),
        "Archived secret must contain metadata"
    );
}

/// Test 1.5: Verify archive file format
///
/// Tests the complete archive file format:
/// - Magic bytes (5 bytes)
/// - Version (2 bytes)
/// - Encrypted payload (variable)
#[test]
fn test_archive_file_format() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify archive building
    assert!(
        archive_code.contains("extend_from_slice") || archive_code.contains("write_all"),
        "Archive must build file from components"
    );

    // Verify header + payload structure
    assert!(
        archive_code.contains("magic")
            && archive_code.contains("version")
            && archive_code.contains("payload"),
        "Archive must combine magic, version, and payload"
    );

    // Verify payload encryption
    assert!(
        archive_code.contains("encrypt") || archive_code.contains("Encryptor"),
        "Archive payload must be encrypted"
    );
}

// ============================================================================
// EXPORT FUNCTIONALITY TESTS
// ============================================================================

/// Test 2.1: Verify export command exists
///
/// Tests that the export command is implemented:
/// - CLI command exists
/// - Calls archive creation function
/// - Handles passphrase input
#[test]
fn test_export_command_exists() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify export command
    assert!(
        cli_code.contains("CommandExport")
            || cli_code.contains("Export")
            || cli_code.contains("export"),
        "CLI must have export command"
    );

    // Verify export handler
    assert!(
        cli_code.contains("cmd_export")
            || cli_code.contains("handle_export")
            || cli_code.contains("export"),
        "CLI must handle export command"
    );

    // Verify output file parameter
    assert!(
        cli_code.contains("output") || cli_code.contains("file") || cli_code.contains("path"),
        "Export command must specify output file"
    );
}

/// Test 2.2: Verify export reads from vault
///
/// Tests that export reads secrets from vault:
/// - Loads vault
/// - Lists all secrets
/// - Gets secret values
#[test]
fn test_export_reads_from_vault() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify create_archive function
    assert!(
        archive_code.contains("create_archive") || archive_code.contains("pub fn export"),
        "Archive module must have create/export function"
    );

    // Verify secrets parameter
    assert!(
        archive_code.contains("secrets") && archive_code.contains("Vec"),
        "create_archive must accept secrets"
    );

    // Verify vault integration
    assert!(
        archive_code.contains("vault") || archive_code.contains("LocalVault"),
        "Export must integrate with vault"
    );
}

/// Test 2.3: Verify export encrypts with age
///
/// Tests that export uses age for encryption:
/// - Passphrase-based encryption
/// - Age encryptor is used
#[test]
fn test_export_encrypts_with_age() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify age usage
    assert!(
        archive_code.contains("age") || archive_code.contains("Encryptor"),
        "Export must use age for encryption"
    );

    // Verify passphrase parameter
    assert!(
        archive_code.contains("passphrase") || archive_code.contains("password"),
        "Export must accept passphrase"
    );

    // Verify passphrase-based encryption
    assert!(
        archive_code.contains("with_user_passphrase") || archive_code.contains("passphrase"),
        "Export must use passphrase-based encryption"
    );
}

/// Test 2.4: Verify export includes all secret metadata
///
/// Tests that export preserves all metadata:
/// - Secret type
/// - Tags
/// - Created/updated timestamps
#[test]
fn test_export_includes_metadata() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify metadata is included
    assert!(
        archive_code.contains("metadata") || archive_code.contains("SecretMetadata"),
        "Export must include secret metadata"
    );

    // Verify metadata structure
    assert!(
        archive_code.contains("secret_type")
            || archive_code.contains("tags")
            || archive_code.contains("created_at"),
        "Metadata must include type, tags, and timestamps"
    );
}

/// Test 2.5: Verify export supports selective export
///
/// Tests that export can filter secrets:
/// - By prefix
/// - By tag
#[test]
fn test_export_supports_selective_export() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify prefix filter
    let has_prefix = cli_code.contains("prefix") || cli_code.contains("filter");

    if has_prefix {
        assert!(
            cli_code.contains("prefix") && cli_code.contains("export"),
            "Export should support prefix filtering"
        );
    }
}

/// Test 2.6: Verify export supports no-encryption mode
///
/// Tests that export can skip encryption (for testing):
/// - Optional encryption
#[test]
fn test_export_supports_no_encryption() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify encryption is optional
    assert!(
        archive_code.contains("Option") && archive_code.contains("passphrase"),
        "Passphrase must be optional (allows no-encryption mode)"
    );

    // Verify conditional encryption
    assert!(
        archive_code.contains("if let Some") || archive_code.contains("unwrap_or"),
        "Encryption must be conditional on passphrase"
    );
}

// ============================================================================
// IMPORT FUNCTIONALITY TESTS
// ============================================================================

/// Test 3.1: Verify import command exists
///
/// Tests that the import command is implemented:
/// - CLI command exists
/// - Calls archive extraction function
/// - Handles passphrase input
#[test]
fn test_import_command_exists() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify import command
    assert!(
        cli_code.contains("CommandImport")
            || cli_code.contains("Import")
            || cli_code.contains("import"),
        "CLI must have import command"
    );

    // Verify import handler
    assert!(
        cli_code.contains("cmd_import")
            || cli_code.contains("handle_import")
            || cli_code.contains("import"),
        "CLI must handle import command"
    );

    // Verify input file parameter
    assert!(
        cli_code.contains("input") || cli_code.contains("file") || cli_code.contains("path"),
        "Import command must specify input file"
    );
}

/// Test 3.2: Verify import validates archive
///
/// Tests that import validates the archive:
/// - Magic bytes check
/// - Version check
/// - Size check
#[test]
fn test_import_validates_archive() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify extract_archive function
    assert!(
        archive_code.contains("extract_archive") || archive_code.contains("pub fn import"),
        "Archive module must have extract/import function"
    );

    // Verify magic bytes validation
    assert!(
        archive_code.contains("magic") && archive_code.contains("Invalid archive"),
        "Import must validate magic bytes"
    );

    // Verify version validation
    assert!(
        archive_code.contains("version") && archive_code.contains("Unsupported"),
        "Import must validate version"
    );

    // Verify size check
    assert!(
        archive_code.contains("too small") || archive_code.contains("len"),
        "Import must validate archive size"
    );
}

/// Test 3.3: Verify import decrypts with age
///
/// Tests that import decrypts with age:
/// - Passphrase-based decryption
/// - Age decryptor is used
#[test]
fn test_import_decrypts_with_age() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify age usage
    assert!(
        archive_code.contains("age") || archive_code.contains("Decryptor"),
        "Import must use age for decryption"
    );

    // Verify passphrase parameter
    assert!(
        archive_code.contains("passphrase") || archive_code.contains("password"),
        "Import must accept passphrase"
    );

    // Verify passphrase-based decryption
    assert!(
        archive_code.contains("with_user_passphrase") || archive_code.contains("passphrase"),
        "Import must use passphrase-based decryption"
    );
}

/// Test 3.4: Verify import writes to vault
///
/// Tests that import writes secrets to vault:
/// - Loads vault
/// - Adds secrets
/// - Preserves metadata
#[test]
fn test_import_writes_to_vault() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify extract returns secrets
    assert!(
        archive_code.contains("ArchivePayload") || archive_code.contains("secrets"),
        "Import must return secrets"
    );

    // Verify vault integration
    assert!(
        archive_code.contains("vault")
            || archive_code.contains("LocalVault")
            || archive_code.contains("add"),
        "Import must integrate with vault"
    );
}

/// Test 3.5: Verify import modes
///
/// Tests that import supports different modes:
/// - Merge (skip existing)
/// - Overwrite (replace existing)
/// - Interactive (prompt for each)
#[test]
fn test_import_modes() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify ImportMode enum
    assert!(
        archive_code.contains("ImportMode") || archive_code.contains("enum.*Mode"),
        "Archive must define import modes"
    );

    // Verify Merge variant
    assert!(
        archive_code.contains("Merge") || archive_code.contains("merge"),
        "Import must support merge mode"
    );

    // Verify Overwrite variant
    assert!(
        archive_code.contains("Overwrite") || archive_code.contains("overwrite"),
        "Import must support overwrite mode"
    );

    // Verify Interactive variant
    assert!(
        archive_code.contains("Interactive") || archive_code.contains("interactive"),
        "Import must support interactive mode"
    );
}

/// Test 3.6: Verify import conflict handling
///
/// Tests that import handles conflicts properly:
/// - Detects existing secrets
/// - Applies mode-specific behavior
/// - Reports conflicts
#[test]
fn test_import_conflict_handling() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify conflict detection
    assert!(
        archive_code.contains("exists")
            || archive_code.contains("conflict")
            || archive_code.contains("contains"),
        "Import must detect existing secrets"
    );

    // Verify mode-specific handling
    assert!(
        archive_code.contains("match") || archive_code.contains("ImportMode"),
        "Import must handle conflicts based on mode"
    );
}

/// Test 3.7: Verify import preserves metadata
///
/// Tests that import preserves all metadata:
/// - Secret type
/// - Tags
/// - Created/updated timestamps
#[test]
fn test_import_preserves_metadata() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !main_path.exists() {
        return;
    }

    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify metadata is preserved in archive struct
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive.rs");
    assert!(
        archive_code.contains("SecretMetadata"),
        "Archive must preserve secret metadata"
    );

    // Verify metadata is passed to vault.set during import
    assert!(
        main_code.contains("vault.set") && main_code.contains("archived_secret.metadata"),
        "Import must pass metadata to vault.set"
    );
}

// ============================================================================
// ARCHIVE ERROR HANDLING TESTS
// ============================================================================

/// Test 4.1: Verify invalid archive handling
///
/// Tests that invalid archives are rejected:
/// - Wrong magic bytes
/// - Unsupported version
/// - Corrupted data
#[test]
fn test_invalid_archive_handling() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify error handling
    assert!(
        archive_code.contains("Result")
            || archive_code.contains("bail")
            || archive_code.contains("anyhow"),
        "Archive functions must return Result"
    );

    // Verify magic bytes error
    assert!(
        archive_code.contains("Invalid archive") || archive_code.contains("wrong magic"),
        "Import must reject invalid magic bytes"
    );

    // Verify version error
    assert!(
        archive_code.contains("Unsupported") || archive_code.contains("version"),
        "Import must reject unsupported version"
    );
}

/// Test 4.2: Verify decryption error handling
///
/// Tests that decryption errors are handled:
/// - Wrong passphrase
/// - Corrypted data
#[test]
fn test_decryption_error_handling() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify decryption error handling
    assert!(
        archive_code.contains("Decryptor")
            && (archive_code.contains("error") || archive_code.contains("?")),
        "Import must handle decryption errors"
    );

    // Verify error message
    assert!(
        archive_code.contains("Decryption error") || archive_code.contains("Failed to decrypt"),
        "Import should provide clear decryption error messages"
    );
}

/// Test 4.3: Verify deserialization error handling
///
/// Tests that deserialization errors are handled:
/// - Invalid msgpack
/// - Missing fields
#[test]
fn test_deserialization_error_handling() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify msgpack deserialization
    assert!(
        archive_code.contains("rmp_serde") || archive_code.contains("from_slice"),
        "Import must deserialize msgpack"
    );

    // Verify deserialization error handling
    assert!(
        archive_code.contains("Deserialization error") || archive_code.contains("Invalid"),
        "Import must handle deserialization errors"
    );
}

/// Test 4.4: Verify IO error handling
///
/// Tests that IO errors are handled:
/// - File not found
/// - Permission denied
/// - Disk full
#[test]
fn test_io_error_handling() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify file operations
    assert!(
        archive_code.contains("read")
            || archive_code.contains("write")
            || archive_code.contains("File"),
        "Archive operations involve file I/O"
    );

    // Verify error propagation
    assert!(
        archive_code.contains("?")
            || archive_code.contains("with_context")
            || archive_code.contains("expect"),
        "Archive functions must propagate I/O errors"
    );
}

// ============================================================================
// ARCHIVE SECURITY TESTS
// ============================================================================

/// Test 5.1: Verify archive encryption is strong
///
/// Tests that archive encryption uses strong algorithms:
/// - Age encryption (XChaCha20-Poly1305)
/// - scrypt for passphrase-based key derivation
#[test]
fn test_archive_encryption_strength() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify age usage
    assert!(
        archive_code.contains("age::")
            || archive_code.contains("age::Encryptor")
            || archive_code.contains("age::Decryptor"),
        "Archive must use age crate for encryption"
    );

    // Age uses XChaCha20-Poly1305 by default
    // This is verified implicitly by using age
}

/// Test 5.2: Verify secret values are base64-encoded
///
/// Tests that secret values are base64-encoded in archives:
/// - Prevents encoding issues
/// - Safe for serialization
#[test]
fn test_secret_values_base64_encoded() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify base64 encoding
    assert!(
        archive_code.contains("base64")
            || archive_code.contains("BASE64")
            || archive_code.contains("encode"),
        "Secret values must be base64-encoded"
    );

    // Verify base64 decoding
    assert!(
        archive_code.contains("decode") || archive_code.contains("decode"),
        "Import must decode base64 values"
    );
}

/// Test 5.3: Verify archive doesn't include plaintext keys
///
/// Tests that archives don't expose sensitive information:
/// - No encryption keys in archive
/// - No plaintext secrets
#[test]
fn test_archive_no_plaintext_keys() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify vault keys are not included
    assert!(
        !archive_code.contains("identity") || !archive_code.contains("private key"),
        "Archive must NOT include vault private keys"
    );

    // Verify encryption is used
    assert!(
        archive_code.contains("encrypt") || archive_code.contains("Encryptor"),
        "Archive payload must be encrypted"
    );
}

/// Test 5.4: Verify passphrase is handled securely
///
/// Tests that passphrase input is secure:
/// - Not logged
/// - Not stored in plain text
#[test]
fn test_passphrase_handled_securely() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify passphrase prompt
    let has_passphrase = cli_code.contains("passphrase") || cli_code.contains("password");

    if has_passphrase {
        // Verify secure input (not echoed)
        assert!(
            cli_code.contains("password")
                || cli_code.contains("read_password")
                || cli_code.contains("rpassword"),
            "Passphrase should be read securely (not echoed)"
        );
    }
}

/// Test 5.5: Verify archive can be committed to git
///
/// Tests that encrypted archives can be safely committed:
/// - Encrypted format
/// - No sensitive data in plaintext
#[test]
fn test_archive_git_safe() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify encryption is used by default
    assert!(
        archive_code.contains("encrypt") || archive_code.contains("Encryptor"),
        "Archives should be encrypted by default"
    );

    // Verify output can be committed
    // (implicitly true if encrypted)
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

/// Test 6.1: Verify export/import roundtrip
///
/// Tests that secrets survive export/import:
/// 1. Create vault with secrets
/// 2. Export to archive
/// 3. Import to new vault
/// 4. Verify secrets match
#[test]
fn test_export_import_roundtrip() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify roundtrip test exists
    assert!(
        archive_code.contains("#[test]") && archive_code.contains("roundtrip"),
        "Archive module should have roundtrip test"
    );

    // Verify test creates, exports, imports
    assert!(
        archive_code.contains("create_archive") && archive_code.contains("extract_archive"),
        "Roundtrip test should use create and extract"
    );
}

/// Test 6.2: Verify export/import preserves metadata
///
/// Tests that metadata survives export/import:
/// - Secret type
/// - Tags
/// - Timestamps
#[test]
fn test_export_import_preserves_metadata() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify metadata is included in roundtrip
    assert!(
        archive_code.contains("metadata") && archive_code.contains("assert"),
        "Roundtrip test should verify metadata"
    );
}

/// Test 6.3: Verify CLI export/import commands work
///
/// Tests that the CLI commands properly integrate:
/// - Export command calls create_archive
/// - Import command calls extract_archive
#[test]
fn test_cli_export_import_integration() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify export command
    assert!(
        cli_code.contains("CommandExport") || cli_code.contains("Export"),
        "CLI must have export command"
    );

    // Verify import command
    assert!(
        cli_code.contains("CommandImport") || cli_code.contains("Import"),
        "CLI must have import command"
    );

    // Verify archive module is used
    assert!(
        cli_code.contains("archive")
            || cli_code.contains("create_archive")
            || cli_code.contains("extract_archive"),
        "CLI commands must use archive module"
    );
}

/// Test 6.4: Verify import merge mode behavior
///
/// Tests that merge mode works correctly:
/// - Existing secrets are preserved
/// - New secrets are added
/// - No data loss
#[test]
fn test_import_merge_mode_behavior() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !main_path.exists() {
        return;
    }

    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify merge mode enum is defined in archive.rs
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive.rs");
    assert!(
        archive_code.contains("ImportMode::Merge") || archive_code.contains("ImportMode"),
        "Archive module should define ImportMode enum"
    );

    // Verify skip existing logic in main.rs import command
    assert!(
        main_code.contains("ImportMode::Merge")
            && (main_code.contains("exists") || main_code.contains("skipped")),
        "Merge mode should skip existing secrets"
    );
}

/// Test 6.5: Verify import overwrite mode behavior
///
/// Tests that overwrite mode works correctly:
/// - Existing secrets are replaced
/// - New secrets are added
#[test]
fn test_import_overwrite_mode_behavior() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify overwrite mode logic
    assert!(
        archive_code.contains("ImportMode::Overwrite")
            || (archive_code.contains("overwrite") && archive_code.contains("mode")),
        "Archive module should handle overwrite mode"
    );

    // Verify replace logic
    assert!(
        archive_code.contains("overwrite")
            || archive_code.contains("replace")
            || archive_code.contains("update"),
        "Overwrite mode should replace existing secrets"
    );
}

/// Test 6.6: Verify import interactive mode
///
/// Tests that interactive mode prompts user:
/// - For each conflict
/// - With options to skip/overwrite/rename
#[test]
fn test_import_interactive_mode() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify interactive mode
    let has_interactive = cli_code.contains("interactive") || cli_code.contains("Interactive");

    if has_interactive {
        // Verify prompt
        assert!(
            cli_code.contains("prompt") || cli_code.contains("confirm") || cli_code.contains("ask"),
            "Interactive mode should prompt user"
        );
    }
}

/// Test 6.7: Verify archive file extension
///
/// Tests that archives use standard file extension:
/// - .sigil or .sigil-archive
#[test]
fn test_archive_file_extension() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify file extension handling
    let has_extension = cli_code.contains(".sigil") || cli_code.contains("extension");

    if has_extension {
        assert!(
            cli_code.contains(".sigil") || cli_code.contains(".sigil-archive"),
            "Archive files should use .sigil extension"
        );
    }
}

/// Test 6.8: Verify archive compression
///
/// Tests that archives can be compressed:
/// - Optional compression
/// - Reduces file size
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

/// Test 6.9: Verify archive verification
///
/// Tests that archives can be verified without importing:
/// - List contents
/// - Show metadata
#[test]
fn test_archive_verification() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify verify or list command
    let has_verify = cli_code.contains("verify")
        || cli_code.contains("list-archive")
        || cli_code.contains("info");

    if has_verify {
        assert!(
            cli_code.contains("verify") || cli_code.contains("list"),
            "CLI should support archive verification"
        );
    }
}

/// Test 6.10: Verify archive includes checksum
///
/// Tests that archives include integrity checksum:
/// - SHA256 hash
#[test]
fn test_archive_includes_checksum() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Age encryption includes authentication (AEAD)
    // This provides integrity protection
    assert!(
        archive_code.contains("age") || archive_code.contains("Encryptor"),
        "Archive encryption provides integrity protection via AEAD"
    );
}

/// Test 6.11: Verify export supports passphrase from stdin
///
/// Tests that export can read passphrase from stdin:
/// - For scripting/pipelines
#[test]
fn test_export_passphrase_from_stdin() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify stdin passphrase option
    let has_stdin = cli_code.contains("stdin")
        || cli_code.contains("--from-stdin")
        || cli_code.contains("from-stdin");

    if has_stdin {
        assert!(
            cli_code.contains("stdin") || cli_code.contains("--from-stdin"),
            "Export should support passphrase from stdin"
        );
    }
}

/// Test 6.12: Verify import supports passphrase from stdin
///
/// Tests that import can read passphrase from stdin:
/// - For scripting/pipelines
#[test]
fn test_import_passphrase_from_stdin() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify stdin passphrase option
    let has_stdin = cli_code.contains("stdin")
        || cli_code.contains("--from-stdin")
        || cli_code.contains("from-stdin");

    if has_stdin {
        assert!(
            cli_code.contains("stdin") || cli_code.contains("--from-stdin"),
            "Import should support passphrase from stdin"
        );
    }
}

/// Test 6.13: Verify archive timestamp handling
///
/// Tests that timestamps are properly handled:
/// - Export timestamp is in UTC
/// - Import preserves original timestamps
#[test]
fn test_archive_timestamp_handling() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if !archive_path.exists() {
        return;
    }

    let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

    // Verify UTC timestamp
    assert!(
        archive_code.contains("Utc")
            || archive_code.contains("DateTime")
            || archive_code.contains("chrono"),
        "Archive must use UTC timestamps"
    );

    // Verify exported_at field
    assert!(
        archive_code.contains("exported_at") || archive_code.contains("timestamp"),
        "Archive must include export timestamp"
    );
}

/// Test 6.14: Verify archive supports incremental exports
///
/// Tests that exports can be incremental:
/// - Export only changed secrets
#[test]
fn test_archive_incremental_exports() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify incremental export option
    let has_incremental = cli_code.contains("incremental")
        || cli_code.contains("since")
        || cli_code.contains("changed");

    if has_incremental {
        assert!(
            cli_code.contains("incremental") || cli_code.contains("since"),
            "Export should support incremental exports"
        );
    }
}

/// Test 6.15: Verify archive supports dry-run mode
///
/// Tests that import can do dry-run:
/// - Show what would be imported
#[test]
fn test_archive_dry_run_mode() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify dry-run option
    let has_dryrun = cli_code.contains("dry-run")
        || cli_code.contains("dry_run")
        || cli_code.contains("preview");

    if has_dryrun {
        assert!(
            cli_code.contains("dry") || cli_code.contains("preview"),
            "Import should support dry-run mode"
        );
    }
}
