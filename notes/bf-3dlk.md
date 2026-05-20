# Bead bf-3dlk: TUI Missing Modes Investigation

## Task Description
Original bead requested implementing missing Import/Export, Breach Alerts, Backend Sync, and Secret Rotation modes for the SIGIL TUI.

## Finding
**All requested modes are already fully implemented.**

The bead description stated "Mode enum in sigil-tui/src/main.rs only has Browse,Detail,Help,Add,Edit,Delete,Audit,Sessions" but this was outdated information.

## Current Implementation (Verified 2026-05-20)

### Mode Enum (line 530)
```rust
enum Mode {
    Browse, Detail, Help, Add, Edit, Delete, Audit, Sessions,
    ImportExport,    // ✓ Present
    BackendSync,     // ✓ Present
    BreachAlerts,    // ✓ Present
    SecretRotation,  // ✓ Present
}
```

### 1. Import/Export Mode
- **State**: `ImportExportState` (line 133) with `ImportMode`, `ImportExportOp`, `ImportExportStep`, `ConflictItem`
- **Draw**: `draw_import_export_view` (line 2481)
- **Handlers**: `enter_import_export_mode`, `exit_import_export_mode` (lines 1233-1256)
- **Key binding**: `i` (Import), `x` (Export) from Browse mode (line 1771-1776)

### 2. Backend Sync Mode
- **State**: `BackendSyncState` (line 213) with `BackendType`, `SyncStatus`, `SyncStep`
- **Draw**: `draw_backend_sync_view` (line 2628)
- **Handlers**: `enter_backend_sync_mode`, `exit_backend_sync_mode` (lines 1259-1277)
- **Key binding**: `y` from Browse mode (line 1777-1779)
- **Backends**: HashiCorp Vault, 1Password, Bitwarden, AWS Secrets Manager

### 3. Breach Alerts Mode
- **State**: `BreachAlert` (line 275) with `BreachSeverity`, `AlertStatus`
- **Draw**: `draw_breach_alerts_view` (line 2751)
- **Handlers**: `enter_breach_alerts_mode`, `exit_breach_alerts_mode`, `breach_select_up/down`, `acknowledge_breach_alert`, `resolve_breach_alert` (lines 1280-1381)
- **Key binding**: `b` from Browse mode (line 1780-1782)
- **Loads from**: Audit log `BreachDetected` entries

### 4. Secret Rotation Mode
- **State**: `RotationState` (line 318) with `RotationStep`
- **Draw**: `draw_secret_rotation_view` (line 2833)
- **Handlers**: `enter_rotation_mode`, `exit_rotation_mode` (lines 1384-1406)
- **Key binding**: `o` from Browse mode (line 1783-1785)

### Help Documentation
All four modes are documented in `draw_help_view` (lines 2219-2233):
- Import/Export: `i`/`x` keys
- Backend Sync: `y` key
- Breach Alerts: `b` key with `a`/`r` actions
- Secret Rotation: `o` key

## Conclusion
No code changes were needed. The bead description was based on outdated information about the TUI implementation. All Phase 6.1 requirements for these modes are complete.
