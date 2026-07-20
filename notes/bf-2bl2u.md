# bf-2bl2u — bwrap availability check audit (phase4_e2e_redteam_test.rs)

**Task:** Identify which test functions in
`crates/sigil-integration-tests/tests/phase4_e2e_redteam_test.rs` require the
`is_bwrap_available()` check but are missing it.

## Result: NO gaps — every bwrap-dependent test is already gated

After reading the full file (961 lines) and cross-referencing usage patterns,
**no test function requires the `is_bwrap_available()` check and lacks it.**
Zero findings, zero false positives.

## Why there are no gaps

The file is architected around a single chokepoint:

- `is_bwrap_available()` (lines 32–58) is the gatekeeper. It is called in
  exactly **one** place: the first line of `build_bwrap_command()` (line 69),
  which returns `None` when bwrap is unavailable.
- `Command::new("bwrap")` appears **only** inside the two helpers
  (line 34 in the checker, line 73 in the builder). It is never invoked
  directly inside any `#[test]` body.
- Every test that depends on bwrap obtains its `Command` via
  `build_bwrap_command(...)` and handles the `None` arm with `return`
  (i.e. skip). So the availability guard is inherited transitively by all 19
  bwrap tests.

Because the guard lives in the builder, adding a *direct* `is_bwrap_available()`
call to any of these tests would be redundant — it would re-check something the
builder already checks a few lines later. That would be a cosmetic change, not
a correctness fix, and would violate the task's "no false positives" criterion.

## Full cross-reference

### 19 tests that use bwrap — all correctly gated via `build_bwrap_command`

| # | Test function | Line | `None => return` arm |
|---|---------------|------|----------------------|
| 4.1.1 | `test_e2e_pid_namespace_blocks_proc1_environ` | 187 | yes (190) |
| 4.1.2 | `test_e2e_pid1_is_not_host_init` | 219 | yes (222) |
| 4.1.3 | `test_e2e_only_sandbox_processes_visible` | 249 | yes (252) |
| 4.2.1 | `test_e2e_aws_credentials_overlayed_with_dev_null` | 292 | yes (307) |
| 4.2.2 | `test_e2e_ssh_key_overlayed_with_dev_null` | 341 | yes (354) |
| 4.2.3 | `test_e2e_env_file_overlayed_with_dev_null` | 379 | yes (390) |
| 4.3.1 | `test_e2e_network_namespace_blocks_connections` | 422 | yes (427) |
| 4.3.2 | `test_e2e_no_network_interfaces` | 450 | yes (453) |
| 4.3.3 | `test_e2e_dns_resolution_fails` | 478 | yes (482) |
| 4.4.1 | `test_e2e_ptrace_blocked_by_seccomp` | 514 | yes (519) |
| 4.4.2 | `test_e2e_mount_blocked_by_seccomp` | 544 | yes (548) |
| 4.5.1 | `test_e2e_path_cannot_be_modified` | 580 | yes (585) |
| 4.5.2 | `test_e2e_ld_preload_removed` | 611 | yes (615) |
| 4.5.3 | `test_e2e_ld_library_path_removed` | 636 | yes (639) |
| 4.5.4 | `test_e2e_shell_removed` | 659 | yes (662) |
| 4.6.1 | `test_e2e_tmpfs_secrets_cleaned_up` | 689 | yes (702) |
| 4.7.1 | `test_e2e_sandbox_overhead_less_than_30ms` | 776 | yes (781) |
| 4.7.2 | `test_e2e_sandbox_overhead_with_cached_secrets` | 813 | yes (824) |
| 4.8.1 | `test_e2e_real_workflow` | 855 | yes (870) |

### 3 tests that do NOT use bwrap — correctly do NOT need the check

| Test function | Line | Why it doesn't need bwrap |
|---------------|------|---------------------------|
| `test_e2e_secrets_zeroized_before_deletion` | 732 | Pure `std::fs` write/read/zeroize/remove on a temp dir. No sandbox. |
| `test_e2e_all_sandbox_providers` | 904 | Exercises `sigil_sandbox` library types (`BubblewrapSandbox::new()`, etc.) which carry their own `is_available()` capability checks. Does not spawn the bwrap binary. |
| `test_non_linux_placeholder` | 956 | `#[cfg(not(target_os = "linux"))]` compile-only stub; prints a message. No bwrap. |

## Cosmetic-only observation (not a defect)

Five of the 19 bwrap tests annotate the `None => return` arm with the comment
`// Skip test if bwrap not available` (lines 313, 360, 396, 704, 872); the other
14 omit the comment. The behaviour is identical either way — the guard fires
regardless of whether the comment is present. Adding comments for consistency
would be a style nit, not a correctness fix, and is out of scope for this task.

## Conclusion

No code changes were warranted. The availability-check design in this file is
sound: one guard in `build_bwrap_command()`, inherited by all 19 bwrap tests via
their `match ... None => return` arms, and correctly absent from the 3 tests that
do not touch bwrap.
