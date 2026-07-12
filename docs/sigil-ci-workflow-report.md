# SIGIL CI Workflow Execution Report

**Workflow Name**: sigil-ci-manual-4qfvb
**Workflow Template**: sigil-ci
**Execution Date**: 2026-07-12

## Final Status

- **Phase**: `Failed`
- **Exit Code**: 101
- **Error Message**: "main: Error (exit code 101)"

## Execution Timeline

- **Started**: 2026-07-12T04:53:15Z
- **Finished**: 2026-07-12T05:25:12Z
- **Total Duration**: 31 minutes 57 seconds (1917 seconds)

## Resource Usage

- **CPU Duration**: 127 (seconds of CPU time)
- **Memory Duration**: 2493 (GiB-seconds of memory)
- **Container Resources**: 
  - CPU: 1000m request, 1500m limit
  - Memory: 2Gi request, 3Gi limit

## Workflow Details

### Template Configuration
- **Active Deadline**: 3600 seconds (1 hour)
- **Pod GC Strategy**: OnPodCompletion
- **Node Selector**: ch.vs1.large-iad (Rackspace Spot)
- **Service Account**: argo-workflow

### Execution Steps
The workflow attempted to execute the following CI pipeline:

1. **System Dependencies Setup**:
   - Install git, curl, build-essential, pkg-config, libssl-dev
   - Install libfuse3-dev, fuse3, python3, nodejs
   - Install GitHub CLI (gh)

2. **Rust Toolchain Installation**:
   - Install Rust stable via rustup
   - Add clippy and rustfmt components

3. **Repository Clone**:
   - Clone from trusted hardcoded source: `https://github.com/jedarden/SIGIL.git`
   - Depth: 1 (shallow clone for speed)

4. **CI Checks** (these likely failed):
   - `cargo fmt --all -- --check`
   - `cargo check --all-targets`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo test`

5. **Release Build** (would have been skipped due to failure):
   - Build all 10 release binaries
   - Create GitHub release with binaries

## Failure Analysis

**Exit Code 101** typically indicates a failure in one of the CI check steps:

1. **Formatting Check** (`cargo fmt --check`): Code formatting issues
2. **Compilation Check** (`cargo check`): Compilation errors
3. **Linting** (`cargo clippy -- -D warnings`): Lint warnings that fail the build
4. **Tests** (`cargo test`): Test failures

## Next Steps for Investigation

To determine the exact cause of failure:

1. **Check Recent Commits**: Review the most recent commits to the main branch
2. **Run Locally**: Execute the failing CI checks locally:
   ```bash
   cargo fmt --all -- --check
   cargo check --all-targets  
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```
3. **Review CI Logs**: Access the Argo Workflows UI for detailed logs
4. **Check Dependencies**: Verify no breaking changes in dependencies

## Recent Workflow History

Other recent sigil-ci workflows have also failed with the same exit code 101:
- sigil-ci-manual-qx5cd: Failed (117m)
- sigil-ci-debug-cvf4s: Failed (106m)
- sigil-ci-manual-4w75q: Failed (96m)
- sigil-ci-manual-mk7qr: Failed (72m)
- sigil-ci-monitor-rls8z: Failed (65m)
- sigil-ci-manual-4qfvb: Failed (38m)

This pattern suggests a persistent issue in the codebase that needs to be addressed.

## Workflow Template

The workflow uses the `sigil-ci` WorkflowTemplate which includes:
- Automatic execution on push to main branch
- GitHub release creation for versioned releases
- Comprehensive CI checks (fmt, check, clippy, test)
- Multi-binary release build (10 binaries total)

---
*Report Generated: 2026-07-12*  
*Argo Workflows Cluster: iad-ci*  
*Workflow Template: sigil-ci*