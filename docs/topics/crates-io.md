# Publishing SIGIL to crates.io

## Overview

SIGIL crates are automatically published to crates.io as part of the CI release process. This enables users to install SIGIL via `cargo install sigil-cli`.

## Setup

### 1. Create a crates.io Account

If you don't already have one:
1. Go to https://crates.io
2. Click "Login" and create an account
3. Verify your email address

### 2. Create an API Token

1. Go to https://crates.io/settings/tokens
2. Click "New API Token"
3. Give it a name like "SIGIL CI"
4. Select "Create and update crates" scope (or "Publish new crates" if only publishing)
5. Copy the generated token

### 3. Create the Kubernetes Secret

In the `iad-ci` cluster, create the secret:

```bash
kubectl --kubeconfig=/home/coding/.kube/iad-ci.kubeconfig create secret generic cargo-registry-token \
  --from-literal=token='YOUR_TOKEN_HERE' \
  --namespace=argo-workflows
```

Note: If using the iad-acb kubeconfig path instead:

```bash
kubectl --kubeconfig=/home/coding/.kube/iad-acb.kubeconfig create secret generic cargo-registry-token \
  --from-literal=token='YOUR_TOKEN_HERE' \
  --namespace=argo-workflows
```

### 4. Verify the Secret

```bash
kubectl --kubeconfig=/home/coding/.kube/iad-acb.kubeconfig get secret cargo-registry-token -n argo-workflows
```

## Publishing Process

The CI workflow (`sigil-ci`) will automatically publish crates in dependency order when a new version is tagged:

1. sigil-core (no sigil dependencies)
2. sigil-shamir (no sigil dependencies)
3. sigil-scrub (depends on sigil-core)
4. sigil-sandbox (depends on sigil-core)
5. sigil-signatures (depends on sigil-core)
6. sigil-vault (depends on sigil-core, sigil-shamir)
7. sigil-tui (depends on sigil-core, sigil-vault)
8. sigil-canary (depends on sigil-core, sigil-scrub)
9. sigil-redteam (depends on sigil-core, sigil-scrub)
10. sigil-sdk (depends on sigil-core)
11. sigil-ssh-agent (depends on sigil-core, sigil-vault, sigil-sdk, sigil-tui)
12. sigil-cli (depends on multiple)

Each publish command uses `--no-verified` to skip dependency verification and includes a fallback error message in case the crate was already published.

## Installation from crates.io

Once published, users can install SIGIL via:

```bash
cargo install sigil-cli
```

## Troubleshooting

### "error: no matching package named X found"

This means a dependency crate hasn't been published yet. Ensure:
1. The CI workflow completed successfully
2. All dependencies were published in the correct order
3. Check the CI logs for any publish failures

### "failed to authenticate"

The CARGO_REGISTRY_TOKEN secret is missing or invalid:
1. Check the secret exists: `kubectl get secret cargo-registry-token -n argo-workflows`
2. Verify the token is valid in crates.io settings
3. Ensure the token has the correct scopes

### "crate X already exists"

This is expected behavior - the workflow includes fallback error messages to handle already-published crates gracefully.

## Manual Publishing

If you need to publish crates manually (for example, during testing):

```bash
# From the SIGIL repository root
cargo publish -p sigil-core
# Wait for crates.io to index (10-60 seconds)
cargo publish -p sigil-shamir
# Continue in dependency order...
```

Note: You'll need to run `cargo login` first with your crates.io token.
