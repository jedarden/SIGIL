#!/bin/bash
# SIGIL Demo Script
# This demonstrates SIGIL's core workflow using the quickstart command

set -e

# Set up demo environment
export DEMO_HOME="/tmp/sigil-demo"
rm -rf "$DEMO_HOME"
mkdir -p "$DEMO_HOME"
export HOME="$DEMO_HOME"
export PATH="/home/coding/SIGIL/target/release:$PATH"

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  SIGIL: Secret Management for AI Coding Agents                       ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# Method 1: Using quickstart (recommended one-command setup)
echo "Method 1: One-Command Setup (Recommended)"
echo "$ sigil quickstart --non-interactive --skip-secret"
echo ""

# Run quickstart in non-interactive mode
sigil quickstart --non-interactive --skip-secret 2>&1 | head -30

echo ""
echo "✅ Vault initialized with age encryption"
echo ""

# Step 2: Add a secret
echo "Step 2: Add a secret (demo API key)"
echo "$ sigil add kalshi/api_key"
(echo "sk-live-abc123xyz789demo") | sigil add kalshi/api_key --from-stdin --non-interactive >/dev/null 2>&1
echo "✅ Secret encrypted and stored"
echo ""

# Step 3: List secrets
echo "Step 3: List secrets in vault"
echo "$ sigil list"
sigil list 2>/dev/null
echo ""

# Step 4: Show secret metadata
echo "Step 4: View secret metadata (value is encrypted)"
echo "$ cat ~/.sigil/vault/kalshi/api_key.age | head -1"
cat ~/.sigil/vault/kalshi/api_key.age | head -1
echo "✅ Secret value never stored in plaintext"
echo ""

# Step 5: Show placeholder syntax
echo "Step 5: Use placeholders in commands"
echo "$ sigil exec 'curl -H \"Authorization: Bearer {{secret:kalshi/api_key}}\" ...'"
echo ""
echo "Placeholder syntax: {{secret:path}}"
echo "  → Resolved at execution time"
echo "  → Scrubbed from output"
echo "  → Never logged or echoed"
echo ""

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  ✅ SIGIL protects your secrets at every layer                       ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "🔒 At rest: age-encrypted vault (~/.sigil/vault/)"
echo "🪝 In use: {{secret:path}} placeholders"
echo "🧹 In output: exact-match scrubbing (7 encodings)"
echo "🛡️ On disk: append-only audit log"
echo ""
echo "Get started:"
echo "  • sigil quickstart        # One-command setup"
echo "  • sigil setup claude-code  # Install agent hooks"
echo "  • sigil help              # Full documentation"
echo "  • https://github.com/jedarden/sigil"
