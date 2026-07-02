# mdBook Build Artifacts Removal

**Date**: 2026-07-02  
**Decision**: Remove mdBook build artifacts from git  
**Status**: ✅ Implemented

## Background

Phase 10.8 of the implementation plan specified a documentation site built with mdBook. The `docs/book/` directory contained 82 HTML files (build output) that were committed to git. This created several problems:

1. **Drift**: Committed HTML files silently drift from markdown sources when docs are updated
2. **No CI rebuild**: No CI step rebuilds the book (CI runs on Argo Workflows, not GitHub Actions)
3. **GitHub Pages unavailable**: GitHub Pages is not enabled on the repository (API returns 404)
4. **Best practice violation**: Build artifacts should not be committed to version control

## Decision

**Chose option (b)**: Remove built output from git, add `docs/book/` to `.gitignore`, and document the build process.

### Rationale

1. **SIGIL uses Argo Workflows for CI**, not GitHub Actions — GitHub Pages integration would require additional infrastructure
2. **Build artifacts in version control** is an anti-pattern — causes merge conflicts and drift
3. **Local rebuilding is simple** — `mdbook build` in `docs/` directory
4. **Aligns with project philosophy** — explicit, local control over build processes

### Implementation

1. Added `docs/book/` to `.gitignore`
2. Removed 82 files from git tracking with `git rm -r --cached docs/book/`
3. Added documentation build instructions to `CONTRIBUTING.md`:

```bash
# Install mdBook (if not already installed)
cargo install mdbook

# Build the documentation
cd docs
mdbook build

# Serve locally for preview (auto-reloads on changes)
mdbook serve
```

### Future Considerations

If GitHub Pages or similar becomes necessary for public documentation hosting:
- Add mdBook build step to Argo Workflows (`sigil-ci` WorkflowTemplate)
- Publish built artifacts to GitHub Pages via `gh` CLI in CI
- OR host on alternative static site hosting (Vercel, Netlify, Cloudflare Pages)

For now, local building is sufficient since:
- Documentation is primarily for developers running SIGIL locally
- All documentation source files (`docs/*.md`) remain in git
- README.md contains quickstart and links to full documentation

## References

- Phase 10.8: Documentation Site Structure (`docs/plan/plan.md`)
- Issue: `docs/book/` has no publish target, drifts from sources
