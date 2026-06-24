# Helm Chart Layout

This directory contains Helm charts for the MetrANOVA stack.

Published Helm repository:

- `https://metranova.github.io/stack`

Quick start:

```bash
helm repo add metranova https://metranova.github.io/stack
helm repo update
helm search repo metranova --versions
```

- `charts/`: local component chart sources (subcharts used by the umbrella chart)
- `metranova/`: umbrella chart that composes the stack
- `metranova/charts/`: generated dependency tarballs created by `helm dependency build`/`helm dependency update`

For umbrella chart installation and upgrade instructions, see:

- [metranova/README.md](metranova/README.md)

## Chart Versioning

MetrANOVA Helm charts follow a semantic versioning strategy with automated publishing via GitHub Actions.

### Version Branches

Version branches follow the pattern `X.Y.Z` (e.g., `1.0.0`, `2.1.3`). When changes are pushed to a version branch:

1. **Version Validation**: The workflow ensures all `Chart.yaml` files have versions matching the branch name
2. **Pre-Release Tagging**: Charts are published with a `-build.N` suffix where `N` is the GitHub run number (e.g., `1.0.0-build.92`)
3. **Dependency Alignment**: The umbrella chart's local dependencies are updated to reference the same pre-release versions
4. **Automatic Publishing**: Charts are packaged and published to GitHub Releases and the Helm repository index

**Important Note:** When a new version branch is created, if Chart.yaml versions don't match the branch name, the workflow will automatically update and commit the versions. However, this commit will **not** trigger a new workflow run (GitHub security feature to prevent infinite loops). The first actual build will occur on the next commit to the branch, which is acceptable since there are no real changes to build until then anyway.

**Example:**
- Branch: `1.0.0`
- Published versions: `1.0.0-build.92` (all component charts and umbrella chart)
- Umbrella dependencies: Reference `1.0.0-build.92` for local components, unchanged for external dependencies

### Main Branch

Changes pushed to `main` publish charts with their current versions as-is, marked as "latest" releases. No version validation or mutation occurs.

### Other Branches

No charts are built or published from non-version, non-main branches.

### Manual Version Updates

To create a new stable release:

1. Create a version branch: `git checkout -b 1.0.0`
2. Push the branch: `git push -u origin 1.0.0`
3. The workflow validates and updates Chart.yaml versions if needed
4. Pre-release builds are published automatically for testing
5. When ready for stable release, merge to `main` with updated Chart.yaml versions
6. The main branch workflow publishes the stable release

### Chart Dependencies

The umbrella chart (`metranova`) references component charts via:

- **Local dependencies**: `file://../charts/` - automatically versioned to match pre-release tags
- **External dependencies**: Remote repository URLs (e.g., Grafana) - versions remain unchanged
