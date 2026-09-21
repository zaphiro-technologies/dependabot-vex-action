# Dependabot VEX candidates

This GitHub Action generates reviewed OpenVEX candidates from dismissed
Dependabot alerts. It preserves historical dismissal metadata, derives product
PURLs when configured to do so, updates the repository-owned VEX document, and
emits safe outputs for a labelled candidate pull request.

The action deliberately generates `under_investigation` statements by default.
Dismissal reasons are mapped as follows:

- `not_used` → `not_affected` / `vulnerable_code_not_present`
- `inaccurate` → `not_affected` / `vulnerable_code_not_in_execute_path`
- `tolerable_risk` → `not_affected` / `inline_mitigations_already_exist`
- `no_bandwidth` → no VEX statement; the original alert receives a comment stating that this is not a security assessment

The action emits safe `pull-request-title` and `pull-request-body` outputs. The
calling workflow uses those outputs with `peter-evans/create-pull-request`.

## Usage

The calling workflow must check out the repository before invoking the action.
It needs `contents: write`, `issues: write`, `pull-requests: write`, and
`vulnerability-alerts: read` permissions.

If dismissed alerts can use `no_bandwidth`, also pass `alerts-token` using a
GitHub App or token with Dependabot alerts write permission. GitHub's
`GITHUB_TOKEN` supports reading Dependabot alerts but not updating them.

```yaml
permissions:
  contents: write
  issues: write
  pull-requests: write
  vulnerability-alerts: read

steps:
  - uses: actions/checkout@v7.0.1
    with:
      fetch-depth: 0

  - id: vex
    uses: zaphiro-technologies/dependabot-vex-action@v1
    with:
      github-token: ${{ github.token }}
      # Required only when a dismissed alert has reason no_bandwidth:
      alerts-token: ${{ secrets.DEPENDABOT_ALERTS_TOKEN }}
      base-branch: main

  - uses: peter-evans/create-pull-request@v7
    if: ${{ steps.vex.outputs.changed == 'true' }}
    with:
      token: ${{ github.token }}
      base: main
      branch: ${{ steps.vex.outputs.candidate-branch }}
      title: ${{ steps.vex.outputs.pull-request-title }}
      body: ${{ steps.vex.outputs.pull-request-body }}
      labels: security
```

When `product-purls` is empty, the action includes the GHCR OCI PURL and
automatically derives PURLs from `go.mod`, `pyproject.toml`, and
`package.json` when those files are present.

## Development

The action is a dependency-free JavaScript action running on Node.js 24. Run
the same checks used by the shared JavaScript workflow with:

```bash
yarn install --immutable
make test
yarn build
```

The direct local test commands are also available:

```bash
node --check src/main.js
npm test
```

The tests use a local mocked GitHub API. They do not require GitHub credentials
and do not create pull requests or modify repository state.
