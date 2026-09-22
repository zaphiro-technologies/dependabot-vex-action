# Dependabot VEX candidates

This GitHub Action generates reviewed OpenVEX candidates from dismissed
Dependabot alerts. It preserves historical dismissal metadata, derives product
PURLs when configured to do so, updates the repository-owned VEX document, and
emits safe outputs for a labelled candidate pull request.

The action deliberately generates `under_investigation` statements for every
dismissal. A Dependabot dismissal is preserved as review context, but it is not
itself sufficient evidence for a `not_affected` assertion. A reviewer must
update the candidate statement with the product-specific status and
justification before merging.

Dismissal reasons are handled as follows:

- `not_used`, `inaccurate`, and `tolerable_risk` → `under_investigation`, with
  the original reason and comment retained in the ledger and statement notes
- `no_bandwidth` → no VEX statement; the original alert receives a comment
  stating that this is not a security assessment

The action emits safe `pull-request-title` and `pull-request-body` outputs. The
calling workflow uses those outputs with `peter-evans/create-pull-request`.
When `candidate-branch` is omitted, the action reuses an existing open
Dependabot VEX candidate branch, including legacy run-specific branches, and
otherwise uses `automation/dependabot-vex`. This keeps repeated workflow runs
on the same pull request instead of opening duplicates.

## Usage

The calling workflow must check out the repository before invoking the action.
It needs `contents: write`, `issues: write`, and `pull-requests: write`
permissions. The token passed as `github-token` must be a GitHub App
installation token with Dependabot alerts write permission when dismissed alerts
can use `no_bandwidth`; the standard `GITHUB_TOKEN` cannot update those alerts.

```yaml
permissions:
  contents: write
  issues: write
  pull-requests: write

steps:
  - uses: actions/checkout@v7.0.1
    with:
      fetch-depth: 0

  - id: app-token
    uses: actions/create-github-app-token@v3
    with:
      app-id: ${{ secrets.APP_ID }}
      private-key: ${{ secrets.APP_SECRET }}
      permission-contents: write
      permission-issues: write
      permission-pull-requests: write
      permission-vulnerability-alerts: write

  - id: vex
    uses: zaphiro-technologies/dependabot-vex-action@v1
    with:
      github-token: ${{ steps.app-token.outputs.token }}
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
automatically derives PURLs from `go.mod`, `pyproject.toml`, and `package.json`
when those files are present.

## Development

The action is a dependency-free JavaScript action running on Node.js 24. Run the
same checks used by the shared JavaScript workflow with:

```bash
yarn install --immutable
make test
yarn build
```

`make test` runs the unit tests with Node.js coverage enabled and generates
`coverage/lcov.info` for Sonar.

The direct local test commands are also available:

```bash
node --check src/main.js
npm test
```

The tests use a local mocked GitHub API. They do not require GitHub credentials
and do not create pull requests or modify repository state.
