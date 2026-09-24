# Dependabot VEX candidates

This GitHub Action generates reviewed OpenVEX candidates from dismissed
Dependabot alerts. It preserves historical dismissal metadata, derives product
PURLs when configured to do so, updates the repository-owned VEX document, and
emits safe outputs for a labelled candidate pull request.

The action maps Dependabot dismissal reasons to OpenVEX statuses and preserves
the original reason and comment as review context. The mappings are product
policy defaults and should be changed if the product context does not support
the assertion. Each statement keeps the configured product scopes with the
dependency as a subcomponent and also lists the exact dependency PURL as a
direct product, so filesystem dependency scans and image scans can both match
the statement.

Dismissal reasons are handled as follows:

- `not_used` → `not_affected` / `vulnerable_code_not_present`
- `inaccurate` → `not_affected` / `vulnerable_code_not_in_execute_path`
- `tolerable_risk` → `not_affected` / `inline_mitigations_already_exist`
- Other dismissal reasons → `under_investigation`, with the original reason and
  comment retained in the ledger and statement notes
- `no_bandwidth` → no VEX statement; the original alert receives a comment
  stating that this is not a security assessment

The action emits safe `pull-request-title` and `pull-request-body` outputs. The
calling workflow uses those outputs with `peter-evans/create-pull-request`. When
`candidate-branch` is omitted, the action uses the historical
`automation/dependabot-vex` branch for the default VEX path. For other VEX paths
it uses `automation/dependabot-vex-<stable-id>`, where the ID is derived from
the repository, base branch, and VEX path. Separate workflow runs targeting the
same VEX therefore update the same branch and open pull request, while different
VEX paths get different branches. Pass `candidate-branch` when a caller needs a
different stable branch identity.

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
when those files are present. Dependency versions are resolved from the
checked-out `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`,
`pnpm-lock.yaml`, `go.mod`/`go.sum`, or `poetry.lock` when GitHub's alert
payload does not include the installed version.

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
