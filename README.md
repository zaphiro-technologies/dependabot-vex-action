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

The action emits safe `pull-request-title`, `pull-request-body`, and
`vulnerability-ids` outputs. The reusable calling workflow first discovers the
new vulnerability identifiers, then invokes the action once per identifier and
uses those outputs with `peter-evans/create-pull-request`. When
`candidate-branch` is omitted, a candidate uses
`automation/dependabot-vex-<vulnerability-id>-<GITHUB_RUN_ID>`. A rerun of the
same GitHub Actions run therefore targets the same vulnerability branch, while
different vulnerabilities in one run get separate branches and pull requests.
Pass `candidate-branch` when a caller needs a different branch identity.

## Usage

The calling workflow must check out the repository before invoking the action.
The workflow can use read-only `GITHUB_TOKEN` permissions as shown below; the
token passed as `github-token` must be a GitHub App installation token with
contents, issues, pull requests, and vulnerability-alerts write permissions.
The standard `GITHUB_TOKEN` cannot update Dependabot alerts when dismissed
alerts use `no_bandwidth`.

```yaml
permissions:
  contents: read
  pull-requests: read
  vulnerability-alerts: read

jobs:
  discover:
    runs-on: ubuntu-latest
    outputs:
      vulnerability-ids: ${{ steps.vex.outputs.vulnerability-ids }}
    steps:
      - uses: actions/checkout@v7.0.1
        with:
          fetch-depth: 0
          ref: main

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

  create-vex-pr:
    needs: discover
    if: ${{ needs.discover.outputs.vulnerability-ids != '[]' }}
    strategy:
      fail-fast: false
      matrix:
        vulnerability-id: ${{ fromJSON(needs.discover.outputs.vulnerability-ids) }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.1
        with:
          fetch-depth: 0
          ref: main

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
          vulnerability-id: ${{ matrix.vulnerability-id }}

      - uses: peter-evans/create-pull-request@v7
        if: ${{ steps.vex.outputs.changed == 'true' }}
        with:
          token: ${{ steps.app-token.outputs.token }}
          base: main
          branch: ${{ steps.vex.outputs.candidate-branch }}
          delete-branch: true
          commit-message: "security: update Dependabot VEX statements"
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
