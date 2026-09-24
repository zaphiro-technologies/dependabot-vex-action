/*
 * Copyright 2026 Zaphiro Technologies
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import test from 'node:test';

const action = path.resolve('src/main.js');

function alert(number, reason, cve, packageName = 'golang.org/x/text') {
  return {
    number,
    state: 'dismissed',
    html_url: `https://github.com/zaphiro-technologies/test/security/dependabot/${number}`,
    dependency: {
      package: { ecosystem: 'go', name: packageName },
      version: 'v0.3.2',
    },
    security_advisory: {
      cve_id: cve,
      ghsa_id: `GHSA-test-${number}`,
      identifiers: [
        { type: 'CVE', value: cve },
        { type: 'GHSA', value: `GHSA-test-${number}` },
      ],
    },
    security_vulnerability: {
      package: { ecosystem: 'go', name: packageName },
      vulnerable_version_range: '< 0.3.3',
      first_patched_version: { identifier: 'v0.3.3' },
    },
    dismissed_reason: reason,
    dismissed_comment: `Review for alert ${number}`,
    dismissed_by: { login: 'tester' },
    dismissed_at: '2026-09-21T00:00:00Z',
  };
}

async function runAction(alerts, {
  token = 'read-token',
  files = {},
  imageName,
  productPurls = 'pkg:oci/test?repository_url=ghcr.io%2Fzaphiro-technologies%2Ftest',
  githubOutput = true,
  nextAlerts,
  runId = '12345',
  vexPath = '.vex/dependabot.openvex.json',
  serverError,
} = {}) {
  const workspace = await mkdtemp(path.join(tmpdir(), 'dependabot-vex-action-'));
  const output = path.join(workspace, 'github-output');
  const requests = [];
  for (const [file, contents] of Object.entries(files)) {
    const target = path.join(workspace, file);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, typeof contents === 'string' ? contents : JSON.stringify(contents));
  }
  const server = http.createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    requests.push({
      method: request.method,
      url: request.url,
      body,
      authorization: request.headers.authorization,
    });
    if (request.method === 'GET' && request.url?.startsWith('/repos/zaphiro-technologies/test/dependabot/alerts')) {
      if (serverError) {
        response.statusCode = serverError.status;
        response.end(serverError.body);
        return;
      }
      response.setHeader('content-type', 'application/json');
      if (nextAlerts && !request.url.includes('page=2')) {
        response.setHeader(
          'link',
          '<http://127.0.0.1:' + server.address().port + '/repos/zaphiro-technologies/test/dependabot/alerts?page=2>; rel="next"',
        );
      }
      response.end(JSON.stringify(request.url.includes('page=2') ? nextAlerts : alerts));
      return;
    }
    if (request.method === 'PATCH' && request.url?.includes('/dependabot/alerts/')) {
      response.setHeader('content-type', 'application/json');
      response.end('{}');
      return;
    }
    response.statusCode = 404;
    response.end('{}');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;

  const result = await new Promise(resolve => {
    const child = spawn(process.execPath, [action], {
      cwd: workspace,
      env: {
        ...process.env,
        GITHUB_API_URL: `http://127.0.0.1:${port}`,
        GITHUB_OUTPUT: output,
        GITHUB_REPOSITORY: 'zaphiro-technologies/test',
        GITHUB_REPOSITORY_OWNER: 'zaphiro-technologies',
        GITHUB_RUN_ID: runId,
        GITHUB_SERVER_URL: 'https://github.com',
        GITHUB_WORKSPACE: workspace,
        INPUT_BASE_BRANCH: 'main',
        INPUT_DISMISSAL_LEDGER_PATH: '.vex/dependabot-dismissals.json',
        'INPUT_GITHUB-TOKEN': token || '',
        INPUT_PRODUCT_PURLS: productPurls,
        INPUT_VEX_PATH: vexPath,
        ...(imageName === undefined ? {} : { INPUT_IMAGE_NAME: imageName }),
        ...(githubOutput ? {} : { GITHUB_OUTPUT: '' }),
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('close', code => resolve({ code, stdout, stderr }));
  });

  const vexFile = path.join(workspace, '.vex/dependabot.openvex.json');
  const ledgerFile = path.join(workspace, '.vex/dependabot-dismissals.json');
  const outputText = await readFile(output, 'utf8').catch(() => '');
  const vex = await readFile(vexFile, 'utf8').then(JSON.parse).catch(() => null);
  const ledger = await readFile(ledgerFile, 'utf8').then(JSON.parse).catch(() => null);
  await new Promise(resolve => server.close(resolve));
  await rm(workspace, { recursive: true, force: true });
  return { ...result, requests, output: outputText, vex, ledger };
}

function outputValue(text, name) {
  const lines = text.split('\n');
  const prefix = `${name}<<`;
  const start = lines.findIndex(line => line.startsWith(prefix));
  if (start === -1) return '';
  const delimiter = lines[start].slice(prefix.length);
  const end = lines.indexOf(delimiter, start + 1);
  return lines.slice(start + 1, end === -1 ? lines.length : end).join('\n');
}

test('maps dismissal reasons to the original VEX policy and links the alerts', async () => {
  const result = await runAction([
    alert(1, 'not_used', 'CVE-2022-32149'),
    alert(2, 'inaccurate', 'CVE-2021-38561'),
    alert(3, 'tolerable_risk', 'CVE-2020-14040'),
  ]);

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.vex.statements.length, 3);
  assert.deepEqual(
    result.vex.statements.map(statement => [statement.status, statement.justification]),
    [
      ['not_affected', 'vulnerable_code_not_present'],
      ['not_affected', 'vulnerable_code_not_in_execute_path'],
      ['not_affected', 'inline_mitigations_already_exist'],
    ],
  );
  assert.match(outputValue(result.output, 'pull-request-title'), /Add VEX statements for/);
  assert.match(outputValue(result.output, 'pull-request-body'), /security\/dependabot\/1/);
  assert.match(outputValue(result.output, 'pull-request-body'), /security\/dependabot\/3/);
});

test('uses the requested singular PR title for one CVE', async () => {
  const result = await runAction([alert(4, 'not_used', 'CVE-2022-32149', 'example.org/widget')]);

  assert.equal(result.code, 0, result.stderr);
  assert.equal(
    outputValue(result.output, 'pull-request-title'),
    'Add VEX statement for CVE-2022-32149 (example.org/widget)',
  );
  assert.match(outputValue(result.output, 'pull-request-body'), /security\/dependabot\/4/);
});

test('uses github-token when reading Dependabot alerts', async () => {
  const result = await runAction([alert(6, 'not_used', 'CVE-2022-32149')], {
    token: 'app-token',
  });

  assert.equal(result.code, 0, result.stderr);
  const getAlerts = result.requests.find(request => request.method === 'GET');
  assert.equal(getAlerts?.authorization, 'Bearer app-token');
});

test('uses a stable VEX identity as the default candidate branch', async () => {
  const firstRun = await runAction([alert(13, 'not_used', 'CVE-2022-32149')], {
    runId: '12345',
  });
  const laterRun = await runAction([alert(13, 'not_used', 'CVE-2022-32149')], {
    runId: '67890',
  });

  assert.equal(firstRun.code, 0, firstRun.stderr);
  assert.equal(laterRun.code, 0, laterRun.stderr);
  const firstBranch = outputValue(firstRun.output, 'candidate-branch');
  const laterBranch = outputValue(laterRun.output, 'candidate-branch');
  assert.equal(firstBranch, 'automation/dependabot-vex');
  assert.equal(firstBranch, laterBranch);
});

test('uses a different stable branch for a different VEX path', async () => {
  const result = await runAction([alert(14, 'not_used', 'CVE-2022-32149')], {
    vexPath: '.vex/other.openvex.json',
  });

  assert.equal(result.code, 0, result.stderr);
  assert.match(
    outputValue(result.output, 'candidate-branch'),
    /^automation\/dependabot-vex-[0-9a-f]{12}$/,
  );
});

test('skips no_bandwidth and annotates the original alert', async () => {
  const result = await runAction([alert(5, 'no_bandwidth', 'CVE-2022-32149')], {
    token: 'app-token',
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.vex, null);
  assert.match(outputValue(result.output, 'skipped-alerts'), /5/);
  const patch = result.requests.find(request => request.method === 'PATCH');
  assert.ok(patch);
  assert.match(JSON.parse(patch.body).dismissed_comment, /not a security assessment/);
});

test('paginates alerts and derives product PURLs from supported project files', async () => {
  const result = await runAction([alert(7, 'not_used', 'CVE-2022-32149')], {
    nextAlerts: [alert(8, 'inaccurate', 'CVE-2021-38561')],
    productPurls: '',
    files: {
      'go.mod': 'module example.com/service\n',
      'pyproject.toml': '[project]\nname = "example_service"\n\n[tool.poetry]\nname = "poetry-service"\n',
      'package.json': JSON.stringify({ name: '@scope/example-service' }),
    },
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.vex.statements.length, 2);
  assert.equal(
    result.requests.filter(request => request.method === 'GET' && request.url.includes('/dependabot/alerts')).length,
    2,
  );
  assert.equal(result.vex.statements[0].products.length, 5);
  assert.equal(
    result.vex.statements[0].products[0].subcomponents[0]['@id'],
    'pkg:golang/golang.org/x/text@v0.3.2',
  );
  assert.equal(
    result.vex.statements[0].products.at(-1)['@id'],
    'pkg:golang/golang.org/x/text@v0.3.2',
  );
});

test('promotes an npm dependency PURL to a direct VEX product', async () => {
  const current = alert(14, 'not_used', 'CVE-2026-84375', 'js-yaml');
  current.dependency.package.ecosystem = 'npm';
  delete current.dependency.version;
  current.dependency.manifest_path = 'package-lock.json';
  current.security_vulnerability.package.ecosystem = 'npm';
  const result = await runAction([current], {
    files: {
      'package-lock.json': {
        lockfileVersion: 3,
        packages: {
          '': { name: 'documentation-test', version: '1.0.0' },
          'node_modules/js-yaml': { version: '4.3.1' },
        },
      },
    },
  });

  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(result.vex.statements[0].products.at(-1), {
    '@id': 'pkg:npm/js-yaml@4.3.1',
  });
});

test('resolves a Go dependency version from go.mod when the alert omits it', async () => {
  const current = alert(15, 'not_used', 'CVE-2026-00015');
  delete current.dependency.version;
  current.dependency.manifest_path = 'go.mod';
  const result = await runAction([current], {
    files: { 'go.mod': 'module example.org/app\n\nrequire golang.org/x/text v0.3.2\n' },
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.vex.statements[0].products.at(-1)['@id'], 'pkg:golang/golang.org/x/text@v0.3.2');
});

test('falls back to go.sum when go.mod does not contain the dependency', async () => {
  const current = alert(17, 'not_used', 'CVE-2026-00017');
  delete current.dependency.version;
  current.dependency.manifest_path = 'go.mod';
  const result = await runAction([current], {
    files: {
      'go.mod': 'module example.org/app\n',
      'go.sum': 'golang.org/x/text v0.3.2 h1:checksum\ngolang.org/x/text v0.3.2/go.mod h1:checksum\n',
    },
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.vex.statements[0].products.at(-1)['@id'], 'pkg:golang/golang.org/x/text@v0.3.2');
});

test('resolves a Poetry dependency version from poetry.lock when the alert omits it', async () => {
  const current = alert(16, 'not_used', 'CVE-2026-00016', 'PyYAML');
  current.dependency.package.ecosystem = 'pip';
  delete current.dependency.version;
  current.dependency.manifest_path = 'pyproject.toml';
  current.security_vulnerability.package.ecosystem = 'pip';
  const result = await runAction([current], {
    files: {
      'poetry.lock': '[metadata]\nlock-version = "2.0"\n\n[[package]]\nname = "pyyaml"\nversion = "6.0.2"\n',
    },
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.vex.statements[0].products.at(-1)['@id'], 'pkg:pypi/PyYAML@6.0.2');
});

test('updates retained statements and reports a scope-only change', async () => {
  const existing = {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    version: 1,
    statements: [{
      status_notes: 'dependabot-alert:https://github.com/zaphiro-technologies/test/security/dependabot/9',
      products: [{ '@id': 'pkg:oci/old', subcomponents: [] }],
    }],
  };
  const current = alert(9, 'not_used', 'CVE-2022-32149');
  const result = await runAction([current], {
    files: { '.vex/dependabot.openvex.json': existing },
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.vex.statements.length, 1);
  assert.match(outputValue(result.output, 'pull-request-title'), /Update VEX product scope/);
  assert.equal(result.vex.statements[0].products[0]['@id'], 'pkg:oci/test?repository_url=ghcr.io%2Fzaphiro-technologies%2Ftest');
});

test('updates an existing generated under-investigation statement to the mapped status', async () => {
  const current = alert(13, 'not_used', 'CVE-2022-32149');
  const result = await runAction([current], {
    files: {
      '.vex/dependabot.openvex.json': {
        '@context': 'https://openvex.dev/ns/v0.2.0',
        version: 1,
        statements: [{
          status_notes: `dependabot-alert:${current.html_url}`,
          products: [{ '@id': 'pkg:oci/test', subcomponents: [] }],
          status: 'under_investigation',
        }],
      },
    },
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.vex.statements[0].status, 'not_affected');
  assert.equal(result.vex.statements[0].justification, 'vulnerable_code_not_present');
});

test('handles an empty alert list without creating a VEX document', async () => {
  const result = await runAction([], { githubOutput: false });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.vex, null);
  assert.equal(result.output, '');
});

test('does not create an empty historical ledger when there are no alerts', async () => {
  const result = await runAction([]);

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.vex, null);
  assert.equal(result.ledger, null);
  assert.equal(outputValue(result.output, 'changed'), 'false');
  assert.equal(outputValue(result.output, 'vex-changed'), 'false');
});

test('reports a ledger-only change when an existing VEX statement is unchanged', async () => {
  const current = alert(11, 'not_used', 'CVE-2022-32149');
  const product = 'pkg:oci/test?repository_url=ghcr.io%2Fzaphiro-technologies%2Ftest';
  const result = await runAction([current], {
    files: {
      '.vex/dependabot.openvex.json': {
        '@context': 'https://openvex.dev/ns/v0.2.0',
        version: 1,
        statements: [{
          status_notes: `dependabot-alert:${current.html_url}`,
          products: [{
            '@id': product,
            subcomponents: [{ '@id': 'pkg:golang/golang.org/x/text@v0.3.2' }],
          }, { '@id': 'pkg:golang/golang.org/x/text@v0.3.2' }],
          status: 'not_affected',
          justification: 'vulnerable_code_not_present',
        }],
      },
    },
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(outputValue(result.output, 'changed'), 'true');
  assert.equal(outputValue(result.output, 'vex-changed'), 'false');
  assert.equal(result.ledger.alerts.length, 1);
});

test('fails when a dismissal record has no package identity', async () => {
  const incomplete = alert(10, 'not_used', 'CVE-2022-32149');
  delete incomplete.dependency;
  delete incomplete.security_vulnerability;
  const result = await runAction([incomplete]);

  assert.equal(result.code, 1);
  assert.match(result.stderr, /missing package identity/);
});

test('sanitizes API error messages before emitting workflow annotations', async () => {
  const result = await runAction([], {
    serverError: { status: 500, body: 'upstream failure\n::warning::injected' },
  });

  assert.equal(result.code, 1);
  assert.doesNotMatch(result.stderr, /\n::warning::/);
});

test('rejects an invalid automatically derived image name', async () => {
  const result = await runAction([], { imageName: 'invalid image', productPurls: '' });

  assert.equal(result.code, 1);
  assert.match(result.stderr, /image-name must be non-empty/);
});
