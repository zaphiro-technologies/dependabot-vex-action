import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
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

async function runAction(alerts, { alertsToken = '' } = {}) {
  const workspace = await mkdtemp(path.resolve('test-workspace-'));
  const output = path.join(workspace, 'github-output');
  const requests = [];
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
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify(alerts));
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
        GITHUB_RUN_ID: '12345',
        GITHUB_SERVER_URL: 'https://github.com',
        GITHUB_WORKSPACE: workspace,
        INPUT_ALERTS_TOKEN: alertsToken,
        INPUT_BASE_BRANCH: 'main',
        INPUT_DISMISSAL_LEDGER_PATH: '.vex/dependabot-dismissals.json',
        INPUT_GITHUB_TOKEN: 'read-token',
        INPUT_PRODUCT_PURLS: 'pkg:oci/test?repository_url=ghcr.io%2Fzaphiro-technologies%2Ftest',
        INPUT_VEX_PATH: '.vex/dependabot.openvex.json',
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('close', code => resolve({ code, stdout, stderr }));
  });

  const vexFile = path.join(workspace, '.vex/dependabot.openvex.json');
  const outputText = await readFile(output, 'utf8').catch(() => '');
  const vex = await readFile(vexFile, 'utf8').then(JSON.parse).catch(() => null);
  await new Promise(resolve => server.close(resolve));
  await rm(workspace, { recursive: true, force: true });
  return { ...result, requests, output: outputText, vex };
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

test('maps dismissal reasons and links the original alerts', async () => {
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

test('uses alerts-token when reading Dependabot alerts', async () => {
  const result = await runAction([alert(6, 'not_used', 'CVE-2022-32149')], {
    alertsToken: 'alerts-read-token',
  });

  assert.equal(result.code, 0, result.stderr);
  const getAlerts = result.requests.find(request => request.method === 'GET');
  assert.equal(getAlerts?.authorization, 'Bearer alerts-read-token');
});

test('skips no_bandwidth and annotates the original alert', async () => {
  const result = await runAction([alert(5, 'no_bandwidth', 'CVE-2022-32149')], {
    alertsToken: 'write-token',
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.vex, null);
  assert.match(outputValue(result.output, 'skipped-alerts'), /5/);
  const patch = result.requests.find(request => request.method === 'PATCH');
  assert.ok(patch);
  assert.match(JSON.parse(patch.body).dismissed_comment, /not a security assessment/);
});
