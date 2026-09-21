import fs from 'node:fs';
import path from 'node:path';

const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
const repository = process.env.GITHUB_REPOSITORY;
const token = input('github-token');
const alertsToken = input('alerts-token');
const apiBase = process.env.GITHUB_API_URL || 'https://api.github.com';
const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com';

if (!repository) fail('GITHUB_REPOSITORY is required');
if (!token) fail('github-token input is required');

const [owner, repo] = repository.split('/');
const baseBranch = input('base-branch', 'main');
const candidateBranch = input('candidate-branch') ||
  `automation/dependabot-vex-${process.env.GITHUB_RUN_ID || 'local'}`;
const vexPath = input('vex-path', '.vex/dependabot.openvex.json');
const ledgerPath = input('dismissal-ledger-path', '.vex/dependabot-dismissals.json');
const githubOutput = process.env.GITHUB_OUTPUT;

function input(name, fallback = '') {
  const key = `INPUT_${name.toUpperCase().replaceAll('-', '_')}`;
  return process.env[key] ?? fallback;
}

function fail(message) {
  const safeMessage = String(message).replaceAll(/[\u0000-\u001F\u007F]/g, ' ');
  console.error(`::error::${safeMessage}`);
  process.exit(1);
}

function output(name, value) {
  if (!githubOutput) return;
  const delimiter = `VEX_${name.replaceAll(/\W/g, '_')}_${Date.now()}`;
  fs.appendFileSync(githubOutput, `${name}<<${delimiter}\n${value ?? ''}\n${delimiter}\n`);
}

function absolute(file) {
  return path.resolve(workspace, file);
}

function readJson(file, fallback) {
  const target = absolute(file);
  if (!fs.existsSync(target)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(target, 'utf8'));
  } catch (error) {
    fail(`Unable to parse ${file}: ${error.message}`);
  }
}

function writeJson(file, value) {
  const target = absolute(file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
}

async function github(endpoint, options = {}, authToken = token) {
  const response = await fetch(`${apiBase}${endpoint}`, {
    ...options,
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${authToken}`,
      'x-github-api-version': '2022-11-28',
      ...options.headers,
    },
  });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!response.ok) {
    const detail = typeof body === 'string' ? body : JSON.stringify(body);
    fail(`GitHub API ${options.method || 'GET'} ${endpoint} failed (${response.status}): ${detail}`);
  }
  return { body, headers: response.headers };
}

function nextPage(linkHeader) {
  if (!linkHeader) return null;
  for (const link of linkHeader.split(',')) {
    if (!link.includes('rel="next"')) continue;
    const start = link.indexOf('<');
    const end = link.indexOf('>', start + 1);
    if (start === -1 || end === -1) return null;
    const url = new URL(link.slice(start + 1, end));
    return url.pathname + url.search;
  }
  return null;
}

async function allDismissedAlerts() {
  const alerts = [];
  let endpoint = `/repos/${owner}/${repo}/dependabot/alerts?state=dismissed&per_page=100`;
  while (endpoint) {
    const response = await github(endpoint, {}, alertsToken || token);
    alerts.push(...(response.body || []));
    endpoint = nextPage(response.headers.get('link'));
  }
  return alerts;
}

function section(text, heading) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex(line => line.trim() === heading);
  if (start === -1) return '';
  const result = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim().startsWith('[')) break;
    result.push(line);
  }
  return result.join('\n');
}

function tomlString(text, key) {
  const line = text.split(/\r?\n/).find(item => {
    const trimmed = item.trim();
    const separator = trimmed.indexOf('=');
    return separator !== -1 && trimmed.slice(0, separator).trim() === key;
  });
  if (!line) return '';
  const value = line.slice(line.indexOf('=') + 1).trim();
  const quote = value[0];
  return (quote === '"' || quote === "'") && value.endsWith(quote)
    ? value.slice(1, -1)
    : '';
}

function deriveSourcePurls() {
  const purls = [];
  const goMod = absolute('go.mod');
  if (fs.existsSync(goMod)) {
    const module = fs.readFileSync(goMod, 'utf8')
      .split(/\r?\n/)
      .find(line => line.trim().startsWith('module '))
      ?.trim()
      .slice('module '.length)
      .trim();
    if (module) purls.push(`pkg:golang/${module}`);
  }

  const pyproject = absolute('pyproject.toml');
  if (fs.existsSync(pyproject)) {
    const text = fs.readFileSync(pyproject, 'utf8');
    const name = tomlString(section(text, '[project]'), 'name')
      || tomlString(section(text, '[tool.poetry]'), 'name');
    if (name) purls.push(`pkg:pypi/${name.replaceAll(/[-_.]+/g, '-').toLowerCase()}`);
  }

  const packageJson = absolute('package.json');
  if (fs.existsSync(packageJson)) {
    try {
      const name = JSON.parse(fs.readFileSync(packageJson, 'utf8')).name;
      const packageName = name?.startsWith('@') ? `%40${name.slice(1)}` : name;
      if (packageName) purls.push(`pkg:npm/${packageName}`);
    } catch (error) {
      console.warn(`Warning: unable to parse package.json: ${error.message}`);
    }
  }
  return purls;
}

function productPurls() {
  const explicit = input('product-purls')
    .split(/\r?\n/)
    .map(value => value.trim())
    .filter(Boolean);
  if (explicit.length) {
    console.log('Using explicitly configured product PURLs');
    return [...new Set(explicit)];
  }

  const imageName = (input('image-name') || repo).toLowerCase();
  if (!imageName || /\s|:/.test(imageName)) {
    fail('image-name must be non-empty and must not contain whitespace or :');
  }
  const imageRepository = `ghcr.io/${owner.toLowerCase()}/${imageName}`;
  const encodedRepository = imageRepository.replaceAll('/', '%2F');
  const derived = [`pkg:oci/${imageName}?repository_url=${encodedRepository}`, ...deriveSourcePurls()];
  console.log('Using automatically derived product PURLs:');
  for (const purl of new Set(derived)) console.log(`  ${purl}`);
  return [...new Set(derived)];
}

function packageInfo(alert) {
  return alert.dependency?.package || alert.security_vulnerability?.package || {};
}

function vulnerabilityInfo(alert) {
  const advisory = alert.security_advisory || {};
  const identifiers = advisory.identifiers || [];
  const name = advisory.cve_id || advisory.ghsa_id || identifiers[0]?.value ||
    `DEPENDABOT-${alert.number}`;
  const aliases = [...new Set([
    advisory.cve_id,
    advisory.ghsa_id,
    ...identifiers.map(identifier => identifier.value),
  ].filter(Boolean))];
  return { name, aliases };
}

function normalizeAlert(alert) {
  const dependency = packageInfo(alert);
  return {
    alert: alert.number,
    url: alert.html_url || `${serverUrl}/${repository}/security/dependabot/${alert.number}`,
    package: {
      ecosystem: dependency.ecosystem || null,
      name: dependency.name || null,
      version: alert.dependency?.version || null,
    },
    vulnerability: vulnerabilityInfo(alert),
    vulnerable_version_range: alert.security_vulnerability?.vulnerable_version_range || null,
    first_patched_version: alert.security_vulnerability?.first_patched_version?.identifier || null,
    dismissed_reason: alert.dismissed_reason || null,
    dismissed_comment: alert.dismissed_comment || null,
    dismissed_by: alert.dismissed_by?.login || alert.dismissed_by || null,
    dismissed_at: alert.dismissed_at || null,
    last_observed_state: 'dismissed',
    skipped: alert.dismissed_reason === 'no_bandwidth',
  };
}

function alertKey(record) {
  return record.url || `alert:${record.alert}`;
}

function marker(record) {
  return `dependabot-alert:${record.url}`;
}

function dependencyPurl(record) {
  const ecosystem = record.package?.ecosystem || '';
  const name = String(record.package?.name || '').replace(/^@/, '%40');
  const types = {
    npm: 'npm', go: 'golang', gomod: 'golang', pip: 'pypi', python: 'pypi',
    maven: 'maven', gradle: 'maven', cargo: 'cargo', bundler: 'gem',
    composer: 'composer', nuget: 'nuget', pub: 'pub', hex: 'hex', mix: 'hex',
    docker: 'docker',
  };
  return `pkg:${types[ecosystem] || ecosystem}/${name}`;
}

function mapVexStatus(record) {
  const mapping = {
    not_used: { status: 'not_affected', justification: 'vulnerable_code_not_present' },
    inaccurate: { status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path' },
    tolerable_risk: { status: 'not_affected', justification: 'inline_mitigations_already_exist' },
  };
  return mapping[record.dismissed_reason] || { status: 'under_investigation' };
}

async function annotateNoBandwidth(alert) {
  const note = '[dependabot-vex-action] This dismissal is not a security assessment; no VEX statement was generated.';
  const original = alert.dismissed_comment || '';
  if (original.includes(note)) return;
  if (!alertsToken) {
    fail(`Dependabot alert ${alert.number} has reason no_bandwidth; alerts-token with Dependabot alerts write permission is required to annotate it`);
  }
  const comment = original ? `${original}\n\n${note}` : note;
  await github(`/repos/${owner}/${repo}/dependabot/alerts/${alert.number}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      state: 'dismissed',
      dismissed_reason: 'no_bandwidth',
      dismissed_comment: comment,
    }),
  }, alertsToken);
  console.log(`Annotated Dependabot alert ${alert.number}: no VEX security assessment`);
}

function mergeLedger(existing, current) {
  const old = Array.isArray(existing.alerts) ? existing.alerts : [];
  const merged = [...old];
  for (const record of current) {
    const index = merged.findIndex(item => alertKey(item) === alertKey(record));
    if (index === -1) merged.push(record);
    else merged[index] = { ...merged[index], ...record };
  }
  return { version: existing.version || 1, alerts: merged };
}

function vexCandidate(record, products) {
  const status = mapVexStatus(record);
  return {
    vulnerability: {
      name: record.vulnerability.name,
      ...(record.vulnerability.aliases.length ? { aliases: record.vulnerability.aliases } : {}),
    },
    products: products.map(product => ({
      '@id': product,
      subcomponents: [{ '@id': dependencyPurl(record) }],
    })),
    status_notes: [
      marker(record),
      `package=${record.package.name || ''}`,
      `ecosystem=${record.package.ecosystem || ''}`,
      `reason=${record.dismissed_reason || 'unknown'}`,
      `comment=${record.dismissed_comment || ''}`,
      `dismissed_by=${record.dismissed_by || ''}`,
      `dismissed_at=${record.dismissed_at || ''}`,
      'This statement was generated from a dismissed Dependabot alert and requires review.',
    ].join('\n'),
    ...status,
  };
}

async function annotateSkippedAlerts(alerts) {
  for (const alert of alerts) {
    if (alert.dismissed_reason === 'no_bandwidth') await annotateNoBandwidth(alert);
  }
}

function loadLedger(normalized) {
  const existingLedger = readJson(ledgerPath, { version: 1, alerts: [] });
  // no_bandwidth is recorded on the Dependabot alert itself via
  // dismissed_comment, but is intentionally not added to the VEX ledger.
  const ledger = mergeLedger(
    existingLedger,
    normalized.filter(record => record.dismissed_reason !== 'no_bandwidth'),
  );
  writeJson(ledgerPath, ledger);

  const records = ledger.alerts || [];
  const invalid = records.filter(record => !record.package?.ecosystem || !record.package?.name);
  if (invalid.length) {
    const invalidAlerts = invalid.map(record => `alert=${record.alert}`).join(', ');
    fail(`Dismissal records are missing package identity: ${invalidAlerts}`);
  }
  return records;
}

function retargetStatement(statement, eligible, products) {
  const notes = statement.status_notes || '';
  if (!notes.startsWith('dependabot-alert:')) return statement;
  const record = eligible.find(item => notes.startsWith(marker(item)));
  if (!record) return statement;
  return {
    ...statement,
    products: products.map(product => ({
      '@id': product,
      subcomponents: [{ '@id': dependencyPurl(record) }],
    })),
  };
}

function retainStatements(existingStatements, eligible, products) {
  const activeMarkers = new Set(eligible.map(marker));
  return existingStatements
    .filter(statement => {
      const notes = statement.status_notes || '';
      if (!notes.startsWith('dependabot-alert:')) return true;
      return activeMarkers.has(notes.split('\n')[0]);
    })
    .map(statement => retargetStatement(statement, eligible, products));
}

function buildVexDocument(existingVex, records, products) {
  const existingStatements = existingVex.statements || [];
  const existingMarkers = new Set(existingStatements.map(statement =>
    (statement.status_notes || '').split('\n')[0]));
  const eligible = records.filter(record => !record.skipped && record.dismissed_reason !== 'no_bandwidth');
  const retained = retainStatements(existingStatements, eligible, products);
  const newRecords = eligible.filter(record => !existingMarkers.has(marker(record)));
  const newStatements = newRecords.map(record => vexCandidate(record, products));
  const statements = [...retained, ...newStatements];
  const existingProducts = [...new Set(existingStatements.flatMap(statement =>
    (statement.products || []).map(product => product['@id']).filter(Boolean)))];
  const productsChanged = eligible.length > 0
    && JSON.stringify(products) !== JSON.stringify(existingProducts);
  const changed = JSON.stringify(statements) !== JSON.stringify(existingStatements)
    || productsChanged;

  const vex = {
    ...existingVex,
    '@context': existingVex['@context'] || 'https://openvex.dev/ns/v0.2.0',
    '@id': existingVex['@id'] || `${serverUrl}/${repository}/blob/${baseBranch}/${vexPath}`,
    author: existingVex.author || 'Dependabot VEX generator',
    role: existingVex.role || 'Automated candidate generator',
    timestamp: changed ? new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') : (existingVex.timestamp || new Date().toISOString()),
    version: changed ? (existingVex.version || 0) + 1 : (existingVex.version || 1),
    statements,
  };
  return { changed, newRecords, statements, vex };
}

function pullRequestDetails(newRecords, skipped) {
  const vulnerabilityCodes = [...new Set(newRecords.map(record => record.vulnerability.name))];
  const vulnerabilityList = newRecords.length
    ? newRecords.map(record => `- ${record.vulnerability.name} (${record.package.name}) — ${record.url}`).join('\n')
    : '- Existing VEX product scope updated';
  let title = 'Update VEX product scope';
  if (newRecords.length === 1) {
    const record = newRecords[0];
    title = `Add VEX statement for ${record.vulnerability.name} (${record.package.name})`;
  } else if (newRecords.length > 1) {
    title = `Add VEX statements for ${vulnerabilityCodes.join(', ')}`;
  }
  const skippedMessage = skipped.length
    ? `Skipped alert(s) because their dismissal reason is no_bandwidth: ${skipped.map(record => record.alert).join(', ')}. The action annotated the original alert that this is not a security assessment and generated no VEX statement for it.`
    : '';
  const body = [
    'This pull request adds reviewed OpenVEX statements generated from dismissed Dependabot alerts.',
    '',
    'Relevant vulnerability alerts:',
    vulnerabilityList,
    '',
    'Review each statement\'s product scope, vulnerability reachability, status, and justification before merging.',
    '',
    skippedMessage,
  ].filter(Boolean).join('\n');
  return { body, title, vulnerabilityCodes };
}

async function main() {
  const products = productPurls();
  if (!products.length) fail('product-purls must contain at least one non-empty PURL');

  const alerts = await allDismissedAlerts();
  const normalized = alerts.map(normalizeAlert);
  const skipped = normalized.filter(record => record.dismissed_reason === 'no_bandwidth');
  await annotateSkippedAlerts(alerts);

  const records = loadLedger(normalized);
  const existingVex = readJson(vexPath, {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    version: 1,
    statements: [],
  });
  const { changed, newRecords, statements, vex } = buildVexDocument(existingVex, records, products);
  if (changed || fs.existsSync(absolute(vexPath))) writeJson(vexPath, vex);

  const { body, title, vulnerabilityCodes } = pullRequestDetails(newRecords, skipped);

  output('changed', changed ? 'true' : 'false');
  output('vex-changed', changed ? 'true' : 'false');
  output('candidate-branch', candidateBranch);
  output('pull-request-title', title);
  output('pull-request-body', body);
  output('pull-request-number', '');
  output('pull-request-url', '');
  output('vulnerability-codes', vulnerabilityCodes.join(', ') || 'scope update');
  output('skipped-alerts', skipped.map(record => record.alert).join(', '));
  console.log(`Currently dismissed Dependabot alerts: ${alerts.length}`);
  console.log(`Historical dismissal records: ${records.length}`);
  console.log(`Generated or retained VEX statements: ${statements.length}`);
  if (!changed) console.log('No VEX document changes required');
}

try {
  await main();
} catch (error) {
  fail(error.stack || error.message || String(error));
}
