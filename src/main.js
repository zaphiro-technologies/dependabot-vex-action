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

import fs from 'node:fs';
import path from 'node:path';

const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
const repository = process.env.GITHUB_REPOSITORY;
const token = input('github-token');
const apiBase = process.env.GITHUB_API_URL || 'https://api.github.com';
const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com';

if (!repository) fail('GITHUB_REPOSITORY is required');
if (!token) fail('github-token input is required');

const [owner, repo] = repository.split('/');
const baseBranch = input('base-branch', 'main');
const vexPath = input('vex-path', '.vex/dependabot.openvex.json');
const ledgerPath = input('dismissal-ledger-path', '.vex/dependabot-dismissals.json');
const vulnerabilityId = input('vulnerability-id');
const requestedCandidateBranch = input('candidate-branch');
let candidateBranch = requestedCandidateBranch || defaultCandidateBranch();
const githubOutput = process.env.GITHUB_OUTPUT;

function safeBranchIdentity(identity) {
  return String(identity)
    .replaceAll(/[^A-Za-z0-9._-]+/g, '-')
    .replaceAll(/-+/g, '-')
    .replaceAll(/^[-.]+|[-.]+$/g, '')
    .slice(0, 80) || 'scope';
}

function vulnerabilityBranchPrefix() {
  return `automation/dependabot-vex-${safeBranchIdentity(vulnerabilityId)}`;
}

function defaultCandidateBranch() {
  return `${vulnerabilityBranchPrefix()}-${process.env.GITHUB_RUN_ID || 'local'}`;
}

function input(name, fallback = '') {
  const upper = name.toUpperCase();
  return process.env[`INPUT_${upper}`]
    ?? process.env[`INPUT_${upper.replaceAll('-', '_')}`]
    ?? fallback;
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
    const response = await github(endpoint);
    alerts.push(...(response.body || []));
    endpoint = nextPage(response.headers.get('link'));
  }
  return alerts;
}

async function reuseExistingCandidateBranch() {
  if (requestedCandidateBranch || !vulnerabilityId || vulnerabilityId === '__vex_scope__') return;

  const endpoint = `/repos/${owner}/${repo}/pulls?state=open&base=${encodeURIComponent(baseBranch)}&per_page=100`;
  const response = await github(endpoint);
  const prefix = `${vulnerabilityBranchPrefix()}-`;
  const candidates = (response.body || [])
    .filter(pullRequest =>
      pullRequest.head?.repo?.full_name === repository
      && pullRequest.head?.ref?.startsWith(prefix))
    .sort((left, right) => (left.number || 0) - (right.number || 0));
  const existing = candidates[0]?.head?.ref;
  if (existing) {
    candidateBranch = existing;
    console.log(`Reusing existing Dependabot VEX candidate branch: ${existing}`);
  }
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

function lockfilePaths(alert) {
  const manifest = String(alert.dependency?.manifest_path || '').replace(/^[/\\]+/, '');
  const manifestDirectory = manifest ? path.dirname(manifest) : '.';
  const names = [
    'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml',
    'go.mod', 'go.sum', 'poetry.lock',
  ];
  return [...new Set([
    ...names.map(name => path.join(manifestDirectory, name)),
    ...names,
  ])]
    .map(file => absolute(file))
    .filter(file => fs.existsSync(file));
}

function addNpmLockVersions(lock, packageName, versions) {
  for (const [location, dependency] of Object.entries(lock.packages || {})) {
    const matchesName = dependency?.name === packageName
      || location === `node_modules/${packageName}`
      || location.endsWith(`/node_modules/${packageName}`);
    if (matchesName && dependency.version) versions.add(String(dependency.version));
  }

  function visit(dependencies) {
    for (const [name, dependency] of Object.entries(dependencies || {})) {
      if (name === packageName && dependency.version) versions.add(String(dependency.version));
      visit(dependency.dependencies);
    }
  }
  visit(lock.dependencies);
}

function addTextLockVersions(text, packageName, versions) {
  const escapedName = packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const selectorPattern = new RegExp(`(^|[\\s,"'])${escapedName}@`);
  let selected = false;
  let headerVersion = null;

  const flush = () => {
    if (selected && headerVersion) versions.add(headerVersion);
    selected = false;
    headerVersion = null;
  };

  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    const headerMatch = line.match(/^ {0,2}(.+):\s*$/);
    const indentation = line.length - line.trimStart().length;
    if (trimmed && headerMatch && (indentation === 0 || selectorPattern.test(trimmed))) {
      flush();
      selected = selectorPattern.test(trimmed);
      const header = headerMatch[1].replace(/^['"]|['"]$/g, '');
      const match = header.match(new RegExp(`${escapedName}@([^,\\s"]+)`));
      if (match && /^v?\d+\.\d+\.\d+(?:[-+].*)?$/.test(match[1])) headerVersion = match[1];
      continue;
    }
    if (!selected) continue;
    const match = trimmed.match(/^version\s*:?[ \t]+["']?([^"'\s]+)["']?/);
    if (match) headerVersion = match[1];
  }
  flush();
}

function addGoModVersions(text, packageName, versions) {
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || /^(module|go|toolchain|replace|exclude)\b/.test(trimmed)) continue;
    const match = trimmed.replace(/^require\s+/, '').match(/^(\S+)\s+(v\S+)(?:\s+\/\/.*)?$/);
    if (match?.[1] === packageName) versions.add(match[2]);
  }
}

function addGoSumVersions(text, packageName, versions) {
  for (const line of text.split(/\r?\n/)) {
    const fields = line.trim().split(/\s+/);
    if (fields[0] !== packageName || !fields[1]) continue;
    versions.add(fields[1].replace(/\/go\.mod$/, ''));
  }
}

function addPoetryLockVersions(text, packageName, versions) {
  const target = packageName.toLowerCase().replaceAll(/[_.]+/g, '-');
  let currentName = null;
  let currentVersion = null;

  const flush = () => {
    if (currentName === target && currentVersion) versions.add(currentVersion);
    currentName = null;
    currentVersion = null;
  };

  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === '[[package]]') {
      flush();
      continue;
    }
    const name = line.match(/^name\s*=\s*["']([^"']+)["']/);
    if (name) currentName = name[1].toLowerCase().replaceAll(/[_.]+/g, '-');
    const version = line.match(/^version\s*=\s*["']([^"']+)["']/);
    if (version) currentVersion = version[1];
  }
  flush();
}

function dependencyVersion(alert, dependency) {
  if (alert.dependency?.version) return String(alert.dependency.version);
  const versions = new Set();
  const files = lockfilePaths(alert);
  const ecosystem = dependency.ecosystem;

  for (const file of files) {
    const basename = path.basename(file);
    if ((ecosystem === 'go' || ecosystem === 'gomod') && basename !== 'go.mod') continue;
    if (ecosystem === 'pip' || ecosystem === 'python' || ecosystem === 'poetry') {
      if (basename !== 'poetry.lock') continue;
    } else if (ecosystem !== 'npm' && ecosystem !== 'go' && ecosystem !== 'gomod') {
      continue;
    }
    try {
      const text = fs.readFileSync(file, 'utf8');
      if (ecosystem === 'npm') {
        if (basename === 'package-lock.json' || basename === 'npm-shrinkwrap.json') {
          addNpmLockVersions(JSON.parse(text), dependency.name, versions);
        } else {
          addTextLockVersions(text, dependency.name, versions);
        }
      } else if (ecosystem === 'go' || ecosystem === 'gomod') {
        addGoModVersions(text, dependency.name, versions);
      } else {
        addPoetryLockVersions(text, dependency.name, versions);
      }
    } catch (error) {
      console.warn(`Warning: unable to resolve ${dependency.name} from ${file}: ${error.message}`);
    }
  }

  if (versions.size === 1) return [...versions][0];
  if ((ecosystem === 'go' || ecosystem === 'gomod') && versions.size === 0) {
    for (const file of files.filter(item => path.basename(item) === 'go.sum')) {
      try {
        addGoSumVersions(fs.readFileSync(file, 'utf8'), dependency.name, versions);
      } catch (error) {
        console.warn(`Warning: unable to resolve ${dependency.name} from ${file}: ${error.message}`);
      }
    }
    if (versions.size === 1) return [...versions][0];
  }
  if (versions.size > 1) {
    console.warn(`Warning: multiple installed versions found for ${dependency.name}; omitting the PURL version`);
  }
  return null;
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
      version: dependencyVersion(alert, dependency),
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

function matchesVulnerability(record) {
  return !vulnerabilityId || vulnerabilityId === '__vex_scope__' ||
    record.vulnerability.name === vulnerabilityId;
}

function encodePurlValue(value) {
  return encodeURIComponent(String(value)).replaceAll(/[!'()*]/g, character =>
    `%${character.codePointAt(0).toString(16).toUpperCase()}`);
}

function dependencyPurl(record) {
  const ecosystem = record.package?.ecosystem || '';
  const name = String(record.package?.name || '')
    .split('/')
    .map(encodePurlValue)
    .join('/');
  const types = {
    npm: 'npm', go: 'golang', gomod: 'golang', pip: 'pypi', python: 'pypi',
    maven: 'maven', gradle: 'maven', cargo: 'cargo', bundler: 'gem',
    composer: 'composer', nuget: 'nuget', pub: 'pub', hex: 'hex', mix: 'hex',
    docker: 'docker',
  };
  const version = record.package?.version ? `@${encodePurlValue(record.package.version)}` : '';
  return `pkg:${types[ecosystem] || ecosystem}/${name}${version}`;
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
  const comment = original ? `${original}\n\n${note}` : note;
  await github(`/repos/${owner}/${repo}/dependabot/alerts/${alert.number}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      state: 'dismissed',
      dismissed_reason: 'no_bandwidth',
      dismissed_comment: comment,
    }),
  });
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
    products: vexProducts(record, products),
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

function vexProducts(record, products) {
  const dependency = dependencyPurl(record);
  return [
    ...products
      .filter(product => product !== dependency)
      .map(product => ({
        '@id': product,
        subcomponents: [{ '@id': dependency }],
      })),
    { '@id': dependency },
  ];
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
    normalized.filter(record =>
      record.dismissed_reason !== 'no_bandwidth' && matchesVulnerability(record)),
  );
  const ledgerExists = fs.existsSync(absolute(ledgerPath));
  const changed = (ledger.alerts.length > 0 || ledgerExists)
    && (!ledgerExists || JSON.stringify(ledger) !== JSON.stringify(existingLedger));
  if (changed) writeJson(ledgerPath, ledger);

  const records = ledger.alerts || [];
  const invalid = records.filter(record => !record.package?.ecosystem || !record.package?.name);
  if (invalid.length) {
    const invalidAlerts = invalid.map(record => `alert=${record.alert}`).join(', ');
    fail(`Dismissal records are missing package identity: ${invalidAlerts}`);
  }
  return { records, changed };
}

function retargetStatement(statement, eligible, products) {
  const notes = statement.status_notes || '';
  if (!notes.startsWith('dependabot-alert:')) return statement;
  const record = eligible.find(item => notes.startsWith(marker(item)));
  if (!record) return statement;
  const status = statement.status === 'under_investigation' ? mapVexStatus(record) : {};
  return {
    ...statement,
    ...status,
    products: vexProducts(record, products),
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
  const existingProducts = [...new Set(
    existingStatements.flatMap(statement => (statement.products || [])
      .map(product => product['@id'])
      .filter(product => products.includes(product))),
  )];
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

function pullRequestDetails(newRecords, skipped, ledgerChanged, vexChanged) {
  const vulnerabilityCodes = [...new Set(newRecords.map(record => record.vulnerability.name))];
  let vulnerabilityList = '- Dependabot dismissal ledger initialized or updated';
  if (newRecords.length) {
    vulnerabilityList = newRecords
      .map(record => `- ${record.vulnerability.name} (${record.package.name}) — ${record.url}`)
      .join('\n');
  } else if (vexChanged) {
    vulnerabilityList = '- Existing VEX product scope updated';
  }
  let title = vexChanged ? 'Update VEX product scope' : 'Update Dependabot dismissal ledger';
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
    'This pull request updates reviewed OpenVEX candidates and historical Dependabot dismissal metadata.',
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
  await reuseExistingCandidateBranch();

  const alerts = await allDismissedAlerts();
  const normalized = alerts.map(normalizeAlert);
  const skipped = normalized.filter(record =>
    record.dismissed_reason === 'no_bandwidth' && matchesVulnerability(record));
  await annotateSkippedAlerts(alerts);

  const { records, changed: ledgerChanged } = loadLedger(normalized);
  const existingVex = readJson(vexPath, {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    version: 1,
    statements: [],
  });
  const { changed: vexChanged, newRecords, statements, vex } = buildVexDocument(existingVex, records, products);
  if (vexChanged || fs.existsSync(absolute(vexPath))) writeJson(vexPath, vex);
  const changed = ledgerChanged || vexChanged;

  const { body, title, vulnerabilityCodes } = pullRequestDetails(newRecords, skipped, ledgerChanged, vexChanged);

  output('changed', changed ? 'true' : 'false');
  output('vex-changed', vexChanged ? 'true' : 'false');
  output('candidate-branch', candidateBranch);
  output('pull-request-title', title);
  output('pull-request-body', body);
  output('vulnerability-codes', vulnerabilityCodes.join(', ') || (ledgerChanged ? 'ledger update' : 'scope update'));
  const candidateVulnerabilityIds = [...new Set(vulnerabilityCodes)];
  output('vulnerability-ids', JSON.stringify(
    candidateVulnerabilityIds.length || !changed ? candidateVulnerabilityIds : ['__vex_scope__'],
  ));
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
