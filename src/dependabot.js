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
import { absolute } from './runtime.js';

function packageInfo(alert) {
  return alert.dependency?.package || alert.security_vulnerability?.package || {};
}

function lockfilePaths(runtime, alert) {
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
    .map(file => absolute(runtime, file))
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

function parseTextLockHeader(line, selectorPattern, escapedName) {
  const trimmed = line.trim();
  const headerMatch = line.match(/^ {0,2}(.+):\s*$/);
  const indentation = line.length - line.trimStart().length;
  const isHeader = trimmed && headerMatch && (indentation === 0 || selectorPattern.test(trimmed));
  if (!isHeader) return null;

  const selected = selectorPattern.test(trimmed);
  const header = headerMatch[1].replace(/^['"]|['"]$/g, '');
  const match = header.match(new RegExp(String.raw`${escapedName}@([^,\s"]+)`));
  const version = match && /^v?\d+\.\d+\.\d+(?:[-+].*)?$/.test(match[1])
    ? match[1]
    : null;
  return { selected, version };
}

function parseTextLockVersion(trimmed) {
  const separator = trimmed.slice('version'.length, 'version'.length + 1);
  if (!trimmed.startsWith('version') || (separator !== ':' && !/\s/.test(separator))) return null;
  let value = trimmed.slice('version'.length).trimStart();
  if (value.startsWith(':')) value = value.slice(1).trimStart();
  if (value.startsWith('"') || value.startsWith("'")) value = value.slice(1);
  return value.split(/["'\s]/, 1)[0] || null;
}

function addTextLockVersions(text, packageName, versions) {
  const escapedName = packageName.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
  const selectorPattern = new RegExp(String.raw`(^|[\s,"'])${escapedName}@`);
  let selected = false;
  let headerVersion = null;

  const flush = () => {
    if (selected && headerVersion) versions.add(headerVersion);
    selected = false;
    headerVersion = null;
  };

  for (const line of text.split(/\r?\n/)) {
    const header = parseTextLockHeader(line, selectorPattern, escapedName);
    if (header) {
      flush();
      selected = header.selected;
      headerVersion = header.version;
      continue;
    }
    if (selected) headerVersion = parseTextLockVersion(line.trim()) || headerVersion;
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

function isRelevantLockfile(ecosystem, basename) {
  if (ecosystem === 'go' || ecosystem === 'gomod') return basename === 'go.mod';
  if (ecosystem === 'pip' || ecosystem === 'python' || ecosystem === 'poetry') {
    return basename === 'poetry.lock';
  }
  return ecosystem === 'npm';
}

function collectLockfileVersions(files, ecosystem, dependency, versions) {
  for (const file of files) {
    const basename = path.basename(file);
    if (!isRelevantLockfile(ecosystem, basename)) continue;
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
}

function collectGoSumVersions(files, dependency, versions) {
  for (const file of files.filter(item => path.basename(item) === 'go.sum')) {
    try {
      addGoSumVersions(fs.readFileSync(file, 'utf8'), dependency.name, versions);
    } catch (error) {
      console.warn(`Warning: unable to resolve ${dependency.name} from ${file}: ${error.message}`);
    }
  }
}

function dependencyVersions(runtime, alert, dependency) {
  if (alert.dependency?.version) return [String(alert.dependency.version)];
  const versions = new Set();
  const files = lockfilePaths(runtime, alert);
  const ecosystem = dependency.ecosystem;

  collectLockfileVersions(files, ecosystem, dependency, versions);
  if ((ecosystem === 'go' || ecosystem === 'gomod') && versions.size === 0) {
    collectGoSumVersions(files, dependency, versions);
  }
  if (versions.size > 1) {
    console.warn(`Warning: multiple installed versions found for ${dependency.name}; retaining all PURL versions`);
  }
  return [...versions];
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

export function normalizeAlert(runtime, alert) {
  const dependency = packageInfo(alert);
  const versions = dependencyVersions(runtime, alert, dependency);
  return {
    alert: alert.number,
    url: alert.html_url || `${runtime.serverUrl}/${runtime.repository}/security/dependabot/${alert.number}`,
    package: {
      ecosystem: dependency.ecosystem || null,
      name: dependency.name || null,
      version: versions.length === 1 ? versions[0] : null,
      ...(versions.length > 1 ? { versions } : {}),
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

export function matchesVulnerability(runtime, record) {
  const { vulnerabilityId } = runtime;
  return !vulnerabilityId || vulnerabilityId === '__vex_scope__' ||
    record.vulnerability.name === vulnerabilityId;
}
