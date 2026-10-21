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
import { absolute, fail, readJson, writeJson } from './runtime.js';
import { matchesVulnerability } from './dependabot.js';

function encodePurlValue(value) {
  return encodeURIComponent(String(value)).replaceAll(/[!'()*]/g, character =>
    `%${character.codePointAt(0).toString(16).toUpperCase()}`);
}

function dependencyPurl(record, version = record.package?.version) {
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
  const purlVersion = version ? `@${encodePurlValue(version)}` : '';
  return `pkg:${types[ecosystem] || ecosystem}/${name}${purlVersion}`;
}

function dependencyPurls(record) {
  const versions = Array.isArray(record.package?.versions) && record.package.versions.length
    ? record.package.versions
    : [record.package?.version || null];
  return [...new Set(versions.map(version => dependencyPurl(record, version)))];
}

function mapVexStatus(record) {
  const mapping = {
    not_used: { status: 'not_affected', justification: 'vulnerable_code_not_present' },
    inaccurate: { status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path' },
    tolerable_risk: { status: 'not_affected', justification: 'inline_mitigations_already_exist' },
  };
  return mapping[record.dismissed_reason] || { status: 'under_investigation' };
}

function alertKey(record) {
  return record.url || `alert:${record.alert}`;
}

function marker(record) {
  return `dependabot-alert:${record.url}`;
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

export function loadLedger(runtime, normalized) {
  const existingLedger = readJson(runtime, runtime.ledgerPath, { version: 1, alerts: [] });
  // no_bandwidth is recorded in the Dependabot comment, not as a VEX decision.
  const ledger = mergeLedger(
    existingLedger,
    normalized.filter(record =>
      record.dismissed_reason !== 'no_bandwidth' && matchesVulnerability(runtime, record)),
  );
  const ledgerExists = fs.existsSync(absolute(runtime, runtime.ledgerPath));
  const changed = (ledger.alerts.length > 0 || ledgerExists)
    && (!ledgerExists || JSON.stringify(ledger) !== JSON.stringify(existingLedger));
  if (changed) writeJson(runtime, runtime.ledgerPath, ledger);

  const records = ledger.alerts || [];
  const invalid = records.filter(record => !record.package?.ecosystem || !record.package?.name);
  if (invalid.length) {
    const invalidAlerts = invalid.map(record => `alert=${record.alert}`).join(', ');
    fail(`Dismissal records are missing package identity: ${invalidAlerts}`);
  }
  return { records, changed };
}

function productsForRecord(record, products) {
  const dependencies = dependencyPurls(record);
  return [
    ...products
      .filter(product => !dependencies.includes(product))
      .map(product => ({
        '@id': product,
        subcomponents: dependencies.map(dependency => ({ '@id': dependency })),
      })),
    ...dependencies.map(dependency => ({ '@id': dependency })),
  ];
}

function vexCandidate(record, products) {
  const status = mapVexStatus(record);
  return {
    vulnerability: {
      name: record.vulnerability.name,
      ...(record.vulnerability.aliases.length ? { aliases: record.vulnerability.aliases } : {}),
    },
    products: productsForRecord(record, products),
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

function retargetStatement(statement, eligible, products) {
  const notes = statement.status_notes || '';
  if (!notes.startsWith('dependabot-alert:')) return statement;
  const record = eligible.find(item => notes.startsWith(marker(item)));
  if (!record) return statement;
  const status = statement.status === 'under_investigation' ? mapVexStatus(record) : {};
  return {
    ...statement,
    ...status,
    products: productsForRecord(record, products),
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

export function buildVexDocument(runtime, existingVex, records, products) {
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
    '@id': existingVex['@id'] || `${runtime.serverUrl}/${runtime.repository}/blob/${runtime.baseBranch}/${runtime.vexPath}`,
    author: existingVex.author || 'Dependabot VEX generator',
    role: existingVex.role || 'Automated candidate generator',
    timestamp: changed ? new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') : (existingVex.timestamp || new Date().toISOString()),
    version: changed ? (existingVex.version || 0) + 1 : (existingVex.version || 1),
    statements,
  };
  return { changed, newRecords, statements, vex };
}

export function pullRequestDetails(newRecords, skipped, ledgerChanged, vexChanged) {
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

export function readExistingVex(runtime) {
  return readJson(runtime, runtime.vexPath, {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    version: 1,
    statements: [],
  });
}

export function writeVexIfNeeded(runtime, vex, changed) {
  if (changed || fs.existsSync(absolute(runtime, runtime.vexPath))) {
    writeJson(runtime, runtime.vexPath, vex);
  }
}
