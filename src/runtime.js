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

export function input(name, fallback = '') {
  const upper = name.toUpperCase();
  return process.env[`INPUT_${upper}`]
    ?? process.env[`INPUT_${upper.replaceAll('-', '_')}`]
    ?? fallback;
}

export function fail(message) {
  const safeMessage = String(message).replaceAll(/[\u0000-\u001F\u007F]/g, ' ');
  console.error(`::error::${safeMessage}`);
  process.exit(1);
}

function safeBranchIdentity(identity) {
  let normalized = '';
  let previousWasHyphen = false;

  for (const character of String(identity)) {
    const code = character.codePointAt(0);
    const allowed = (code >= 48 && code <= 57)
      || (code >= 65 && code <= 90)
      || (code >= 97 && code <= 122)
      || character === '.'
      || character === '_'
      || character === '-';
    const next = allowed ? character : '-';
    if (next === '-' && previousWasHyphen) continue;
    normalized += next;
    previousWasHyphen = next === '-';
  }

  let start = 0;
  let end = normalized.length;
  while (start < end && (normalized[start] === '-' || normalized[start] === '.')) start++;
  while (end > start && (normalized[end - 1] === '-' || normalized[end - 1] === '.')) end--;
  return normalized.slice(start, end).slice(0, 80) || 'scope';
}

export function createRuntime() {
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const repository = process.env.GITHUB_REPOSITORY;
  const token = input('github-token');

  if (!repository) fail('GITHUB_REPOSITORY is required');
  if (!token) fail('github-token input is required');

  const [owner, repo] = repository.split('/');
  const vulnerabilityId = input('vulnerability-id');
  const requestedCandidateBranch = input('candidate-branch');

  const vulnerabilityBranchPrefix = () =>
    `automation/dependabot-vex-${safeBranchIdentity(vulnerabilityId)}`;
  const defaultCandidateBranch = () =>
    `${vulnerabilityBranchPrefix()}-${process.env.GITHUB_RUN_ID || 'local'}`;

  return {
    workspace,
    repository,
    owner,
    repo,
    token,
    apiBase: process.env.GITHUB_API_URL || 'https://api.github.com',
    serverUrl: process.env.GITHUB_SERVER_URL || 'https://github.com',
    baseBranch: input('base-branch', 'main'),
    vexPath: input('vex-path', '.vex/dependabot.openvex.json'),
    ledgerPath: input('dismissal-ledger-path', '.vex/dependabot-dismissals.json'),
    vulnerabilityId,
    requestedCandidateBranch,
    candidateBranch: requestedCandidateBranch || defaultCandidateBranch(),
    githubOutput: process.env.GITHUB_OUTPUT,
    vulnerabilityBranchPrefix,
  };
}

export function output(runtime, name, value) {
  if (!runtime.githubOutput) return;
  const delimiter = `VEX_${name.replaceAll(/\W/g, '_')}_${Date.now()}`;
  fs.appendFileSync(runtime.githubOutput, `${name}<<${delimiter}\n${value ?? ''}\n${delimiter}\n`);
}

export function absolute(runtime, file) {
  return path.resolve(runtime.workspace, file);
}

export function readJson(runtime, file, fallback) {
  const target = absolute(runtime, file);
  if (!fs.existsSync(target)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(target, 'utf8'));
  } catch (error) {
    fail(`Unable to parse ${file}: ${error.message}`);
  }
}

export function writeJson(runtime, file, value) {
  const target = absolute(runtime, file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
}
