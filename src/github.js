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

import { fail } from './runtime.js';

export function createGitHubClient(runtime) {
  async function request(endpoint, options = {}, authToken = runtime.token) {
    const response = await fetch(`${runtime.apiBase}${endpoint}`, {
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

  return request;
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

export async function allDismissedAlerts(request, runtime) {
  const alerts = [];
  let endpoint = `/repos/${runtime.owner}/${runtime.repo}/dependabot/alerts?state=dismissed&per_page=100`;
  while (endpoint) {
    const response = await request(endpoint);
    alerts.push(...(response.body || []));
    endpoint = nextPage(response.headers.get('link'));
  }
  return alerts;
}

export async function reuseExistingCandidateBranch(request, runtime) {
  const { vulnerabilityId, requestedCandidateBranch } = runtime;
  if (requestedCandidateBranch || !vulnerabilityId || vulnerabilityId === '__vex_scope__') return;

  const endpoint = `/repos/${runtime.owner}/${runtime.repo}/pulls?state=open&base=${encodeURIComponent(runtime.baseBranch)}&per_page=100`;
  const response = await request(endpoint);
  const prefix = `${runtime.vulnerabilityBranchPrefix()}-`;
  const candidates = (response.body || [])
    .filter(pullRequest =>
      pullRequest.head?.repo?.full_name === runtime.repository
      && pullRequest.head?.ref?.startsWith(prefix))
    .sort((left, right) => (left.number || 0) - (right.number || 0));
  const existing = candidates[0]?.head?.ref;
  if (existing) {
    runtime.candidateBranch = existing;
    console.log(`Reusing existing Dependabot VEX candidate branch: ${existing}`);
  }
}

export async function annotateSkippedAlerts(request, runtime, alerts) {
  for (const alert of alerts) {
    if (alert.dismissed_reason !== 'no_bandwidth') continue;
    const note = '[dependabot-vex-action] This dismissal is not a security assessment; no VEX statement was generated.';
    const original = alert.dismissed_comment || '';
    if (original.includes(note)) continue;

    const comment = original ? `${original}\n\n${note}` : note;
    await request(`/repos/${runtime.owner}/${runtime.repo}/dependabot/alerts/${alert.number}`, {
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
}
