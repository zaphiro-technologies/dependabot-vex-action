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

import {
  allDismissedAlerts,
  annotateSkippedAlerts,
  createGitHubClient,
  reuseExistingCandidateBranch,
} from './github.js';
import { createRuntime, fail, output } from './runtime.js';
import { normalizeAlert, matchesVulnerability } from './dependabot.js';
import { productPurls } from './products.js';
import {
  buildVexDocument,
  loadLedger,
  pullRequestDetails,
  readExistingVex,
  writeVexIfNeeded,
} from './vex.js';

async function main() {
  const runtime = createRuntime();
  const request = createGitHubClient(runtime);
  const products = productPurls(runtime);
  if (!products.length) fail('product-purls must contain at least one non-empty PURL');

  await reuseExistingCandidateBranch(request, runtime);

  // Gather alerts, then normalize their dependency and advisory details.
  const alerts = await allDismissedAlerts(request, runtime);
  const normalized = alerts.map(alert => normalizeAlert(runtime, alert));
  const skipped = normalized.filter(record =>
    record.dismissed_reason === 'no_bandwidth' && matchesVulnerability(runtime, record));
  await annotateSkippedAlerts(request, runtime, alerts);

  // Merge alert history into the ledger and reconcile matching statements in OpenVEX.
  const { records, changed: ledgerChanged } = loadLedger(runtime, normalized);
  const existingVex = readExistingVex(runtime);
  const { changed: vexChanged, newRecords, statements, vex } =
    buildVexDocument(runtime, existingVex, records, products);
  writeVexIfNeeded(runtime, vex, vexChanged);

  const changed = ledgerChanged || vexChanged;
  const { body, title, vulnerabilityCodes } =
    pullRequestDetails(newRecords, skipped, ledgerChanged, vexChanged);
  writeOutputs(runtime, {
    changed,
    vexChanged,
    title,
    body,
    vulnerabilityCodes,
    skipped,
    ledgerChanged,
  });

  console.log(`Currently dismissed Dependabot alerts: ${alerts.length}`);
  console.log(`Historical dismissal records: ${records.length}`);
  console.log(`Generated or retained VEX statements: ${statements.length}`);
  if (!changed) console.log('No VEX document changes required');
}

function writeOutputs(runtime, {
  changed,
  vexChanged,
  title,
  body,
  vulnerabilityCodes,
  skipped,
  ledgerChanged,
}) {
  output(runtime, 'changed', changed ? 'true' : 'false');
  output(runtime, 'vex-changed', vexChanged ? 'true' : 'false');
  output(runtime, 'candidate-branch', runtime.candidateBranch);
  output(runtime, 'pull-request-title', title);
  output(runtime, 'pull-request-body', body);
  output(runtime, 'vulnerability-codes', vulnerabilityCodes.join(', ') || (ledgerChanged ? 'ledger update' : 'scope update'));

  // An empty ID list means no CVE-specific candidate; scope changes use the sentinel.
  output(runtime, 'vulnerability-ids', JSON.stringify(
    vulnerabilityCodes.length || !changed ? vulnerabilityCodes : ['__vex_scope__'],
  ));
  output(runtime, 'skipped-alerts', skipped.map(record => record.alert).join(', '));
}

try {
  await main();
} catch (error) {
  fail(error.stack || error.message || String(error));
}
