import type {
  Alert,
  AlertDetail,
  Dashboard,
  Dataset,
  InlineEvent,
  NormalizedEvent,
  Rule,
  Run,
  SigmaSample,
  ValidationReport,
} from '../src/types';

export const rule: Rule = {
  id: 'AUTH-001',
  name: 'Brute force authentication',
  description:
    'Repeated failures require investigation; this indicator is not proof of compromise.',
  severity: 'high',
  enabled: true,
  conditions: { all: [{ field: 'event.outcome', operator: 'equals', value: 'failure' }] },
  threshold: { count: 2, window_seconds: 300 },
  group_by: ['source.ip'],
  suppression_seconds: 60,
  branches: [],
  mitre_attack: ['T1110'],
  false_positives: ['A legitimate user may mistype a password.'],
  provenance: { kind: 'bundled', author: 'Fixture Author', license: 'Test fixture' },
  yaml: 'id: AUTH-001\nname: Brute force authentication\nthreshold:\n  count: 2',
  updated_at: '2026-01-15T10:00:00Z',
};

export const event: NormalizedEvent = {
  storage_id: 'storage-event-1',
  run_id: 'run-1',
  event: {
    id: 'fixture-event-1',
    timestamp: '2026-01-15T10:00:00Z',
    source: 'fixture',
    category: 'authentication',
    type: 'start',
    action: 'login',
    outcome: 'failure',
    severity: 'informational',
  },
  host: { name: 'fixture-host', ip: '10.10.1.2' },
  user: { name: 'fixture-user' },
  source: { ip: '192.0.2.7', port: 51500 },
  destination: { ip: '10.10.1.2', port: 22 },
  process: {
    name: null,
    executable: null,
    command_line: null,
    pid: null,
    parent: { name: null, executable: null, pid: null },
  },
  network: { protocol: 'tcp' },
  dns: { query: null },
  file: { path: null },
  raw_event: {
    message: '<img src=x onerror="window.logExecuted=true">',
    value: 'raw fixture input',
  },
  metadata: { synthetic: true },
};

export const secondEvent: NormalizedEvent = {
  ...event,
  storage_id: 'storage-event-2',
  event: { ...event.event, id: 'fixture-event-2', timestamp: '2026-01-15T10:00:30Z' },
};

export const inlineEvent: InlineEvent = {
  event: event.event,
  host: event.host,
  user: event.user,
  source: event.source,
  destination: event.destination,
  process: event.process,
  network: event.network,
  dns: event.dns,
  file: event.file,
  raw_event: event.raw_event,
  metadata: event.metadata,
};

export const alert: Alert = {
  id: 'alert-1',
  run_id: 'run-1',
  rule_id: rule.id,
  rule_name: rule.name,
  severity: 'high',
  status: 'new',
  created_at: '2026-01-15T10:00:31Z',
  first_seen: event.event.timestamp,
  last_seen: secondEvent.event.timestamp,
  triggered_at: secondEvent.event.timestamp,
  event_count: 2,
  source_entities: { ips: ['192.0.2.7'] },
  affected_entities: {
    hosts: ['fixture-host'],
    users: ['fixture-user'],
    destination_ips: ['10.10.1.2'],
  },
  mitre_attack: ['T1110'],
  description: rule.description,
  branch: 'source-threshold',
  group: { 'source.ip': '192.0.2.7' },
  provenance: rule.provenance,
};

export const alertDetail: AlertDetail = {
  ...alert,
  evidence: [event, secondEvent],
  evidence_ids: [event.storage_id, secondEvent.storage_id],
  rule_snapshot: rule,
};

export const run: Run = {
  id: 'run-1',
  name: 'Fixture replay',
  kind: 'replay',
  dataset_id: 'positive-fixture',
  status: 'completed',
  created_at: '2026-01-15T11:00:00Z',
  completed_at: '2026-01-15T11:00:01Z',
  total_events: 2,
  processed_events: 2,
  duplicate_events: 0,
  alerts_created: 1,
  speed: 'instant',
  error: null,
  watermark: secondEvent.event.timestamp,
  metrics: { events_per_second: 123.45, elapsed_seconds: 0.0162 },
  rules_count: 1,
};

export const dataset: Dataset = {
  id: 'positive-fixture',
  path: 'test-data/authentication/fixture.jsonl',
  name: 'Authentication positive fixture',
  format: 'jsonl',
  event_count: 2,
  expected: [{ rule_id: rule.id, severity: 'high', event_count: 2, branch: 'source-threshold' }],
  kind: 'positive',
  synthetic: true,
  source: 'Generated unit-test fixture',
  license: 'Test fixture',
  sha256: '0'.repeat(64),
};

export const benignDataset: Dataset = {
  ...dataset,
  id: 'benign-fixture',
  path: 'test-data/benign/fixture.jsonl',
  name: 'Benign authentication fixture',
  expected: [],
  kind: 'benign',
};

export const dashboard: Dashboard = {
  events_processed: 27,
  active_alerts: 3,
  critical_alerts: 1,
  high_alerts: 2,
  total_alerts: 5,
  detection_rules: 7,
  enabled_rules: 6,
  runs: 2,
  timeline: [
    { timestamp: '2026-01-15T10:00:00Z', events: 12, alerts: 1 },
    { timestamp: '2026-01-15T10:01:00Z', events: 15, alerts: 4 },
  ],
  top_sources: [{ ip: '192.0.2.7', count: 19 }],
  top_rules: [{ rule_id: rule.id, name: rule.name, count: 4 }],
  mitre: [{ id: 'T1110', name: 'Brute Force', count: 4, rules: [rule.id] }],
  recent_alerts: [alert],
};

export const emptyDashboard: Dashboard = {
  ...dashboard,
  events_processed: 0,
  active_alerts: 0,
  critical_alerts: 0,
  high_alerts: 0,
  total_alerts: 0,
  runs: 0,
  timeline: [],
  top_sources: [],
  top_rules: [],
  mitre: [],
  recent_alerts: [],
};

export const passedReport: ValidationReport = {
  status: 'passed',
  passed: 1,
  failed: 0,
  total: 1,
  benign_passed: 0,
  benign_total: 0,
  duration_seconds: 0.034,
  scope: 'bundled',
  results: [
    {
      test_id: 'AUTH-POSITIVE',
      name: 'Included brute-force scenario',
      dataset_id: dataset.id,
      kind: 'positive',
      status: 'passed',
      expected: dataset.expected,
      actual: dataset.expected,
      events_processed: 2,
      duplicates_ignored: 0,
      duration_seconds: 0.034,
      errors: [],
      alerts: [
        {
          ...alert,
          id: 'validation-alert-1',
          run_id: 'validation:positive-fixture',
          evidence: [inlineEvent, { ...inlineEvent, event: secondEvent.event }],
        },
      ],
      metrics: { rules_evaluated: 1 },
    },
  ],
};

export const failedReport: ValidationReport = {
  ...passedReport,
  status: 'failed',
  passed: 0,
  failed: 1,
  results: [
    {
      ...passedReport.results[0],
      status: 'failed',
      actual: [],
      alerts: [],
      errors: ['Expected 1 alert; observed 0.'],
    },
  ],
};

export const observedReport: ValidationReport = {
  ...passedReport,
  status: 'observed',
  passed: 0,
  results: [{ ...passedReport.results[0], status: 'observed', expected: null, errors: [] }],
};

export const benignReport: ValidationReport = {
  ...passedReport,
  benign_passed: 1,
  benign_total: 1,
  results: [
    {
      ...passedReport.results[0],
      test_id: 'AUTH-BENIGN',
      name: 'Controlled benign fixture',
      kind: 'benign',
      dataset_id: benignDataset.id,
      expected: [],
      actual: [],
      alerts: [],
    },
  ],
};

export const sigmaRule: Rule = {
  ...rule,
  id: 'sigma-unit-fixture',
  name: 'Sigma unit-test process indicator',
  enabled: false,
  provenance: {
    kind: 'sigma',
    author: 'Sigma Fixture Author',
    source_url: 'https://example.test/rules/unit-fixture.yml',
    license: 'Test fixture',
    license_url: 'https://example.test/test-license',
    upstream_id: 'sigma-unit-fixture',
  },
};

export const sigmaSample: SigmaSample = {
  id: 'sigma-unit-fixture',
  name: 'Sigma unit-test process indicator',
  author: 'Sigma Fixture Author',
  source_url: 'https://example.test/rules/unit-fixture.yml',
  license: 'Test fixture',
  license_url: 'https://example.test/test-license',
  yaml: 'title: Sigma unit-test process indicator\nid: sigma-unit-fixture\nauthor: Sigma Fixture Author\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: fixture.exe\n  condition: selection',
  dataset_id: dataset.id,
  negative_dataset_id: benignDataset.id,
  expected_alerts: 1,
};
