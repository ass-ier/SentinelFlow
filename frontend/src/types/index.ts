import type { Delivery } from './integrations';

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type AlertStatus = 'new' | 'investigating' | 'resolved' | 'false_positive' | 'suppressed';
export type RunStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ReplaySpeed = 'instant' | 'realtime' | '10x';
export type InputFormat = 'json' | 'jsonl' | 'csv' | 'syslog' | 'windows' | 'wazuh';
export type JsonObject = Record<string, unknown>;

export interface NormalizedEvent {
  storage_id: string;
  run_id: string;
  event: {
    id: string;
    timestamp: string;
    source: string;
    category:
      | 'authentication'
      | 'process'
      | 'network'
      | 'identity'
      | 'file'
      | 'system'
      | 'application';
    type: string;
    action: string;
    outcome: 'success' | 'failure' | 'unknown';
    severity: Severity;
  };
  host: { name: string | null; ip: string | null };
  user: { name: string | null };
  source: { ip: string | null; port: number | null };
  destination: { ip: string | null; port: number | null };
  process: {
    name: string | null;
    executable: string | null;
    command_line: string | null;
    pid: number | null;
    parent: { name: string | null; executable: string | null; pid: number | null };
  };
  network: { protocol: string | null };
  dns: { query: string | null };
  file: { path: string | null };
  raw_event: JsonObject | string;
  metadata: JsonObject;
}

export type InlineEvent = Omit<NormalizedEvent, 'storage_id' | 'run_id'>;

export interface Provenance {
  kind: string;
  author?: string | null;
  source_url?: string | null;
  license?: string | null;
  license_url?: string | null;
  upstream_id?: string | null;
  status?: string | null;
  logsource?: JsonObject;
  tags?: string[];
  references?: string[];
  original_yaml?: string | null;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  enabled: boolean;
  conditions: JsonObject | unknown[];
  threshold: { count: number; window_seconds: number };
  group_by: string[];
  suppression_seconds: number;
  branches: JsonObject[];
  mitre_attack: string[];
  false_positives: string[];
  provenance: Provenance;
  yaml: string;
  updated_at: string;
}

export type RuleSnapshot = Omit<Rule, 'yaml' | 'updated_at'> &
  Partial<Pick<Rule, 'yaml' | 'updated_at'>>;

export interface Alert {
  id: string;
  run_id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  status: AlertStatus;
  created_at: string;
  first_seen: string;
  last_seen: string;
  triggered_at: string;
  event_count: number;
  source_entities: { ips: string[] };
  affected_entities: { hosts: string[]; users: string[]; destination_ips: string[] };
  mitre_attack: string[];
  description: string;
  branch: string;
  group: JsonObject;
  provenance: Provenance;
}

export interface AlertDetail extends Alert {
  evidence: NormalizedEvent[];
  rule_snapshot: RuleSnapshot;
  evidence_ids: string[];
  telemetry_sources?: {
    provider: string;
    connector_id: string | null;
    source_table: string | null;
    source_channel: string | null;
    source_host: string | null;
  }[];
  notifications?: Delivery[];
}

export interface ValidationAlert extends Alert {
  evidence: InlineEvent[];
}

export interface Run {
  id: string;
  name: string;
  kind: string;
  dataset_id: string | null;
  status: RunStatus;
  created_at: string;
  completed_at: string | null;
  total_events: number;
  processed_events: number;
  duplicate_events: number;
  alerts_created: number;
  speed: ReplaySpeed;
  error: string | null;
  watermark: string | null;
  metrics: JsonObject;
  rules_count: number;
}

export interface Expected {
  rule_id: string;
  severity: Severity;
  event_count: number | null;
  branch: string;
}

export interface Dataset {
  id: string;
  path: string;
  name: string;
  format: InputFormat;
  event_count: number;
  expected: Expected[];
  kind:
    | 'positive'
    | 'benign'
    | 'boundary'
    | 'regression'
    | 'mixed'
    | 'policy'
    | 'parser'
    | 'public'
    | 'sigma';
  synthetic: boolean;
  source: string;
  license: string;
  sha256: string;
}

export interface Collection<T> {
  items: T[];
  total: number;
}

export interface Paginated<T> extends Collection<T> {
  offset: number;
  limit: number;
}

export interface Dashboard {
  events_processed: number;
  active_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  total_alerts: number;
  detection_rules: number;
  enabled_rules: number;
  runs: number;
  timeline: { timestamp: string; events: number; alerts: number }[];
  top_sources: { ip: string; count: number }[];
  top_rules: { rule_id: string; name: string; count: number }[];
  mitre: { id: string; name: string; count: number; rules: string[] }[];
  recent_alerts: Alert[];
}

export interface IngestResult {
  run: Run;
  events_processed: number;
  events_stored: number;
  duplicates_ignored: number;
  detections_triggered: number;
  alerts_created: number;
}

export interface ValidationResult {
  test_id: string;
  name: string;
  dataset_id: string;
  kind: string;
  status: 'passed' | 'failed' | 'observed';
  expected: Expected[] | null;
  actual: Expected[];
  events_processed: number;
  duplicates_ignored: number;
  duration_seconds: number;
  errors: string[];
  alerts: ValidationAlert[];
  metrics: JsonObject;
}

export interface ValidationReport {
  status: 'passed' | 'failed' | 'observed';
  passed: number;
  failed: number;
  total: number;
  benign_passed: number;
  benign_total: number;
  duration_seconds: number;
  scope: string;
  results: ValidationResult[];
}

export interface SigmaSample {
  id: string;
  name: string;
  author: string;
  source_url: string;
  license: string;
  license_url: string;
  yaml: string;
  dataset_id: string;
  negative_dataset_id: string;
  expected_alerts: number;
}

export interface TestCounts {
  passed: number;
  failed: number;
  total: number;
  skipped?: number;
}

export interface ValidationArtifact extends JsonObject {
  status: 'validated' | 'failed' | 'stale' | 'running';
  is_current: boolean;
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  total_tests_passed?: number;
  backend?: TestCounts & {
    coverage_percent?: number;
    categories?: Record<string, TestCounts>;
  };
  frontend?: TestCounts;
  detections?: TestCounts & { benign_passed: number; benign_total: number };
  steps: {
    name: string;
    command: string | string[];
    status: string;
    exit_code: number;
    duration_seconds: number;
  }[];
  source_fingerprint: string;
  error?: string;
}

export interface BenchmarkArtifact extends JsonObject {
  status: 'passed' | 'failed' | 'stale';
  is_current: boolean;
  events_processed: number;
  events_per_second: number;
  detection_seconds: number;
  alerts_generated: number;
  rules_evaluated: number;
  active_rules: number;
  measured_at: string;
  scope: string;
}

export interface ProjectEvidence {
  validation: ValidationArtifact | null;
  benchmark: BenchmarkArtifact | null;
  validation_log: string;
  validation_running: boolean;
  files: { path: string; bytes: number }[];
  documents: { path: string; title: string }[];
}

export interface Health {
  status: string;
  version: string;
  auth_required: boolean;
  public_demo?: boolean;
  public_demo_run_limit?: number | null;
}
