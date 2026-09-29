import type { AlertStatus, JsonObject, Severity } from './index';

export type ConnectorType = 'microsoft_sentinel' | 'microsoft_graph' | 'windows_wef';
export interface QueryProfile {
  id: string;
  table: string;
  timestamp: string;
  normalizer: string;
}
export interface ConnectorConfig {
  name: string;
  type: ConnectorType;
  mode: 'live' | 'demo';
  enabled: boolean;
  tenant_id: string | null;
  client_id: string | null;
  workspace_id: string | null;
  secret_ref: string | null;
  profiles: { id: string; enabled: boolean; interval_seconds: number }[];
  overlap_seconds: number;
  lookback_seconds: number;
  page_size: number;
  max_pages: number;
}
export interface Connector extends ConnectorConfig {
  id: string;
  status: string;
  last_success: string | null;
  last_failure: string | null;
  last_error: string | null;
  last_event_time: string | null;
  events_received: number;
  events_processed: number;
  events_failed: number;
  duplicate_events: number;
  retry_count: number;
  run_id: string | null;
}
export interface IntegrationOverview {
  connectors: Connector[];
  notifications: Record<string, number>;
  external_enabled: boolean;
  notifications_enabled: boolean;
  public_demo: boolean;
  worker: { running: boolean; enabled: boolean; last_error: string | null };
  profiles: Record<'microsoft_sentinel' | 'microsoft_graph', QueryProfile[]>;
}
export interface DestinationConfig {
  name: string;
  type: 'power_automate' | 'webhook';
  mode: 'live' | 'demo';
  enabled: boolean;
  url_ref: string | null;
  authentication: 'none' | 'bearer' | 'hmac';
  auth_ref: string | null;
  timeout_seconds: number;
  max_attempts: number;
  retry_seconds: number;
}
export interface Destination extends DestinationConfig {
  id: string;
  health: string;
  last_delivery: Delivery | null;
  failure_count: number;
}
export interface Delivery {
  id: string;
  idempotency_key: string;
  alert_id: string | null;
  destination_id: string;
  status: 'pending' | 'processing' | 'delivered' | 'failed' | 'suppressed' | 'dead_letter';
  attempt_count: number;
  created_at: string;
  last_attempt_at: string | null;
  delivered_at: string | null;
  http_status: number | null;
  error: string | null;
  next_attempt_at: number | null;
  mock: boolean;
  event: 'security_alert' | 'notification_test';
}
export interface DeliveryDetail extends Delivery {
  payload: JsonObject;
  attempts: {
    number: number;
    timestamp: string;
    http_status: number | null;
    error: string | null;
  }[];
}
export interface NotificationPolicy {
  id?: string;
  name: string;
  enabled: boolean;
  destinations: string[];
  severities: Severity[];
  rule_ids: string[];
  providers: string[];
  mitre_techniques: string[];
  hosts: string[];
  users: string[];
  statuses: AlertStatus[];
  include_replays: boolean;
}
export interface DemoResult {
  mode: 'demo';
  connector_id: string;
  run_id: string;
  events_processed: number;
  status: string;
  deliveries: Delivery[];
  live_tested: false;
}
