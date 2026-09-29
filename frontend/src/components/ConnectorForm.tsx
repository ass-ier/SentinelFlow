import { useState } from 'react';
import type {
  Connector,
  ConnectorConfig,
  ConnectorType,
  IntegrationOverview,
} from '../types/integrations';
import { api } from '../services/api';
import { CONNECTOR_NAMES } from '../services/integrations';
import { label } from '../services/format';
import { Button, ErrorNotice, Notice, SelectField, TextField } from './ui';

export function ConnectorForm({
  connector,
  overview,
  onSave,
  onCancel,
}: {
  connector?: Connector;
  overview: IntegrationOverview;
  onSave: () => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState<ConnectorConfig>(
    connector
      ? {
          name: connector.name,
          type: connector.type,
          mode: connector.mode,
          enabled: connector.enabled,
          tenant_id: connector.tenant_id,
          client_id: connector.client_id,
          workspace_id: connector.workspace_id,
          secret_ref: connector.secret_ref,
          profiles: connector.profiles,
          overlap_seconds: connector.overlap_seconds,
          lookback_seconds: connector.lookback_seconds,
          page_size: connector.page_size,
          max_pages: connector.max_pages,
        }
      : {
          name: '',
          type: 'microsoft_sentinel',
          mode: 'live',
          enabled: false,
          tenant_id: null,
          client_id: null,
          workspace_id: null,
          secret_ref: 'SENTINEL_CLIENT_SECRET',
          profiles: [{ id: 'signin_logs', enabled: true, interval_seconds: 60 }],
          overlap_seconds: 120,
          lookback_seconds: 900,
          page_size: 200,
          max_pages: 5,
        },
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const profiles = value.type === 'windows_wef' ? [] : overview.profiles[value.type];
  function patch(change: Partial<ConnectorConfig>) {
    setValue((previous) => ({ ...previous, ...change }));
  }
  return (
    <form
      className="integration-form"
      onSubmit={async (event) => {
        event.preventDefault();
        setSaving(true);
        setError(null);
        try {
          await api(
            `/integrations/connectors${connector ? `/${encodeURIComponent(connector.id)}` : ''}`,
            {
              method: connector ? 'PATCH' : 'POST',
              body: value,
            },
          );
          onSave();
        } catch (failure) {
          setError(failure);
        } finally {
          setSaving(false);
        }
      }}
    >
      <h2>{connector ? 'Edit connector' : 'Configure connector'}</h2>
      <Notice>
        Enter server-side environment variable names, never secret values. Live polling also
        requires the corresponding server enable flag.
      </Notice>
      <div className="integration-fields">
        <TextField
          label="Connector name"
          value={value.name}
          maxLength={100}
          required
          onChange={(e) => patch({ name: e.target.value })}
        />
        <SelectField
          label="Telemetry provider"
          value={value.type}
          disabled={!!connector?.run_id}
          onChange={(e) => {
            const type = e.target.value as ConnectorType;
            patch({
              type,
              profiles:
                type === 'windows_wef'
                  ? []
                  : [
                      {
                        id: type === 'microsoft_sentinel' ? 'signin_logs' : 'signins',
                        enabled: true,
                        interval_seconds: 60,
                      },
                    ],
              secret_ref:
                type === 'windows_wef'
                  ? null
                  : type === 'microsoft_sentinel'
                    ? 'SENTINEL_CLIENT_SECRET'
                    : 'GRAPH_CLIENT_SECRET',
            });
          }}
        >
          {Object.entries(CONNECTOR_NAMES).map(([key, name]) => (
            <option key={key} value={key}>
              {name}
            </option>
          ))}
        </SelectField>
        <SelectField
          label="Connector mode"
          value={value.mode}
          disabled={!!connector?.run_id}
          onChange={(e) => patch({ mode: e.target.value as 'live' | 'demo' })}
        >
          <option value="live">Live API (disabled until configured)</option>
          <option value="demo">Demo / local mock only</option>
        </SelectField>
        {value.type !== 'windows_wef' && value.mode === 'live' && (
          <>
            <TextField
              label="Tenant ID"
              value={value.tenant_id || ''}
              onChange={(e) => patch({ tenant_id: e.target.value || null })}
            />
            <TextField
              label="Client ID"
              value={value.client_id || ''}
              onChange={(e) => patch({ client_id: e.target.value || null })}
            />
            {value.type === 'microsoft_sentinel' && (
              <TextField
                label="Workspace ID"
                value={value.workspace_id || ''}
                onChange={(e) => patch({ workspace_id: e.target.value || null })}
              />
            )}
            <TextField
              label="Client secret environment reference"
              value={value.secret_ref || ''}
              maxLength={101}
              onChange={(e) => patch({ secret_ref: e.target.value || null })}
            />
          </>
        )}
        <TextField
          label="Overlap (seconds)"
          type="number"
          min={0}
          max={3600}
          value={value.overlap_seconds}
          onChange={(e) => patch({ overlap_seconds: Number(e.target.value) })}
        />
        <TextField
          label="Initial lookback (seconds)"
          type="number"
          min={60}
          max={86400}
          value={value.lookback_seconds}
          onChange={(e) => patch({ lookback_seconds: Number(e.target.value) })}
        />
        <TextField
          label="Rows per page"
          type="number"
          min={1}
          max={500}
          value={value.page_size}
          onChange={(e) => patch({ page_size: Number(e.target.value) })}
        />
        <TextField
          label="Pages per poll"
          type="number"
          min={1}
          max={10}
          value={value.max_pages}
          onChange={(e) => patch({ max_pages: Number(e.target.value) })}
        />
      </div>
      {profiles.length > 0 && (
        <fieldset className="integration-profiles">
          <legend>Query profiles</legend>
          {profiles.map((profile) => {
            const selected = value.profiles.find((item) => item.id === profile.id);
            return (
              <div key={profile.id} className="profile-option">
                <label>
                  <input
                    type="checkbox"
                    checked={!!selected?.enabled}
                    onChange={(e) => {
                      patch({
                        profiles: [
                          ...value.profiles.filter((item) => item.id !== profile.id),
                          {
                            id: profile.id,
                            enabled: e.target.checked,
                            interval_seconds: selected?.interval_seconds ?? 60,
                          },
                        ],
                      });
                    }}
                  />{' '}
                  {label(profile.id)} <span className="muted">({profile.table})</span>
                </label>
                {selected?.enabled && (
                  <TextField
                    label={`${profile.table} poll interval (seconds)`}
                    type="number"
                    min={30}
                    max={86400}
                    value={selected.interval_seconds}
                    onChange={(e) =>
                      patch({
                        profiles: value.profiles.map((item) =>
                          item.id === profile.id
                            ? { ...item, interval_seconds: Number(e.target.value) }
                            : item,
                        ),
                      })
                    }
                  />
                )}
              </div>
            );
          })}
        </fieldset>
      )}
      {value.type === 'windows_wef' && (
        <Notice>
          Install the Windows collector on the WEC host. This connector receives authenticated
          batches; it never connects to a domain controller.
        </Notice>
      )}
      <ErrorNotice error={error} title="Connector was not saved" />
      <div className="form-actions">
        <Button onClick={onCancel} disabled={saving}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={saving}>
          {saving ? 'Saving...' : 'Save connector'}
        </Button>
      </div>
    </form>
  );
}
