import { useState } from 'react';
import { api } from '../services/api';
import type { Destination, DestinationConfig } from '../types/integrations';
import { Button, ErrorNotice, Notice, SelectField, TextField } from './ui';

export function DestinationForm({
  destination,
  onSave,
  onCancel,
}: {
  destination?: Destination;
  onSave: () => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState<DestinationConfig>(
    destination
      ? {
          name: destination.name,
          type: destination.type,
          mode: destination.mode,
          enabled: destination.enabled,
          url_ref: destination.url_ref,
          authentication: destination.authentication,
          auth_ref: destination.auth_ref,
          timeout_seconds: destination.timeout_seconds,
          max_attempts: destination.max_attempts,
          retry_seconds: destination.retry_seconds,
        }
      : {
          name: '',
          type: 'power_automate',
          mode: 'live',
          enabled: false,
          url_ref: '',
          authentication: 'none',
          auth_ref: null,
          timeout_seconds: 5,
          max_attempts: 3,
          retry_seconds: 5,
        },
  );
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const patch = (change: Partial<DestinationConfig>) =>
    setValue((previous) => ({ ...previous, ...change }));
  return (
    <form
      className="integration-form"
      onSubmit={async (event) => {
        event.preventDefault();
        setSaving(true);
        setError(null);
        try {
          await api(`/notifications/destinations${destination ? `/${destination.id}` : ''}`, {
            method: destination ? 'PATCH' : 'POST',
            body: value,
          });
          onSave();
        } catch (failure) {
          setError(failure);
        } finally {
          setSaving(false);
        }
      }}
    >
      <h2>{destination ? 'Edit destination' : 'New notification destination'}</h2>
      <Notice>
        Keep the full Flow URL and authentication secrets in server environment variables. Enter
        only their names here. Live delivery requires NOTIFICATIONS_ENABLED=true.
      </Notice>
      <div className="integration-fields">
        <TextField
          label="Destination name"
          required
          maxLength={100}
          value={value.name}
          onChange={(e) => patch({ name: e.target.value })}
        />
        <SelectField
          label="Destination type"
          value={value.type}
          disabled={!!destination}
          onChange={(e) => patch({ type: e.target.value as DestinationConfig['type'] })}
        >
          <option value="power_automate">Power Automate / Teams workflow</option>
          <option value="webhook">Generic webhook</option>
        </SelectField>
        <SelectField
          label="Delivery mode"
          value={value.mode}
          disabled={!!destination}
          onChange={(e) =>
            patch({
              mode: e.target.value as 'live' | 'demo',
              url_ref: null,
              authentication: 'none',
              auth_ref: null,
            })
          }
        >
          <option value="live">Live HTTPS endpoint</option>
          <option value="demo">Mock / loopback HTTP receiver</option>
        </SelectField>
        {value.mode === 'live' && (
          <>
            <TextField
              label="URL environment reference"
              required
              value={value.url_ref || ''}
              maxLength={101}
              placeholder="SENTINEL_INTEGRATION_FLOW_URL"
              onChange={(e) => patch({ url_ref: e.target.value })}
            />
            <SelectField
              label="Webhook authentication"
              value={value.authentication}
              onChange={(e) =>
                patch({ authentication: e.target.value as DestinationConfig['authentication'] })
              }
            >
              <option value="none">None (Flow trigger URL authentication)</option>
              <option value="bearer">Bearer token</option>
              <option value="hmac">HMAC-SHA256 with timestamp</option>
            </SelectField>
            {value.authentication !== 'none' && (
              <TextField
                label="Authentication environment reference"
                required
                value={value.auth_ref || ''}
                maxLength={101}
                onChange={(e) => patch({ auth_ref: e.target.value })}
              />
            )}
          </>
        )}
        <TextField
          label="Timeout (seconds)"
          type="number"
          min={1}
          max={15}
          value={value.timeout_seconds}
          onChange={(e) => patch({ timeout_seconds: Number(e.target.value) })}
        />
        <TextField
          label="Maximum attempts"
          type="number"
          min={1}
          max={5}
          value={value.max_attempts}
          onChange={(e) => patch({ max_attempts: Number(e.target.value) })}
        />
        <TextField
          label="Initial retry delay (seconds)"
          type="number"
          min={1}
          max={300}
          value={value.retry_seconds}
          onChange={(e) => patch({ retry_seconds: Number(e.target.value) })}
        />
      </div>
      <ErrorNotice error={error} title="Destination was not saved" />
      <div className="form-actions">
        <Button onClick={onCancel} disabled={saving}>
          Cancel
        </Button>
        <Button variant="primary" type="submit" disabled={saving}>
          {saving ? 'Saving...' : 'Save destination'}
        </Button>
      </div>
    </form>
  );
}
