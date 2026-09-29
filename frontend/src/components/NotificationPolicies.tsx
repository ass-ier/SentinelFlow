import { useState } from 'react';
import { useResource } from '../hooks/useResource';
import { api } from '../services/api';
import type { Collection } from '../types';
import type { Destination, NotificationPolicy } from '../types/integrations';
import {
  Button,
  EmptyState,
  ErrorNotice,
  LoadingState,
  Panel,
  StatusBadge,
  Table,
  TextField,
} from './ui';

const blank: NotificationPolicy = {
  name: '',
  enabled: true,
  destinations: [],
  severities: [],
  rule_ids: [],
  providers: [],
  mitre_techniques: [],
  hosts: [],
  users: [],
  statuses: ['new'],
  include_replays: false,
};

function PolicyForm({
  initial,
  destinations,
  onSave,
  onCancel,
}: {
  initial: NotificationPolicy;
  destinations: Destination[];
  onSave: () => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState(initial);
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const [filters, setFilters] = useState(
    Object.fromEntries(
      ['severities', 'rule_ids', 'providers', 'mitre_techniques', 'hosts', 'users', 'statuses'].map(
        (key) => [
          key,
          initial[key as keyof NotificationPolicy] instanceof Array
            ? (initial[key as keyof NotificationPolicy] as string[]).join(', ')
            : '',
        ],
      ),
    ),
  );
  return (
    <form
      className="integration-form"
      onSubmit={async (event) => {
        event.preventDefault();
        setSaving(true);
        setError(null);
        try {
          const { id, ...body } = value;
          await api(`/notifications/policies${id ? `/${id}` : ''}`, {
            method: id ? 'PATCH' : 'POST',
            body: {
              ...body,
              ...Object.fromEntries(
                Object.entries(filters).map(([key, text]) => [
                  key,
                  text
                    .split(',')
                    .map((item) => item.trim())
                    .filter(Boolean),
                ]),
              ),
            },
          });
          onSave();
        } catch (failure) {
          setError(failure);
        } finally {
          setSaving(false);
        }
      }}
    >
      <h3>{initial.id ? 'Edit notification policy' : 'Create notification policy'}</h3>
      <TextField
        label="Policy name"
        required
        maxLength={100}
        value={value.name}
        onChange={(e) => setValue({ ...value, name: e.target.value })}
      />
      <fieldset className="integration-profiles">
        <legend>Destinations</legend>
        {destinations.map((destination) => (
          <label key={destination.id}>
            <input
              type="checkbox"
              checked={value.destinations.includes(destination.id)}
              onChange={(e) =>
                setValue({
                  ...value,
                  destinations: e.target.checked
                    ? [...value.destinations, destination.id]
                    : value.destinations.filter((id) => id !== destination.id),
                })
              }
            />{' '}
            {destination.name}
          </label>
        ))}
      </fieldset>
      <p className="form-note">
        Comma-separated exact matches. Empty fields match any value; all populated fields must
        match. Replays are excluded by default.
      </p>
      <div className="integration-fields">
        {Object.entries({
          severities: 'Severities',
          rule_ids: 'Rule IDs',
          providers: 'Source providers',
          mitre_techniques: 'MITRE techniques',
          hosts: 'Hosts',
          users: 'Users',
          statuses: 'Alert statuses',
        }).map(([key, title]) => (
          <TextField
            key={key}
            label={title}
            value={filters[key]}
            maxLength={1500}
            onChange={(e) => setFilters({ ...filters, [key]: e.target.value })}
          />
        ))}
      </div>
      <label className="checkbox-field">
        <input
          type="checkbox"
          checked={value.include_replays}
          onChange={(e) => setValue({ ...value, include_replays: e.target.checked })}
        />{' '}
        Explicitly notify for isolated replays
      </label>
      <ErrorNotice error={error} title="Policy was not saved" />
      <div className="form-actions">
        <Button onClick={onCancel} disabled={saving}>
          Cancel
        </Button>
        <Button type="submit" disabled={saving || !value.destinations.length}>
          {saving ? 'Saving...' : 'Save policy'}
        </Button>
      </div>
    </form>
  );
}
export function NotificationPolicies({
  destinations,
  readOnly,
}: {
  destinations: Destination[];
  readOnly: boolean;
}) {
  const resource = useResource<Collection<NotificationPolicy>>('/notifications/policies');
  const [editing, setEditing] = useState<NotificationPolicy | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  return (
    <Panel
      title="Notification policies"
      description="Routing is separate from detection and alert status. One delivery per alert and destination."
      actions={
        !readOnly && (
          <Button disabled={!destinations.length} onClick={() => setEditing(blank)}>
            Create policy
          </Button>
        )
      }
    >
      <ErrorNotice error={resource.error} onRetry={resource.reload} />
      <ErrorNotice error={error} />
      {resource.loading && <LoadingState label="Loading notification policies" />}
      {resource.data?.items.length ? (
        <Table caption="Notification policies">
          <thead>
            <tr>
              <th scope="col">Policy</th>
              <th scope="col">State</th>
              <th scope="col">Routing</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {resource.data.items.map((policy) => (
              <tr key={policy.id}>
                <td>{policy.name}</td>
                <td>
                  <StatusBadge status={policy.enabled ? 'enabled' : 'disabled'} />
                </td>
                <td>
                  {policy.severities.join(', ') || 'Any severity'}
                  <span className="cell-secondary">
                    {policy.destinations
                      .map(
                        (id) =>
                          destinations.find((item) => item.id === id)?.name ||
                          'Deleted destination',
                      )
                      .join(', ')}
                  </span>
                </td>
                <td>
                  <div className="row-actions">
                    <Button disabled={readOnly || busy} onClick={() => setEditing(policy)}>
                      Edit
                    </Button>
                    <Button
                      disabled={readOnly || busy}
                      onClick={async () => {
                        setBusy(true);
                        setError(null);
                        try {
                          const { id, ...body } = policy;
                          await api(`/notifications/policies/${id}`, {
                            method: 'PATCH',
                            body: { ...body, enabled: !body.enabled },
                          });
                          resource.reload();
                        } catch (failure) {
                          setError(failure);
                        } finally {
                          setBusy(false);
                        }
                      }}
                    >
                      {policy.enabled ? 'Disable' : 'Enable'}
                    </Button>
                    <Button
                      disabled={readOnly || busy}
                      onClick={() => setDeleting(policy.id || null)}
                    >
                      Delete
                    </Button>
                    {deleting === policy.id && (
                      <>
                        <Button
                          variant="danger"
                          disabled={busy}
                          onClick={async () => {
                            setBusy(true);
                            setError(null);
                            try {
                              await api(`/notifications/policies/${policy.id}`, {
                                method: 'DELETE',
                              });
                              setDeleting(null);
                              resource.reload();
                            } catch (failure) {
                              setError(failure);
                            } finally {
                              setBusy(false);
                            }
                          }}
                        >
                          Confirm delete policy
                        </Button>
                        <Button onClick={() => setDeleting(null)}>Keep policy</Button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : !resource.loading && !resource.error ? (
        <EmptyState
          title="No notification policies configured"
          description="Alerts continue to be stored. Configure a destination, then choose which alerts should notify it."
        />
      ) : null}
      {!readOnly && editing && (
        <PolicyForm
          key={editing.id || 'new'}
          initial={editing}
          destinations={destinations}
          onCancel={() => setEditing(null)}
          onSave={() => {
            setEditing(null);
            resource.reload();
          }}
        />
      )}
    </Panel>
  );
}
