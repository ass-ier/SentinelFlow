import { useState } from 'react';
import { useResource } from '../hooks/useResource';
import { api } from '../services/api';
import type { Collection } from '../types';
import { Button, ErrorNotice, Notice, StatusBadge, Table, TextField } from './ui';

interface Credential {
  id: string;
  name: string;
  token_ref: string;
  scopes: string[];
  connector_id: string | null;
  enabled: boolean;
  expires_at: string | null;
}
function CredentialEditor() {
  const resource = useResource<Collection<Credential>>('/integrations/credentials');
  const [name, setName] = useState('');
  const [reference, setReference] = useState('');
  const [connector, setConnector] = useState('');
  const [expiration, setExpiration] = useState('');
  const [scopes, setScopes] = useState<string[]>(['alerts:read']);
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  return (
    <>
      <Notice>
        Generate a separate random token locally, set it in a server variable named
        SENTINEL_INTEGRATION_..., then register only its reference here. Never paste the token.
        Changing the environment value rotates it; revocation and expiry take effect on the next
        request. A blank expiration preserves non-expiring credentials.
      </Notice>
      <ErrorNotice error={resource.error} onRetry={resource.reload} />
      <ErrorNotice error={error} title="Credential change did not complete" />
      <form
        className="integration-form"
        onSubmit={async (event) => {
          event.preventDefault();
          setSaving(true);
          setError(null);
          try {
            await api('/integrations/credentials', {
              method: 'POST',
              body: {
                name,
                token_ref: reference,
                scopes,
                connector_id: connector || null,
                enabled: true,
                expires_at: expiration ? new Date(expiration).toISOString() : null,
              },
            });
            resource.reload();
            setName('');
            setReference('');
            setExpiration('');
          } catch (failure) {
            setError(failure);
          } finally {
            setSaving(false);
          }
        }}
      >
        <div className="integration-fields">
          <TextField
            label="Credential name"
            value={name}
            required
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
          />
          <TextField
            label="Token environment reference"
            value={reference}
            required
            maxLength={101}
            onChange={(e) => setReference(e.target.value)}
          />
          <TextField
            label="Bound Windows connector ID"
            value={connector}
            maxLength={64}
            onChange={(e) => setConnector(e.target.value)}
            hint="Required for windows:ingest; restricts the collector to one source."
          />
          <TextField
            label="Expiration (local time)"
            type="datetime-local"
            value={expiration}
            onChange={(e) => setExpiration(e.target.value)}
            hint="Optional. Stored in UTC; expired credentials cannot call integration APIs."
          />
        </div>
        <fieldset className="integration-profiles">
          <legend>Granted scopes</legend>
          {['alerts:read', 'alerts:notify', 'notifications:test', 'windows:ingest'].map((scope) => (
            <label key={scope}>
              <input
                type="checkbox"
                checked={scopes.includes(scope)}
                onChange={(e) =>
                  setScopes(
                    e.target.checked ? [...scopes, scope] : scopes.filter((item) => item !== scope),
                  )
                }
              />{' '}
              {scope}
            </label>
          ))}
        </fieldset>
        <Button type="submit" disabled={saving || !scopes.length}>
          {saving ? 'Registering...' : 'Register credential reference'}
        </Button>
      </form>
      {!!resource.data?.items.length && (
        <Table caption="Scoped integration credentials">
          <thead>
            <tr>
              <th scope="col">Credential</th>
              <th scope="col">Scopes</th>
              <th scope="col">State</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {resource.data.items.map((credential) => (
              <tr key={credential.id}>
                <td>
                  {credential.name}
                  <span className="cell-secondary mono">{credential.token_ref}</span>
                </td>
                <td>{credential.scopes.join(', ')}</td>
                <td>
                  <StatusBadge
                    status={
                      !credential.enabled
                        ? 'revoked'
                        : credential.expires_at && Date.parse(credential.expires_at) <= Date.now()
                          ? 'expired'
                          : 'enabled'
                    }
                  />
                  <span className="cell-secondary">
                    {credential.expires_at
                      ? `Expires ${new Date(credential.expires_at).toLocaleString()}`
                      : 'No expiration'}
                  </span>
                </td>
                <td>
                  <Button
                    disabled={saving || !credential.enabled}
                    onClick={async () => {
                      setSaving(true);
                      setError(null);
                      try {
                        const { id, ...config } = credential;
                        await api(`/integrations/credentials/${id}`, {
                          method: 'PATCH',
                          body: { ...config, enabled: false },
                        });
                        resource.reload();
                      } catch (failure) {
                        setError(failure);
                      } finally {
                        setSaving(false);
                      }
                    }}
                  >
                    Revoke
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </>
  );
}

export function CredentialSettings() {
  const [open, setOpen] = useState(false);
  return (
    <details className="disclosure" onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary>Scoped integration credentials</summary>
      {open && <CredentialEditor />}
    </details>
  );
}
