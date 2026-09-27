import { useEffect, useRef, useState } from 'react';
import {
  Activity,
  BookOpenCheck,
  Braces,
  CircleHelp,
  FlaskConical,
  LayoutDashboard,
  ListFilter,
  Menu,
  Play,
  RefreshCw,
  Settings2,
  ShieldCheck,
  Siren,
  SlidersHorizontal,
  X,
} from 'lucide-react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { useWorkspace } from '../hooks/workspace';
import { useResource } from '../hooks/useResource';
import {
  getToken,
  MAX_TOKEN_LENGTH,
  route,
  saveToken,
  TOKEN_PATTERN,
  TOKEN_REQUIREMENTS,
} from '../services/api';
import { label } from '../services/format';
import type { Health } from '../types';
import { Button, ErrorNotice, IconButton, SelectField, TextField } from './ui';

const navigation = [
  {
    group: 'Investigate',
    links: [
      { path: '/', name: 'Overview', icon: LayoutDashboard },
      { path: '/events', name: 'Events', icon: ListFilter },
      { path: '/alerts', name: 'Alerts', icon: Siren },
    ],
  },
  {
    group: 'Engineer',
    links: [
      { path: '/rules', name: 'Detection rules', icon: SlidersHorizontal },
      { path: '/testing', name: 'Detection testing', icon: FlaskConical },
      { path: '/replay', name: 'Replay', icon: Play },
      { path: '/sigma', name: 'Sigma', icon: Braces },
    ],
  },
  {
    group: 'Verify',
    links: [{ path: '/evidence', name: 'Project evidence', icon: BookOpenCheck }],
  },
];

function ConnectionSettings({ authRequired }: { authRequired: boolean }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [token, setToken] = useState('');
  const [error, setError] = useState<unknown>(null);
  const { refresh } = useWorkspace();
  return (
    <>
      <IconButton
        label="Connection settings"
        onClick={() => {
          setToken(getToken());
          setError(null);
          dialog.current?.showModal();
        }}
      >
        <Settings2 size={18} aria-hidden="true" />
      </IconButton>
      <dialog ref={dialog} className="settings-dialog" aria-labelledby="connection-title">
        <div className="dialog-heading">
          <h2 id="connection-title">Connection settings</h2>
          <IconButton label="Close connection settings" onClick={() => dialog.current?.close()}>
            <X size={18} aria-hidden="true" />
          </IconButton>
        </div>
        <p className="muted">
          {authRequired
            ? 'This backend requires a Bearer token.'
            : 'The local backend does not require a token by default.'}{' '}
          Use the token configured by your backend operator.
        </p>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            try {
              saveToken(token);
              refresh();
              dialog.current?.close();
            } catch (failure) {
              setError(failure);
            }
          }}
        >
          <TextField
            label="API token"
            type="password"
            autoComplete="off"
            value={token}
            maxLength={MAX_TOKEN_LENGTH}
            pattern={TOKEN_PATTERN}
            title={TOKEN_REQUIREMENTS}
            onChange={(event) => {
              setToken(event.target.value);
              setError(null);
            }}
            onInvalid={() => setError(new Error(TOKEN_REQUIREMENTS))}
            hint={`${TOKEN_REQUIREMENTS} Stored only in this tab’s session storage. Leave empty to remove the saved token.`}
          />
          <ErrorNotice error={error} />
          <div className="form-actions">
            <Button onClick={() => dialog.current?.close()}>Cancel</Button>
            <Button type="submit" variant="primary">
              Save connection
            </Button>
          </div>
        </form>
      </dialog>
    </>
  );
}

export function Shell() {
  const { runId, runs, runsLoading, runsError, setRunId, refresh, revision } = useWorkspace();
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const previousPath = useRef(location.pathname);
  const health = useResource<Health>('/health', { refreshKey: revision, pollMs: 15000 });
  const selectedRun = runs.find((run) => run.id === runId);

  useEffect(() => {
    setMenuOpen(false);
    if (previousPath.current !== location.pathname) {
      document.querySelector<HTMLElement>('main h1')?.focus({ preventScroll: true });
      previousPath.current = location.pathname;
    }
    const active = navigation
      .flatMap((group) => group.links)
      .find((item) => item.path === location.pathname);
    document.title = `${active?.name ?? 'Investigation'} · SentinelFlow`;
  }, [location.pathname]);

  useEffect(() => {
    if (!menuOpen) return;
    const close = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMenuOpen(false);
    };
    document.addEventListener('keydown', close);
    return () => document.removeEventListener('keydown', close);
  }, [menuOpen]);

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      <header className="topbar">
        <IconButton
          label={menuOpen ? 'Close navigation' : 'Open navigation'}
          className="mobile-menu"
          aria-expanded={menuOpen}
          aria-controls="workspace-navigation"
          onClick={() => setMenuOpen((value) => !value)}
        >
          {menuOpen ? <X size={20} aria-hidden="true" /> : <Menu size={20} aria-hidden="true" />}
        </IconButton>
        <div className="scope-control">
          <SelectField
            label="Run scope"
            value={runId}
            onChange={(event) => setRunId(event.target.value)}
            disabled={runsLoading && !runId}
          >
            <option value="">All runs</option>
            {runId && !selectedRun && <option value={runId}>{runId}</option>}
            {runs.map((run) => (
              <option key={run.id} value={run.id}>
                {run.name} · {label(run.status)} · {run.id.slice(0, 8)}
              </option>
            ))}
          </SelectField>
          <span className="scope-explanation" title={runId || undefined}>
            {runId
              ? 'Events & alerts in one isolated run'
              : 'Events & alerts aggregated across runs'}
          </span>
        </div>
        <div className="connection-status" role="status">
          <span
            className={`connection-dot ${health.data?.status === 'ok' && !health.error ? 'connected' : ''}`}
          />
          {health.loading
            ? 'Connecting'
            : health.error
              ? 'API unavailable'
              : health.data?.status === 'ok'
                ? 'Local API connected'
                : 'Check API'}
        </div>
        <div className="topbar-actions">
          <IconButton label="Refresh workspace data" onClick={refresh}>
            <RefreshCw size={17} aria-hidden="true" />
          </IconButton>
          <ConnectionSettings authRequired={health.data?.auth_required ?? false} />
        </div>
      </header>
      <aside id="workspace-navigation" className={`sidebar ${menuOpen ? 'mobile-open' : ''}`}>
        <Link to={route('/', runId)} className="brand" aria-label="SentinelFlow overview">
          <ShieldCheck size={30} strokeWidth={1.5} aria-hidden="true" />
          <span>
            <strong>SentinelFlow</strong>
            <small>Detection & evidence</small>
          </span>
        </Link>
        <nav aria-label="Workspace navigation">
          {navigation.map(({ group, links }) => (
            <div className="nav-group" key={group}>
              <h2>{group}</h2>
              {links.map(({ path, name, icon: Icon }) => (
                <NavLink
                  key={path}
                  to={route(path, runId)}
                  end={path === '/'}
                  onClick={() => setMenuOpen(false)}
                >
                  <Icon size={17} strokeWidth={1.7} aria-hidden="true" />
                  <span>{name}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div>
            <Activity size={15} aria-hidden="true" />
            <strong>Local workspace</strong>
          </div>
          <p>
            Inspect evidence.
            <br />
            Verify what actually fired.
          </p>
          <span className="sidebar-version">
            v{health.data?.version ?? '0.1.0'} <span>All timestamps UTC</span>
          </span>
        </div>
      </aside>
      <main id="main-content" className="main-content" tabIndex={-1}>
        {!!runsError && (
          <ErrorNotice error={runsError} onRetry={refresh} title="Run list could not be loaded" />
        )}
        <Outlet />
      </main>
      <footer className="workspace-footer">
        <span>
          <CircleHelp size={13} aria-hidden="true" />
          Indicators support investigation; they do not prove compromise.
        </span>
        <Link to={route('/evidence', runId)}>Data provenance & limitations</Link>
      </footer>
    </div>
  );
}
