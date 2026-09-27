import { useId, useState } from 'react';
import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from 'react';
import {
  AlertCircle,
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  Inbox,
  RefreshCw,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import type { LinkProps } from 'react-router-dom';
import { ApiError, errorMessage } from '../services/api';
import { label, number, pretty, utc } from '../services/format';
import type { Severity } from '../types';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';

export function Button({
  variant = 'secondary',
  className = '',
  type = 'button',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return <button type={type} className={`button button-${variant} ${className}`} {...props} />;
}

export function LinkButton({
  variant = 'secondary',
  className = '',
  ...props
}: LinkProps & { variant?: Variant }) {
  return <Link className={`button button-${variant} ${className}`} {...props} />;
}

export function IconButton({
  label: accessibleLabel,
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <Button
      variant="ghost"
      className={`icon-button ${className}`}
      aria-label={accessibleLabel}
      title={accessibleLabel}
      {...props}
    />
  );
}

interface FieldProps {
  label: string;
  hint?: string;
  error?: string;
}

export function TextField({
  label: fieldLabel,
  hint,
  error,
  id,
  className = '',
  ...props
}: InputHTMLAttributes<HTMLInputElement> & FieldProps) {
  const generated = useId();
  const fieldId = id ?? generated;
  return (
    <div className={`field ${className}`}>
      <label htmlFor={fieldId}>{fieldLabel}</label>
      <input
        id={fieldId}
        aria-describedby={error ? `${fieldId}-error` : hint ? `${fieldId}-hint` : undefined}
        aria-invalid={error ? true : undefined}
        {...props}
      />
      {hint && <small id={`${fieldId}-hint`}>{hint}</small>}
      {error && (
        <small id={`${fieldId}-error`} className="field-error">
          {error}
        </small>
      )}
    </div>
  );
}

export function SelectField({
  label: fieldLabel,
  hint,
  error,
  id,
  className = '',
  children,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement> & FieldProps) {
  const generated = useId();
  const fieldId = id ?? generated;
  return (
    <div className={`field ${className}`}>
      <label htmlFor={fieldId}>{fieldLabel}</label>
      <select
        id={fieldId}
        aria-describedby={error ? `${fieldId}-error` : hint ? `${fieldId}-hint` : undefined}
        aria-invalid={error ? true : undefined}
        {...props}
      >
        {children}
      </select>
      {hint && <small id={`${fieldId}-hint`}>{hint}</small>}
      {error && (
        <small id={`${fieldId}-error`} className="field-error">
          {error}
        </small>
      )}
    </div>
  );
}

export function TextareaField({
  label: fieldLabel,
  hint,
  error,
  id,
  className = '',
  ...props
}: TextareaHTMLAttributes<HTMLTextAreaElement> & FieldProps) {
  const generated = useId();
  const fieldId = id ?? generated;
  return (
    <div className={`field ${className}`}>
      <label htmlFor={fieldId}>{fieldLabel}</label>
      <textarea
        id={fieldId}
        aria-describedby={error ? `${fieldId}-error` : hint ? `${fieldId}-hint` : undefined}
        aria-invalid={error ? true : undefined}
        {...props}
      />
      {hint && <small id={`${fieldId}-hint`}>{hint}</small>}
      {error && (
        <small id={`${fieldId}-error`} className="field-error">
          {error}
        </small>
      )}
    </div>
  );
}

export function PageHeader({
  title,
  description,
  actions,
  breadcrumbs,
}: {
  title: string;
  description: ReactNode;
  actions?: ReactNode;
  breadcrumbs?: ReactNode;
}) {
  return (
    <header className="page-header">
      {breadcrumbs && (
        <nav aria-label="Breadcrumb" className="breadcrumbs">
          {breadcrumbs}
        </nav>
      )}
      <div className="page-heading-row">
        <div>
          <h1 tabIndex={-1}>{title}</h1>
          <p className="page-description">{description}</p>
        </div>
        {actions && <div className="page-actions">{actions}</div>}
      </div>
    </header>
  );
}

export function Panel({
  title,
  description,
  actions,
  children,
  className = '',
}: {
  title?: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  const id = useId();
  return (
    <section className={`panel ${className}`} aria-labelledby={title ? id : undefined}>
      {(title || actions) && (
        <div className="panel-heading">
          <div>
            {title && <h2 id={id}>{title}</h2>}
            {description && <p>{description}</p>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Badge({
  children,
  tone = 'neutral',
}: {
  children: ReactNode;
  tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'info';
}) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge severity severity-${severity}`}>{label(severity)}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  const lower = status.toLowerCase();
  const tone = ['passed', 'pass', 'completed', 'resolved', 'validated', 'success'].includes(lower)
    ? 'success'
    : ['failed', 'fail', 'failure', 'error'].includes(lower)
      ? 'danger'
      : ['running', 'investigating', 'pending', 'observed'].includes(lower)
        ? 'warning'
        : lower === 'new'
          ? 'info'
          : 'neutral';
  const text = lower === 'passed' ? 'PASS' : lower === 'failed' ? 'FAIL' : label(status);
  return <Badge tone={tone}>{text}</Badge>;
}

export function ErrorNotice({
  error,
  onRetry,
  title = 'Something needs attention',
}: {
  error: unknown;
  onRetry?: () => void;
  title?: string;
}) {
  if (!error) return null;
  return (
    <div className="notice notice-error" role="alert">
      <AlertCircle size={18} aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        <p>{errorMessage(error)}</p>
        {error instanceof ApiError && error.requestId && (
          <small className="mono">Request: {error.requestId}</small>
        )}
      </div>
      {onRetry && (
        <Button onClick={onRetry}>
          <RefreshCw size={14} aria-hidden="true" /> Retry
        </Button>
      )}
    </div>
  );
}

export function Notice({
  children,
  tone = 'info',
}: {
  children: ReactNode;
  tone?: 'info' | 'success' | 'warning';
}) {
  return (
    <div className={`notice notice-${tone}`} role={tone === 'success' ? 'status' : undefined}>
      <div>{children}</div>
    </div>
  );
}

export function LoadingState({ label: loadingLabel = 'Loading data' }: { label?: string }) {
  return (
    <div className="loading-state" role="status" aria-live="polite">
      <span>{loadingLabel}…</span>
      <div className="skeleton skeleton-wide" aria-hidden="true" />
      <div className="skeleton" aria-hidden="true" />
      <div className="skeleton skeleton-short" aria-hidden="true" />
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <Inbox size={26} strokeWidth={1.5} aria-hidden="true" />
      <h3>{title}</h3>
      <p>{description}</p>
      {action && <div className="empty-actions">{action}</div>}
    </div>
  );
}

export function Table({
  caption,
  children,
  className = '',
}: {
  caption: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className="table-scroll" role="region" aria-label={`${caption} table`} tabIndex={0}>
      <table className={className}>
        <caption className="sr-only">{caption}</caption>
        {children}
      </table>
    </div>
  );
}

export function Pagination({
  total,
  offset,
  limit,
  onChange,
}: {
  total: number;
  offset: number;
  limit: number;
  onChange: (offset: number, limit: number) => void;
}) {
  return (
    <div className="pagination">
      <span className="muted">
        {total === 0
          ? '0 results'
          : `${number(Math.min(offset + 1, total))}–${number(Math.min(offset + limit, total))} of ${number(total)}`}
      </span>
      <div className="pagination-controls">
        <SelectField
          label="Rows per page"
          className="inline-field"
          value={limit}
          onChange={(event) => onChange(0, Number(event.target.value))}
        >
          {[25, 50, 100].map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </SelectField>
        <IconButton
          label="Previous page"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit), limit)}
        >
          <ChevronLeft size={16} aria-hidden="true" />
        </IconButton>
        <IconButton
          label="Next page"
          disabled={offset + limit >= total}
          onClick={() => onChange(offset + limit, limit)}
        >
          <ChevronRight size={16} aria-hidden="true" />
        </IconButton>
      </div>
    </div>
  );
}

export function Time({ value, short = false }: { value?: string | null; short?: boolean }) {
  return value ? (
    <time className="mono time" dateTime={value} title={`${utc(value)} UTC`}>
      {utc(value, short)}
    </time>
  ) : (
    <span className="muted">—</span>
  );
}

export function CodeBlock({
  value,
  label: codeLabel = 'Evidence',
}: {
  value: unknown;
  label?: string;
}) {
  const text = pretty(value);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedText(text);
      setCopyError(null);
    } catch {
      setCopyError('Clipboard unavailable. Select the text below and copy it directly.');
    }
  }
  return (
    <div className="code-block">
      <div className="code-toolbar">
        <span>{codeLabel}</span>
        <Button variant="ghost" onClick={() => void copy()} aria-label={`Copy ${codeLabel}`}>
          {copiedText === text ? (
            <Check size={13} aria-hidden="true" />
          ) : (
            <Copy size={13} aria-hidden="true" />
          )}
          {copiedText === text ? 'Copied' : 'Copy'}
        </Button>
      </div>
      {copyError && (
        <p role="status" className="copy-error">
          {copyError}
        </p>
      )}
      <pre tabIndex={0} aria-label={codeLabel}>
        <code>{text}</code>
      </pre>
    </div>
  );
}

export function Fact({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div>
      <dt>{term}</dt>
      <dd>{children ?? '—'}</dd>
    </div>
  );
}
