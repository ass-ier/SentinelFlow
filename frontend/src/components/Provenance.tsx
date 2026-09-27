import { ExternalLink } from 'lucide-react';
import { label, safeUrl } from '../services/format';
import type { Provenance as ProvenanceType } from '../types';
import { Fact } from './ui';

export function ExternalLinkSafe({
  href,
  children,
}: {
  href?: string | null;
  children: React.ReactNode;
}) {
  const safe = safeUrl(href);
  return safe ? (
    <a href={safe} target="_blank" rel="noopener noreferrer" className="external-link">
      {children}
      <ExternalLink size={12} aria-hidden="true" />
    </a>
  ) : (
    <span>{children}</span>
  );
}

export function Provenance({ value }: { value: ProvenanceType }) {
  return (
    <dl className="facts provenance">
      <Fact term="Rule origin">{label(value.kind)}</Fact>
      <Fact term="Author">{value.author || 'Not supplied'}</Fact>
      <Fact term="Source">
        {value.source_url ? (
          <ExternalLinkSafe href={value.source_url}>{value.source_url}</ExternalLinkSafe>
        ) : (
          'Local definition'
        )}
      </Fact>
      <Fact term="License">
        {value.license ? (
          <ExternalLinkSafe href={value.license_url}>{value.license}</ExternalLinkSafe>
        ) : (
          'Not supplied'
        )}
      </Fact>
      {value.upstream_id && (
        <Fact term="Upstream ID">
          <span className="mono">{value.upstream_id}</span>
        </Fact>
      )}
      {value.status && <Fact term="Upstream status">{label(value.status)}</Fact>}
    </dl>
  );
}

export function MitreTags({ techniques }: { techniques: string[] }) {
  return techniques.length ? (
    <div className="tag-list">
      {techniques.map((technique) => {
        const valid = /^T\d{4}(?:\.\d{3})?$/.test(technique);
        return (
          <span className="technique-tag" key={technique}>
            <ExternalLinkSafe
              href={
                valid
                  ? `https://attack.mitre.org/techniques/${technique.replace('.', '/')}/`
                  : undefined
              }
            >
              {technique}
            </ExternalLinkSafe>
          </span>
        );
      })}
    </div>
  ) : (
    <span className="muted">No mapping supplied</span>
  );
}
