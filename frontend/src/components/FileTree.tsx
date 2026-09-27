import { FileText, Folder } from 'lucide-react';
import type { ProjectEvidence } from '../types';
import { number } from '../services/format';

interface Node {
  name: string;
  path: string;
  bytes?: number;
  children: Node[];
}

function makeTree(files: ProjectEvidence['files']): Node[] {
  const roots: Node[] = [];
  for (const file of files) {
    let siblings = roots;
    const parts = file.path.split('/').filter(Boolean);
    parts.forEach((part, index) => {
      const path = parts.slice(0, index + 1).join('/');
      let node = siblings.find((candidate) => candidate.path === path);
      if (!node) {
        node = { name: part, path, children: [] };
        siblings.push(node);
      }
      if (index === parts.length - 1) node.bytes = file.bytes;
      siblings = node.children;
    });
  }
  const sort = (nodes: Node[]) => {
    nodes.sort(
      (a, b) =>
        Number(b.children.length > 0) - Number(a.children.length > 0) ||
        a.name.localeCompare(b.name),
    );
    nodes.forEach((node) => sort(node.children));
  };
  sort(roots);
  return roots;
}

function TreeNodes({
  nodes,
  documents,
  onDocument,
  root = false,
}: {
  nodes: Node[];
  documents: Set<string>;
  onDocument: (path: string) => void;
  root?: boolean;
}) {
  return (
    <ul>
      {nodes.map((node) => (
        <li key={node.path}>
          {node.children.length ? (
            <details open={root}>
              <summary>
                <Folder size={15} aria-hidden="true" />
                <span>{node.name}/</span>
              </summary>
              <TreeNodes nodes={node.children} documents={documents} onDocument={onDocument} />
            </details>
          ) : (
            <div className="file-leaf">
              <FileText size={14} aria-hidden="true" />
              {documents.has(node.path) ? (
                <button
                  type="button"
                  className="file-document"
                  onClick={() => onDocument(node.path)}
                  title={node.path}
                >
                  {node.name}
                </button>
              ) : (
                <span title={node.path}>{node.name}</span>
              )}
              <small>{number(node.bytes ?? 0)} B</small>
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}

export function FileTree({
  files,
  documents,
  onDocument,
}: {
  files: ProjectEvidence['files'];
  documents: ProjectEvidence['documents'];
  onDocument: (path: string) => void;
}) {
  return (
    <div className="file-tree">
      <TreeNodes
        nodes={makeTree(files)}
        documents={new Set(documents.map((document) => document.path))}
        onDocument={onDocument}
        root
      />
    </div>
  );
}
