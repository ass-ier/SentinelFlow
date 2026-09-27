# Evidence-register visual system

This frontend implements the approved **Operate** direction: an incident casework
desk for SOC analysts and detection engineers. It is not a marketing surface or a
claim of production-SIEM capability. The source contract is retained as an HTML
comment in `index.html` (candidate 5, seed `key260c28ac`).

## Visual rules

- Cool-white working canvas (`#f4f7f9`) and white surfaces, with slate navigation
  (`#1b2e3d`). Primary text is `#243746`; supporting text is `#5b6e7a`.
- Muted teal (`#216b64`) is reserved for actions, selected state, evidence links,
  and the event activity series. Semantic red/amber are reserved for severity,
  failures, attention, and the alert activity series.
- Crisp one-pixel boundaries, 6px component corners, no gradients or decorative
  glows. Only the native connection dialog has an offset shadow.
- System UI typography, compact fixed-size hierarchy, and local monospace stacks
  for IDs, timestamps, commands, raw input, and measurements. No external font requests.
- The overview’s five figures form one register strip, not five independent cards.
  The broad activity plot and alert register dominate the workspace; lower source
  and rule rankings are compact lists.

## Investigation hierarchy

Navigation is grouped into Investigate, Engineer, and Verify. Run scope remains in
the persistent header. Case detail leads with severity, current status, evidence
count, rule/branch, and run, followed by actual event-time bounds and entity links.
Status editing is secondary to the evidence. A pinned rule snapshot is explicitly
separated from the current operational definition.

Table rows expose direct investigation links and expandable raw evidence. Definition
and validation views progressively disclose exact source, criteria, provenance,
expected versus observed alerts, and measured execution metrics.

## States and semantics

Loading is a labeled skeleton, not a fake metric. Empty states teach the next action.
Errors retain the last known data, identify failed actions, and expose retries.
Mutation controls remain unchanged until the API confirms success. Status and severity
always have text in addition to color. PASS, FAIL, and OBSERVED are distinct server
results, not styling decisions.

## Responsive and accessible behavior

Desktop uses a 224px sidebar. Below 760px it becomes an inline, collapsible navigation
region, preserving keyboard order without an overlay or hidden focus trap. Below
460px primary forms stack; controls grow, while evidence tables retain their columns
inside horizontally scrollable, labeled regions. Case timelines become vertical.

Native buttons, selects, checkboxes, progress, details, tables, and dialog semantics
are preserved. Focus rings are visible, content is escaped, layout supports long IDs
and logs, and reduced-motion preferences suppress transitions.

Real desktop/mobile browser inspection is performed by the parent integration task,
after repository validation; no screenshots or recordings are represented as captured
by this frontend implementation task.
