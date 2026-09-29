# Interface design

SentinelFlow uses an evidence-register layout for SOC investigation: select a
run, triage an alert, and follow its pinned rule to the exact triggering records.
The interface prioritizes scanability and provenance over decorative security
graphics. The direction contract is retained in `frontend/index.html`; product
context and constraints are in `PRODUCT.md`.

## Shipped visual system

| Element | Implementation |
|---|---|
| Working surface | Cool white `#f4f7f9`, white panels, crisp `#dbe3e9` separators |
| Primary text | Slate `#243746`; secondary text `#5b6e7a` |
| Navigation | Fixed 224px slate `#1b2e3d` rail on desktop; collapsible mobile navigation |
| Actions | Restrained teal `#216b64`, darker hover, pale selected states |
| Typography | Local system sans-serif; 14px body, 26px main headings at default browser settings |
| Evidence | Local monospace stack and tabular numerals for identifiers, time, counts and raw logs |
| Controls | 6px corners, visible boundaries, textual labels and 2px focus outlines |
| Severity/status | Text plus semantic color; neither meaning nor interaction depends on color alone |

No remote fonts, marketing imagery, external chart service or fabricated
operational metric is required. The dashboard gives the main activity plot and
alert register more space than summary metrics. Run scope remains visible
throughout investigation so aggregated and isolated results are distinguishable.

## Investigation and engineering patterns

- Dense semantic tables support event and alert scanning. Rows disclose
  normalized fields and original evidence without treating log content as HTML.
- Alert detail separates the detection summary, analyst workflow status,
  complete entities, exact evidence and immutable rule snapshot.
- Rule toggles describe their future-run scope. Testing a disabled definition
  is explicit and does not silently enable it.
- Validation separates expected and observed output. Custom outcomes without
  an expectation are observed, never labeled PASS.
- Sigma source, compilation, persistence and testing are distinct operations.
  Authorship, license, unsupported semantics and disabled-by-default import are
  visible next to the operation they affect.
- Replay uses persisted backend progress and an event feed. Project evidence
  reads actual local validation logs and receipts, including failed/stale states.

## Responsive and accessible behavior

Layouts collapse at smaller widths instead of shrinking evidence text into
unreadable columns. Tables retain their own horizontal scroll regions. Mobile
navigation closes after a destination is selected, and long values wrap without
causing document-wide horizontal overflow. ATT&CK identifiers remain intact.

Keyboard users have a skip link, labeled forms, semantic disclosure controls,
visible focus and focus movement into the main workspace. Loading, empty,
failure, unsupported-input, disconnected and stale-report states have explicit
text. Reduced-motion preferences are respected. Raw evidence and copy failures
remain readable without relying on animation or clipboard availability.

## Verification evidence

The final live workflow covers all eight main routes at 1440px and 390px,
mobile navigation, keyboard entry, real API mutations and evidence retrieval.
The frontend suite exercises form, state and error behavior; this is not a
claim of a complete external accessibility audit.

Actual captures are in `screenshots/`, including the mobile dashboard. The
continuous walkthrough and media receipt are in `recordings/`. Full-page
captures scroll real overflow panes into view before saving so their contents
are painted; no application data is substituted for presentation.
