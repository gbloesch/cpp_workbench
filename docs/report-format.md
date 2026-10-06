# Report format, version 1

The exported file is UTF-8 JSON. Numeric chart fields are JSON numbers, never
strings with percent signs. `schemaVersion` is 1. See `report.schema.json`.

## Top-level fields

| Field | Meaning |
|---|---|
| `schemaVersion` | Protocol/schema version |
| `generatedAt` | UTC timestamp of this export/view refresh |
| `scope` | Latest completed scan of currently open C++ documents |
| `counting` | Attribution and denominator definitions |
| `totals` | Analyzed documents, all findings, memory findings, SQL findings |
| `rows` | Flat, fixed list of 24 chart rows: 12 locations × 2 flaw types |
| `findings` | Findings with source locations, context paths, and evidence |
| `documents` | Per-document C++ output plus version/hash/scan time |
| `documentStatuses` | Pending/analyzing/complete/failed/skipped files |

## Each row

`type` is `memory-leak` or `sql-injection`. `location` is a stable category ID.
`label` is a human-readable display label. `count` is a nonnegative integer.
`percentOfType` and `percentOfAll` are numbers from 0 to 100.

Only the **primary**, innermost recognized context receives the count. Sum all
row counts to obtain `totals.findings`. All `memory-leak` row counts sum to
`totals.memoryLeaks`. The equivalent SQL sum is `totals.sqlInjections`.

## Findings and positions

`id` is stable only within a document version. Combine `documentUri`,
`documentVersion`, and `id` to identify a finding in an export. It is not a
cross-version tracking ID for measuring fixes or identifying users.

`startByte` is a zero-based UTF-8 byte offset, inclusive. `endByte` is exclusive.
`line` is one-based. These positions refer to the unsaved snapshot at
`documentVersion`, not necessarily the disk file. VS Code consumes UTF-16
positions, so the extension converts offsets before displaying diagnostics.

`contexts` is outermost-to-innermost, for example `["function","for","if"]`.
`primaryContext` is its last item. `relatedLocation` is optional and identifies
a possible exit or overwrite for a memory finding. It has its own byte range,
line, explanation, and contexts. Memory's main location is its allocation.

`confidence` is `heuristic`. Messages and evidence help users assess a possible
problem. Category metadata is suitable for grouping findings, not certifying
that any given line is vulnerable.

## Session and updates

Changed files lose their older displayed counts until the new scan completes.
Closed files are removed. Each completed file version contributes at most once.
This prevents the polling frequency from changing the totals. During scanning,
`documentStatuses` explains files absent from the completed-report denominator.

The report includes file paths and finding descriptions but **not full source
code**. Source copies are stored separately for the two local C++ stages. If a
future site accepts report uploads, design that feature explicitly; no upload
exists in this extension.

## Suggested website chart inputs

```javascript
const rows = report.rows.filter(r => r.type === selectedType);
const series = rows.map(r => ({
  category: r.location,
  label: r.label,
  value: r.count,
  percentage: r.percentOfType
}));
```

Use `count` for a count bar chart or `percentOfType` for a composition chart.
Do not add percentages across different flaw types; their denominators differ.
If grouping by all nested contexts later, explicitly label that overlapping
chart: its sum can exceed the total number of distinct findings.
