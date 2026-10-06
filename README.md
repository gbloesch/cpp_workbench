# C++ Security Workbench

A working capstone prototype for Visual Studio Code. Users write C++ in their
normal editor. The extension captures unsaved code, runs two separate C++17
programs, displays possible security problems, and reports where they occur.

**The included detectors are bounded, heuristic static analyzers. They are not a
complete C++ compiler or a production security audit. False positives and missed
issues are possible.** The UI calls results “possible” vulnerabilities. See the
coverage section before interpreting any count as a confirmed flaw.

## Quick start

1. Extract the ZIP. Open the inner **cpp-security-workbench** folder in VS Code.
   This folder must contain `package.json`.
2. You need Node.js 20+ and a **C++17 compiler**: GCC/MinGW, Clang, or MSVC.
   Node/npm do not install a C++ compiler. See Windows setup below if needed.
3. In a terminal inside this folder, run:

   ```powershell
   node scripts/build.js
   ```

   The equivalent is `npm.cmd run build`. There are no npm dependencies, and
   **you do not need npm install**. The script builds both C++ executables and
   checks the JavaScript source. Both must succeed before continuing.

4. Press **F5** in VS Code. This opens an Extension Development Host with the
   `examples` folder. Open `vulnerable.cpp` there.
5. Look for three buttons in the **top-right editor toolbar**, above the C++ file:

   | Icon | Tooltip / command | Action |
   |---|---|---|
   | Shield | C++ Security: Analyze Current File | Analyze immediately |
   | Globe | C++ Security: Open Website | Open your configured website |
   | Graph | C++ Security: View Patterns | Open the readable pattern report |

   Hover to see the names. On narrow windows buttons may be in the `...` menu.
   All commands are also available using **Ctrl+Shift+P**.

6. The demo should produce **two possible memory leaks and two possible SQL
   injections**. If only `vulnerable.cpp` is open, each occupied table row has
   count 1, 50% of its type, and 25% of all findings. Opening other examples adds
   their latest findings to the report. Close them to remove them.
7. Edit code without saving: the next timer check reads the editor's current
   contents. **View → Output → C++ Security Workbench** shows scan activity,
   the document version, and the snapshot directory.

Disable the older security extension while comparing results so that its
diagnostics do not get confused with this project's diagnostics. Findings here
have source **C++ Security Workbench**.

## Windows compiler setup

If you already have `g++ --version` or `clang++ --version` working in your terminal,
try the build immediately. You can set `$env:CXX` to a compiler executable path:

```powershell
$env:CXX = 'C:\msys64\ucrt64\bin\g++.exe'
node scripts/build.js
```

That path is only an example; it must match your installation.

For **MSVC**, install Microsoft's Visual Studio Build Tools with the **Desktop
development with C++** workload, including the compiler and Windows SDK. Open
**Developer Command Prompt for Visual Studio** from the Start menu, then run:

```cmd
cd /d "C:\your\path\cpp-security-workbench"
node scripts/build.js
```

Once built, open this folder in VS Code and press F5 normally. The executables
remain in `bin/win32-x64` (or your platform/architecture folder). F5 checks the
build; it does not rebuild C++ automatically. The VS Code C/C++ extension by
itself does not include a compiler.

Official setup references:
- [Microsoft C++ setup](https://code.visualstudio.com/docs/cpp/config-msvc)
- [GCC/MinGW setup](https://code.visualstudio.com/docs/cpp/config-mingw)

The ZIP contains source code. Build the native programs on the machine where the
extension runs. Windows, Linux, and macOS builds use different executables. In
WSL/SSH/remote workspaces, build for the remote extension host's operating system.

## Where to change the interval and website URL

**While using the extension:** in the Extension Development Host, press
**Ctrl+,**, search **C++ Security**, and edit:

- **Scan Interval Ms** (`cppSecurity.scanIntervalMs`) — default `500`.
  `1000` means once per second. Range: 100–60000 ms.
- **Website Url** (`cppSecurity.websiteUrl`) — replace `https://example.com`
  with your site's address, such as `https://your-project.example`.

Or run **Preferences: Open User Settings (JSON)** and merge these properties:

```json
{
  "cppSecurity.scanIntervalMs": 1000,
  "cppSecurity.websiteUrl": "https://your-project.example"
}
```

Do not create a second pair of outer braces if your settings already contain
other properties. Settings changes take effect immediately; no rebuild is needed.

**To change defaults in the extension you distribute:** edit
`package.json` → `contributes` → `configuration` → `properties` → the relevant
setting's `default`. Restart the debug session after editing the manifest.
Explicit User or Workspace settings override defaults.

The development project's `.vscode/settings.json` also includes sample settings.
They apply only when that particular folder is the open workspace, not when the
development host opens the `examples` folder. User Settings in the development
host are the least confusing way to configure the demonstration.

Other settings: `cppSecurity.enabled`, `cppSecurity.maxFileBytes`, and
`cppSecurity.analysisTimeoutMs`. A manual scan works when automatic scanning is
disabled. Oversized/failed/pending scans are shown separately from completed
scans. “No findings” does not mean “no vulnerabilities.”

## How the two C++ programs receive the copied code

1. `src/extension.js` checks open C++ documents every configured interval.
2. Only a new/changed version, or an explicitly requested scan, is submitted.
3. `src/pipeline.js` creates **two separate UTF-8 copies** of that exact snapshot.
4. It reads the first copy and passes a JSON request through stdin to
   `native/security_analyzer.cpp`. That program detects findings and returns JSON.
5. It reads the second copy and sends it **with those same-version findings** to
   `native/pattern_analyzer.cpp`. That program identifies statement locations,
   assigns categories, and computes counts/percentages in C++.
6. The extension displays diagnostics and merges per-document numeric counts into
   a current report. Classification stays in C++.

The user program is never compiled or executed by the scanner. Only the analyzer
programs themselves are compiled during setup. This is why the sample needs no
MySQL development package and why incomplete editor code can be inspected.

Use **C++ Security: Open Snapshot Folder** to inspect:

```text
<VS Code extension data>/session-<host-id>/snapshots/<document-id>/
    document.json
    security/
        snapshot.cpp
        findings.json
    patterns/
        snapshot.cpp
        report.json
```

The actual directory is printed in the Output panel after each scan. It is VS
Code's extension data directory, not your source project. Versioned work folders
prevent the two programs from accidentally receiving different versions. A new
successful scan replaces that document's previous snapshot. Closing a document
removes its published snapshot. Each extension host uses a separate session
directory so multiple VS Code windows do not overwrite each other's data. The
next activation clears abandoned sessions whose host process is no longer
running. Local copies can remain after a crash until that cleanup occurs.

Scanning is queued to avoid overlapping native work. When code changes during a
scan, old results are discarded and the newest available version is queued.
The interval is a polling interval, not a promise that analysis finishes in that
time. Syntax-heavy files may take longer. A file exceeding the size, time, path,
or token limit is skipped, failed, or explicitly marked incomplete.

The source and reports stay local. The website button opens the configured URL;
it does not upload code or synchronize a dashboard. This version measures the
current open documents, not named users, scan history, or a whole unopened project.

## Understanding View Patterns

The report shows totals, separate memory/SQL tables, finding details, scan status,
and analysis notes. Categories include `for`, `while`, `do-while`, `if`, `else`,
`case`, `default`, `switch`, `try`, `catch`, function body, and global/unrecognized.
An `if` is a conditional branch, rather than a loop.

**Counting choices are explicit:**

- A finding inside `for → if` counts once under **if**, the innermost construct.
  `contexts` retains both locations for future overlapping/nested charts.
- Memory findings use the **allocation location**. If an early return causes the
  possible leak, the return location and its contexts are recorded separately in
  `relatedLocation`. Thus allocation outside an `if` remains “function body,”
  while the report shows that its problematic exit is inside an `if`.
- SQL findings use the database call location.
- Several paths to the same finding are deduplicated by rule and source location.
- Repeated scans replace results; they do not increment a lifetime counter.
- `% of this type = row count / all findings of that type * 100`.
- `% of all findings = row count / all findings of either type * 100`.
- These percentages describe findings, not defective source lines, total loop
  counts, or a probability that a programmer writes vulnerable code.
- Zero denominators give 0%; values are rounded to two decimals.

## JSON for your future website

Run **C++ Security: Export Patterns JSON** from Ctrl+Shift+P to choose where to
save a report. A latest report is also maintained as `patterns-latest.json` next
to the snapshots directory. See `docs/report-format.md`,
`docs/report.schema.json`, and `docs/example-report.json`.

The chart data is deliberately flat:

```json
{
  "type": "memory-leak",
  "location": "for",
  "label": "For loop",
  "count": 1,
  "percentOfType": 50,
  "percentOfAll": 25
}
```

For example, website JavaScript can obtain labels and bar heights with:

```javascript
const memoryRows = report.rows.filter(row => row.type === 'memory-leak');
const labels = memoryRows.map(row => row.label);
const counts = memoryRows.map(row => row.count);
const percentages = memoryRows.map(row => row.percentOfType);
```

## Where to edit the analysis code

| File | Purpose |
|---|---|
| `native/security_analyzer.cpp` | SQL taint propagation, allocation/ownership checks, path exploration |
| `native/pattern_analyzer.cpp` | Location attribution, per-file counts and percentages |
| `native/cpp_model.hpp` | C++ tokenization and the supported statement structure |
| `native/json.hpp` | Dependency-free native JSON protocol |
| `rules/security-rules.json` | SQL sink names/argument indexes, input functions, parameter assumption, enable switches |
| `src/extension.js` | Timer, toolbar commands, diagnostics, stale-result handling |
| `src/pipeline.js` | Source copies and connections to both C++ executables |
| `src/reports.js` | Merge native counts and format the readable view |
| `package.json` | Default settings, toolbar contributions, extension identity |

The VS Code glue uses plain JavaScript so there is no TypeScript/npm dependency
installation. **Both analysis stages are implemented in C++.** Change C++ files,
then run `node scripts/build.js` again. Change JavaScript, then restart F5. Rules
are loaded for each new scan, so use Analyze after changing the JSON rule file.
SQL `queryArgument` indexes are zero-based: index 1 means the second argument.

## What the included detection covers

SQL: input from `cin`, `getline`, `argv`, configured return-value input functions,
selected buffer-writing input functions, simple assignments, concatenation,
`append`/`assign`, `sprintf`/`snprintf`, and selected string-copy operations. The
configured SQL functions flag input-derived **query text**. A fixed query with
bound parameter values is not flagged merely because a bound value is untrusted.
String/character function parameters are treated as potentially untrusted by
default; disable `treatParametersAsInput` if that assumption is unsuitable.

Memory: simple raw `new`/`new[]`, `malloc`/`calloc`, matching pointer cleanup and
aliases, unreleased function paths, early exits, overwrites, direct `realloc`
assignment, and basic smart-pointer ownership. Recognized branches are explored
separately. Loops use a zero/one-iteration approximation. Unknown callees receiving
pointers are treated as possible ownership transfers, which reduces false
positives but can miss leaks.

### Deliberate limitations

This is not Clang and does not understand all C++ syntax or semantics. It does not
resolve includes, macros, overloads, templates, build flags, separate files, or
general function-to-function data flow. Classes, lambdas, complex declarations,
container ownership, custom allocators, reference aliases, pointer arithmetic,
shared-pointer cycles, repeated-loop behavior, correlated branch conditions, SQL
escaping/custom sanitizers, and exception matching are incomplete or unsupported.
Exception paths are approximated; not all possible throws are modeled. Cleanup
mismatches, use-after-free and double-free are separate weaknesses and are not
implemented as dedicated rules. Rule lists do not prove security. Blank or
unsupported snippets can produce no findings and an explanatory analysis note.

Path exploration is capped at 64 states and 80000 node-state visits per file;
the lexer is capped at 100000 tokens. Truncation is reported. A production version
should replace the lightweight model with a real C++ parser/static analyzer while
keeping the snapshot protocol, VS Code UI, and report format.

Authoritative background:
- [CWE-401: Memory leaks](https://cwe.mitre.org/data/definitions/401.html)
- [CWE-89: SQL injection](https://cwe.mitre.org/data/definitions/89.html)
- [Clang Static Analyzer checkers](https://clang.llvm.org/docs/analyzer/checkers.html)
- [CodeQL C/C++ SQL-injection reference](https://codeql.github.com/codeql-query-help/cpp/cpp-sql-injection/)
- [VS Code commands](https://code.visualstudio.com/api/extension-guides/command)
- [VS Code webviews](https://code.visualstudio.com/api/extension-guides/webview)

## Verification

```powershell
node scripts/build.js
npm.cmd test
```

Tests exercise both compiled C++ programs, representative safe/unsafe source,
location/percentage calculations, UTF-8/UTF-16 position mapping, exact snapshot
copies, and mocked VS Code lifecycle behavior. `docs/verification.md` records the
checks performed when this ZIP was prepared, including platform limits.
