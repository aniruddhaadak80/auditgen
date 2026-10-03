# Contributing

Thanks for looking at auditgen. This is a security and compliance tool, so the
bar for changes is higher than for an ordinary CLI.

## The rule that overrides everything else

**A control must never reach `satisfied` without evidence that supports it.**

Every change is judged against that first. If your change can make a status
flatter without adding evidence, it is wrong, even if it passes every test.

Concretely:

- Absence of evidence is never compliance. If a collector cannot reach its
  endpoint, the control is `manual`, not `satisfied`.
- An assertion that passed but reported a gap is `partial`, not `satisfied`.
- The AI narrative pass writes prose. It must not be able to set, promote or
  clear a status. If you add a model call anywhere near status logic, it will
  not be merged.
- Advisory remarks go in `Finding.notes`. Never in `Finding.gaps`. A note in
  `gaps` silently downgrades a passing control.

## Getting set up

```bash
git clone https://github.com/aniruddhaadak80/auditgen
cd auditgen
npm install
npm run typecheck
npm test
```

Node 20.10 or newer. There are no runtime dependencies and we intend to keep it
that way; a new dependency needs a strong argument in the PR description.

## Workflow

1. Branch from `main`.
2. Write the failing test first. For a status bug, assert the status is *not*
   what it currently is.
3. Make it pass.
4. `npm run typecheck && npm test && npm run build`.
5. Open a PR against `main`.

## Adding a control

1. Add it to `src/controls/soc2.ts` or `src/controls/iso27001.ts` with the real
   criterion language. Do not paraphrase an auditor's wording into something
   vaguer.
2. Point it at a collector, or mark it `manual: true` if no repository can prove
   it. A control with no collector and no `manual` flag fails
   `test/controls.test.ts`.
3. Set `guidance` to describe what a reviewer actually opens. This text grounds
   the AI narrative, so vagueness here becomes vague output.
4. Run `npm test`. The registry test checks id format, framework mapping,
   duplicate ids and collector resolution.

## Adding a collector

Collectors are run **once per audit** and their results attributed to every
control that references them, so one observation can legitimately support several
controls without repeating API calls. Keep them cheap.

- Return `CollectorResult[]`. Prefer one assertion per result so a partially
  passing control reads honestly.
- Put shortfalls in `gaps`, remarks in `notes`.
- Set `unverifiable: true` when the signal cannot be observed. The engine turns
  an entirely unverifiable control into `manual`.
- Redact anything secret. Prefix, length and digest only. See `redact()` in
  `src/collectors/git.ts`.
- Never assert a negative you did not verify. "Protection settings could not be
  read" and "protection is absent" are different findings, and conflating them
  produces a report that is confidently wrong.
- Prefer the shared `tree` index on `CollectorContext` over fresh content
  requests. One recursive tree call answers most file-presence questions.

## Tests

`node:test`, no framework. Tests compile with `npm run pretest` because Node 22
does not remap `.js` specifiers to `.ts`.

Coverage we care about most:

- `test/hash.test.ts` — chain integrity, including tamper, reorder, insert and
  delete.
- `test/evaluate.test.ts` — the status decision table.
- `test/audit.test.ts` — the wrong-repository guard.

If you change `src/engine/evaluate.ts` and no test in `evaluate.test.ts` fails,
you have not tested it properly.

## Commits and pull requests

- Conventional-ish subjects: `Add Annex A.8.9 coverage`, `Fix false pass when
  protection settings are unreadable`.
- Explain *why* in the body when the reason is not obvious from the diff.
- One concern per PR. A control addition plus a refactor plus a CLI change
  cannot be reviewed.
- If a PR changes evidence output, say whether existing chain roots change. They
  will if any assertion's content changed.

## Reporting vulnerabilities

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

Be direct and assume good faith. Reviewers will tell you that a change can produce
a false pass, and that is not a personal judgment about your work, it is the one
property this tool must never lose. Disagreement is welcome; take it to the
issue.

## Licence

Contributions are accepted under the MIT licence.