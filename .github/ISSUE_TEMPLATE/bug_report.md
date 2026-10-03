---
name: Bug report
about: Something is wrong or produces a wrong result
labels: ["bug", "needs-triage"]
---

## What happened

<!-- What you ran, and what came out instead. -->

## Reproduce

```bash
# exact command
```

## Expected

## Actual

```
<!-- paste the terminal output or the relevant part of the JSON report -->
```

## Is a status wrong?

If auditgen reported a control as `satisfied` when it should not have, say so
explicitly. That is the highest-priority class of bug here and it changes how we
triage.

- [ ] A control is wrongly `satisfied`
- [ ] A control is wrongly `gap` or `partial`
- [ ] Output or evidence is otherwise wrong
- [ ] Crash or hang
- [ ] Not a correctness issue

## Environment

| | |
| --- | --- |
| auditgen version | `auditgen --version` |
| Node version | `node --version` |
| OS | |
| Repository audited | public name, or "my own" |
| Token scopes | e.g. `repo`, or "no token" |

## Anything else

<!--
If a control came out wrong, include the control id and its evidence block from
the JSON report. That is usually enough to diagnose without asking for more.
-->