## What this changes

<!-- One paragraph. What does an auditor or user get that they did not get before? -->

## Type

- [ ] Bug fix
- [ ] New control
- [ ] New collector
- [ ] Feature
- [ ] Docs
- [ ] Build or CI

## The false-pass check

<!--
Required for anything touching src/engine/, src/collectors/, or a control
definition. Answer all three.

- Could this change make a control reach `satisfied` without evidence supporting it?
- Could it turn an unverifiable control into a passing one?
- Are all remarks in `notes` rather than `gaps`?
-->

## Checklist

- [ ] `npm run typecheck` passes
- [ ] `npm test` passes
- [ ] `npm run build` passes
- [ ] New behaviour has a test that fails without this change
- [ ] If evidence output changed, existing chain roots will change and I have said so

## Verification

<!--
How you checked this. If you ran the CLI against a real repository, say which
and paste the relevant terminal output.
-->