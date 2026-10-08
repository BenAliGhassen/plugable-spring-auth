---
name: review-code
description: "Review code changes for production-impacting bugs, security vulnerabilities, broken edge cases, and regressions. Use for code review, reviewing a diff or pull request, security-focused review, or checking code quality before merge."
user-invocable: true
---

# Code Review

Review changes for defects that could affect production behavior. Prioritize correctness, security, data integrity, availability, and meaningful performance risks. Do not spend review effort on style preferences, naming, or missing tests unless they expose or conceal a concrete defect.

## Review workflow

1. Identify the review scope: requested files, the current diff, or the pull request. For a diff review, inspect the complete diff and the surrounding implementation needed to understand its behavior.
2. Trace changed behavior through relevant callers, data models, configuration, and tests. Check boundary conditions, error paths, state transitions, concurrency, and interactions with existing behavior.
3. Look for concrete issues such as incorrect logic, unsafe input handling, authorization gaps, secret or personal-data exposure, transaction and persistence errors, race conditions, resource leaks, and inefficient operations on likely hot paths.
4. Verify each candidate against the actual code. Confirm its preconditions and impact; use tests, focused commands, or a small reproduction when practical. Reject speculative findings and issues that cannot be tied to observable behavior.
5. Report only actionable findings. Deduplicate overlapping reports, order them by severity, cite the narrowest accurate file and line range, and explain the triggering condition and production impact.
6. If no actionable issue is found, say so explicitly. Do not make code changes unless the user separately requests and approves them.

## Severity

- **🔴 Important**: A defect likely to cause incorrect production behavior, security compromise, data loss, or significant outage. State why it should be fixed before merge.
- **🟡 Nit**: A concrete, low-impact issue that is worth addressing but should not block merging. Keep these concise and limit them to actionable items.
- **🟣 Pre-existing**: A verified defect in surrounding code that the reviewed change did not introduce. Report separately from change-introduced findings and explain that it predates the change.

Do not elevate an issue solely because it is in a security-sensitive area. Base severity on a plausible exploit or failure path, prerequisites, and impact. Do not label ordinary style or preference differences as findings.

## Finding format

For each finding, include:

- Severity marker and short title.
- Exact file path and line or narrow line range.
- The input/state/concurrency condition that triggers the defect.
- The resulting user-visible, security, data-integrity, availability, or performance impact.
- A minimal, concrete remediation. Include a small code example only when it clarifies the fix.

Use this structure:

```text
🔴 Important — <short title>
File: <path>:<line or range>
<Triggering condition and concrete impact.>
Fix: <minimal remediation>
```

For PR reviews, focus on regressions introduced by the changes. Put verified pre-existing defects in a separate section and do not imply that the PR introduced them.

## Review boundaries

- Do not edit files, apply fixes, or commit changes as part of a review.
- Do not report unsupported assumptions as facts; ask for missing context when a finding depends on an unknown contract.
- Do not claim tests passed unless they were run and their results observed.
- Keep the summary brief and reserve detailed explanations for actionable findings.

## Reference

This workflow is informed by [Claude Code Review](https://code.claude.com/docs/en/code-review), especially its focus on production correctness, security, verified findings, deduplication, severity ranking, and concise actionable reporting.
