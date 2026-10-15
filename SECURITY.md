# Security Policy

## Status

This project is a reference implementation of cookie-based JWT authentication for Spring Boot. It has *not been independently audited*. It is provided "as is" under the MIT License, without warranty. Review it against your own threat model before using it in production.

## Supported versions

There are no versioned releases yet. Only the latest commit on the master branch receives fixes.

## Reporting a vulnerability

*Please do not open a public issue for security problems.*

Report privately through GitHub: open the repository's *Security* tab and choose *Report a vulnerability*. Only the maintainer can see the report.

Please include:

- what the problem is and which part of the code is affected (file, endpoint or configuration);
- steps to reproduce it, or a proof of concept;
- the impact you expect (for example: account takeover, token theft, bypass of the login protection);
- the commit you tested.

## What to expect

This is a personal open-source project maintained on a best-effort basis:

- an acknowledgement within *7 days*;
- an assessment and, if confirmed, a fix or a documented mitigation as soon as possible;
- credit in the fix commit, unless you prefer to stay anonymous.

Please give a reasonable time to fix the issue before disclosing it publicly.

## Scope

*In scope:* the template package (com.example.demo.security): token issuing and validation, refresh rotation and reuse detection, cookies, CSRF, CORS, login protection, configuration checks, security logging.

*Out of scope:*

- the example project code (com.example.demo.user), which is meant to be replaced;
- issues already listed under *Known limitations* in the [README](README.md);
- problems that only appear when the documented requirements are ignored (for example: a weak or committed AUTH_JWT_SECRET, AUTH_COOKIE_SECURE=false in production, or a frontend that sends parallel refresh requests).