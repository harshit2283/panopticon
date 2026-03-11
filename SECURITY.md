# Security Policy

## Supported Posture

Panopticon is currently an experimental MVP. Security reports are welcome, but
the project should not be treated as a production-certified security product.

## Reporting A Vulnerability

Please report vulnerabilities privately through GitHub's "Report a
vulnerability" flow in the repository Security tab. Do not open a public issue
or discussion with exploit details.

We aim to acknowledge new reports within 3 business days and provide a status
update within 7 business days after acknowledgement.

When reporting, include:

- affected version or commit
- environment details
- impact
- reproduction steps
- any proof-of-concept material that helps confirm the issue

If you need an encrypted follow-up channel before a dedicated PGP key is
published, mention that in the GitHub report and a private follow-up channel
can be arranged if needed.

If you are unsure whether an issue is security-relevant, report it privately
anyway.

## What Counts As Security-Relevant

- unintended disclosure of captured traffic or PII
- bypass of configured privacy controls
- unsafe endpoint exposure
- integrity issues in exported or audited data
- privilege or isolation issues in the agent or deployment artifacts

## Current Limits

Some hardening work is intentionally incomplete in the current MVP. See
`README.md` and `docs/CURRENT-STATE.md` before assuming a missing control is an
unexpected vulnerability.
