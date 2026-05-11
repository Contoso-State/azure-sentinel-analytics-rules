# Security

Thank you for helping keep this project safe.

## Reporting a vulnerability

Please **do not open public GitHub issues** for security vulnerabilities. Instead, report them privately:

- Open a [security advisory](https://github.com/Contoso-State/azure-sentinel-analytics-rules/security/advisories/new), or
- Email the maintainers at **security@contosostate.org**.

Include as much detail as possible:

- A description of the issue and its impact
- Steps to reproduce (KQL query, workbook tab, deployment input, etc.)
- The affected file(s) or commit hash
- Any suggested mitigations

We will acknowledge receipt within 5 business days and aim to provide a remediation plan within 30 days.

## Scope

This repository contains:

- Microsoft Sentinel analytics rules (Bicep / ARM)
- Azure Monitor workbooks (ARM)
- KQL hunting queries

Issues that are in scope include (but are not limited to):

- Hardcoded credentials, secrets, or tenant identifiers
- Detection logic with high false-negative or false-positive risk
- Workbook queries that expose sensitive data unintentionally
- Insecure deployment patterns

Out of scope: vulnerabilities in upstream Azure services or third-party tools — please report those to the respective vendor.

## Supported versions

Only the `main` branch is supported. Apply the latest commit when investigating an issue.
