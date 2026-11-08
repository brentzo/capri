# BR-08 - Full evidence and a tamper-evident audit trail

**Requirement:** As an auditor, I want to reconstruct exactly what the system did and verify that nothing was altered, so that the assessment is defensible after the fact.

**Implemented by:** HC-DATA-01 (append-only evidence store), HC-SAFE-01 (hash-chained audit log).

## Acceptance scenarios

```gherkin
Feature: Full evidence and a tamper-evident audit trail
  As an auditor
  I want to reconstruct exactly what the system did and verify nothing was altered
  So that the assessment is defensible after the fact

  Scenario: Every action and decision is recorded append-only
    When the system requests, allows, denies, or executes anything
    Then it is written to an append-only log with the responsible role and a timestamp

  Scenario: Tampering with the record is detectable
    Given the audit log
    When I verify its hash chain
    Then any altered or removed entry is detected

  Scenario: A finding is always backed by raw evidence
    Given a confirmed finding
    Then it links to the raw request and response captured when it was found and when it was verified

  Scenario: Timestamps are shown in a human form
    When I read the audit or the report
    Then times are shown in am/pm, not a 24-hour clock
```
