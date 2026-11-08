Feature: Deliver a trustworthy, actionable report
  As an operator
  I want a report of confirmed findings with impact, severity, remediation, and evidence
  So that I can hand it to engineers and fix things

  Scenario: The report is released only if it validates
    When the run finishes
    Then the report is released only if every confirmed finding has a distinct finder and verifier, evidence, a CVSS score, and a CWE

  Scenario: Hardening notes are kept separate from vulnerabilities
    Given a defense-in-depth gap with no demonstrated impact
    Then it is listed as a hardening note with no severity
    And it is not counted among the confirmed vulnerabilities

  Scenario: The report says what was tried, not only what was found
    When I read the report
    Then it includes a coverage summary of attempted, not-applicable, and blocked techniques

  Scenario: The report never leaks internal failure detail
    Given a step failed internally during the run
    Then the report describes findings in target-neutral terms
    And it contains no stack traces, status codes, or raw errors
