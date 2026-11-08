# BR-04 - Report only independently verified findings

**Requirement:** As a security lead, I want every reported vulnerability reproduced by a second, independent agent before it is confirmed, so that I can act on the report without re-checking it myself.

**Implemented by:** HC-FIND-01 (finding lifecycle, verification protocol), HC-AGENT-01 (role isolation), HC-MODEL-01 (provider diversity).

## Acceptance scenarios

```gherkin
Feature: Report only independently verified findings
  As a security lead
  I want every reported vulnerability reproduced by a second, independent agent
  So that I can act on the report without re-checking it myself

  Scenario: A lead becomes a finding only after independent reproduction
    Given the agent has produced a lead with repro steps and evidence
    When a second, independent agent reproduces the success signal in a fresh snapshot
    Then the lead is confirmed
    And the confirmation records a verifier distinct from the finder

  Scenario: The finder can never be the verifier
    When a finding is recorded
    Then it is rejected if the finder and verifier are the same session or share a model provider

  Scenario: An unreproduced lead never ships as confirmed
    Given a lead the verifier could not reproduce
    Then it is reported as rejected or inconclusive
    And it never appears as a confirmed vulnerability

  Scenario: Confidence alone never confirms a finding
    Given a signal that fired with the highest confidence
    Then it still requires independent reproduction before it is confirmed
```
