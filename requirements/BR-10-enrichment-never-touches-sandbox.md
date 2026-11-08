# BR-10 - Optional external intel that never touches the sandbox

**Requirement:** As an operator, I want the system to use public CVE and advisory intel when available, so that it is better informed, without ever exposing the target or letting outside content widen what it does.

**Implemented by:** HC-ENRICH-01 (enrichment plane, untrusted-data posture), HC-MODEL-01 (MCP boundary).

## Acceptance scenarios

```gherkin
Feature: Optional external intel that never touches the sandbox
  As an operator
  I want the system to use public CVE and advisory intel when available
  So that it is better informed, without exposing the target or widening scope

  Scenario: Enrichment runs outside the sandbox
    When the system looks up intel for a detected stack and version
    Then the lookup runs on the control plane
    And it is never reachable from the sandbox range

  Scenario: Fetched content cannot steer the system
    Given an enrichment result that contains an injected instruction
    Then the instruction cannot widen scope, raise the blast tier, or trigger a tool call

  Scenario: Queries never leak the target or the operator
    When an enrichment query is sent
    Then it carries only public technology identifiers and a generic client name

  Scenario: The run proceeds without enrichment
    Given no enrichment key is configured
    Then the run continues using the knowledge base alone
```
