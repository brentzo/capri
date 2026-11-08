# BR-02 - Safe by construction (scope, egress, containment)

**Requirement:** As a security lead approving an autonomous assessment, I want the system to be unable to reach out of scope or leave the sandbox even if it tries, so that an autonomous agent is contained as strictly as a hostile one.

**Implemented by:** HC-SUB-01 (no-route gateway, isolation, guard proof), HC-SAFE-01 (guardrail inventory, defense in depth).

## Acceptance scenarios

```gherkin
Feature: Stay in scope and in the sandbox, by construction
  As a security lead approving an autonomous assessment
  I want the system to be unable to reach out of scope or leave the sandbox
  So that an autonomous agent is contained as strictly as a hostile one

  Scenario: An out-of-scope action is denied before it runs
    Given a run scoped to the lab range
    When the agent proposes a request to a host outside that range
    Then the request is denied before it executes
    And the denial is recorded in the audit log

  Scenario: Nothing in the sandbox can reach the internet
    Given a provisioned sandbox
    When anything inside it attempts to reach a public address
    Then the attempt fails because no route exists

  Scenario: Active work does not begin until containment is proven
    Given a freshly provisioned range
    When the start-up checks run
    Then the system proves it cannot reach an out-of-scope host or the internet before any active probe runs

  Scenario: An exploited target cannot escape onto my network
    Given a target that the agent has compromised inside the range
    When it attempts to pivot to the operator host or another network
    Then those hosts remain unreachable
```
