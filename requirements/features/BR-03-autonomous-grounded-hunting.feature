Feature: Hunt autonomously using curated real-world techniques
  As an operator
  I want the system to find, prioritize, and try applicable techniques on its own
  So that coverage does not depend on me scripting each step

  Scenario: Assets are matched to the techniques that apply to them
    Given a target with discovered endpoints and services
    When the system threat-models the target
    Then it selects the knowledge-base techniques whose applicability matches each asset
    And it ignores techniques that do not apply

  Scenario: Every applicable technique is attempted and accounted for
    When the hunting phase completes
    Then each asset-and-technique pair is recorded as attempted, not-applicable, or blocked-by-policy
    And I can see what was tried, not only what was found

  Scenario: Findings are grounded in the knowledge base, not improvised
    Given a confirmed finding
    Then it cites the exact knowledge-base card and version that produced it

  Scenario: Techniques chain through what earlier steps discovered
    Given a technique that yields a credential
    When a later technique requires an authenticated session
    Then the system sequences the second technique after the first
