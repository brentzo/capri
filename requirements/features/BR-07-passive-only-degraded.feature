Feature: Degrade safely when the sandbox is not proven
  As an operator
  I want the system to keep working but only passively when it cannot prove containment
  So that it never does active harm it cannot contain

  Scenario: Without a proven sandbox, no active probe runs
    Given the sandbox or its guard checks are not proven
    When the run proceeds
    Then no active probe executes
    And only passive observation is performed

  Scenario: Leads are never confirmed in passive-only mode
    Given the run is in passive-only mode
    Then every lead stays unverified
    And nothing is reported as a confirmed vulnerability

  Scenario: The report is honest about the mode
    When a passive-only run produces a report
    Then the report states plainly that it ran without an enforced sandbox
