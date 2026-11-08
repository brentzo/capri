Feature: Authorize and scope an engagement
  As an operator running an authorized assessment
  I want the system to act only within an explicit, signed engagement contract
  So that it can never touch anything I did not authorize

  Scenario: A valid contract is accepted and the run is scoped to it
    Given an engagement contract scoped to my lab range within tonight's window
    When I submit it to start a run
    Then the run is accepted
    And only hosts inside that scope are reachable

  Scenario: A contradictory or out-of-scope contract is refused with a reason
    Given an engagement contract whose in-scope range overlaps my management network
    When I submit it
    Then the run is refused before any sandbox is provisioned
    And I am told which field is the problem

  Scenario: The system will not act outside the authorized window
    Given a valid contract whose window has not started
    When I try to start the run
    Then the system does not act until the window opens
    And it stops in-flight work when the window ends

  Scenario: Exclusions always win over inclusions
    Given a host that appears in both the in-scope and out-of-scope lists
    When the agent proposes an action against that host
    Then the action is denied as out of scope
