Feature: Bounded cost and controlled model access
  As an operator
  I want to cap spend and keep model access under control
  So that an autonomous run cannot surprise me with cost or take an unsafe model path

  Scenario: A budget breach stops work cleanly
    Given a per-run budget
    When a role reaches its budget
    Then that role stops and the run fails closed
    And it never falls through to a direct provider call

  Scenario: Finder and verifier do not share a failure mode
    When the system starts
    Then it refuses to run unless the finder and verifier use disjoint model providers

  Scenario: Rate limits protect both the target and the model APIs
    When the agent probes a target
    Then the per-target request rate and the per-model request rate are enforced independently
