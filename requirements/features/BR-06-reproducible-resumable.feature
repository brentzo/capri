Feature: Reproducible and resumable runs
  As an operator
  I want to stop a run and resume it, and reproduce any finding on demand
  So that a long assessment survives interruption and its findings are defensible

  Scenario: A killed run resumes where it left off
    Given a run that was killed mid-assessment
    When I resume it
    Then it continues from the coverage ledger
    And it reaches the same confirmed findings as an uninterrupted run over the same targets

  Scenario: Any finding can be replayed deterministically
    Given a confirmed finding
    When I replay its repro steps against a fresh snapshot
    Then the same success signal fires again

  Scenario: Re-running completed work changes nothing
    Given a technique already recorded as done for an asset
    When the run encounters it again
    Then it is a no-op unless I explicitly force a re-run
