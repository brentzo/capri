Feature: Assess project dependencies privately
  As a project maintainer
  I want Capri to assess dependency vulnerabilities and supply-chain hygiene locally
  So that I can find risky packages without revealing my dependency inventory

  Scenario: Hygiene runs without a vulnerability database
    Given I select a project with dependency manifests
    And the local Trivy database is unavailable
    When I start Capri's source assessment
    Then dependency hygiene still runs
    And vulnerable dependency coverage is reported as not_run with a reason
    And the assessment exits normally

  Scenario: Vulnerability matching stays offline
    Given I have downloaded the Trivy database with Capri's explicit update command
    And my project contains a lockfile dependency covered by an advisory
    When I start Capri's source assessment
    Then the report names the package, version, advisory and lockfile location
    And it says reachability was not checked
    And no dependency inventory is sent over the network

  Scenario: Coverage distinguishes checked from unchecked ecosystems
    Given my project uses multiple package ecosystems
    When I read the dependency assessment
    Then each ecosystem has its own coverage status and reasons
    And each assessment area reads complete only when every ecosystem is complete, not run only when none ran, and partial otherwise

  Scenario: Database updates happen only when requested
    Given I want current vulnerability advisories
    When I run `capri source update-db`
    Then Capri downloads only the public Trivy vulnerability database into its own cache
    And Capri prints the database update time
    And later assessments do not update the database automatically

  Scenario: Reports do not disclose the dependency inventory
    Given the project contains many dependencies and one vulnerable package
    When Capri writes the report
    Then it contains package counts and vulnerable packages only
    And it contains no complete package inventory or source snippets
    And it is written outside the selected project
