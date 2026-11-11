# BR-11 - Assess local project source privately

**Requirement:** As a project maintainer, I want Capri to scan a local project with local rules and keep the results on my machine, so that I can review source-level security risks without exposing source code.

**Implemented by:** HC-PROJ-01 (local source assessment).

## Acceptance scenarios

```gherkin
Feature: Assess local project source privately
  As a project maintainer
  I want Capri to scan a local project with local rules and keep the results on my machine
  So that I can review source-level security risks without exposing source code

  Scenario: Source is scanned without running project code
    Given I select a local project directory
    When I start Capri's source assessment
    Then Capri scans it with its local rule pack
    And it does not execute project code or change project files

  Scenario: Source content stays out of model prompts and reports
    Given the scan finds a possible credential or vulnerable code pattern
    When Capri writes the report
    Then the report contains rule metadata and a code location
    And it contains no matched source snippet or credential value
    And no source content or source findings are sent to a model provider

  Scenario: Runtime coverage is reported honestly
    When I read the source assessment report
    Then it distinguishes advisory source findings from runtime findings
    And it says runtime assessment was not run when no project runtime was tested

  Scenario: Missing local scanner stops before scanning
    Given the local Semgrep CLI is unavailable
    When I start Capri's source assessment
    Then Capri reports that the local scanner is required
    And it does not install a scanner or fetch a rule pack
```
