# ADR-0003 Execution kernel extraction

## Decision
Create explicit execution backends (`process`, `environment`, `docker`) behind
typed contracts, including cleanup and output limits.

## Rationale
Current monolithic execution paths mix process launch, isolation policy, and verdict logic.

## Consequences
- Enables independent failure-domain testing.
- Enables deterministic cleanup assertions.
