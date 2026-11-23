### Mutation runs that a runaway test cannot end

- `scripts/mutants.sh` gives the whole run a memory limit (7 GB per change
  running at once, `MUTANTS_MEMORY`) with no swap, where systemd can give a
  delegated user scope. The run's first full test pass (the baseline) is
  under that limit too.
- Each copy's test programs run in a memory compartment of their own
  (`MUTANTS_TEST_MEMORY`, 6 GB). A change that makes a test use memory
  without end now ends only that test, and the change counts as caught.
  Before, such a test filled the run's whole limit and systemd-oomd ended
  the whole run (2026-11-23: after 358 of 2307 changes).
- Without such a scope the run goes on without limits and says so.
  `tests/mutants/memory-compartments.sh` checks the compartments on a
  computer.
