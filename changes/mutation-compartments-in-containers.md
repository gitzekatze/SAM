### Mutation runs keep their memory compartments inside a container

- `scripts/mutants-cgroup.sh start` now moves every process of the run's
  scope into its "main" compartment, not only itself. Inside a container the
  scope also holds the container's first process (its init), and a cgroup
  with processes of its own cannot give its children memory limits: the run
  stopped with "Device or resource busy". Mutation runs of security code are
  run in an isolated container, so the compartments must work there too.
- `tests/mutants/memory-compartments.sh` checks both cases: the run alone in
  its scope, and the run with another process in it. The second case fails
  with the earlier script.
