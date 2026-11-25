### The strict syscall filter blocks every call its description names

- The strict filter (experimental, off by default) promised to block
  access to other processes and the NUMA memory calls. It now also blocks
  `process_madvise`, `pidfd_getfd` and `kcmp`, which need the same
  permission as `ptrace`, and `get_mempolicy`, `set_mempolicy` and
  `set_mempolicy_home_node`. The documentation says what no system call
  filter can block (`/proc/<pid>/mem` and `/proc/<pid>/fd`), why the app's
  own process namespace limits both to its own processes, and that Mesa
  drivers may print a harmless `kcmp` warning under the strict filter.
