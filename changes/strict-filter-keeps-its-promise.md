### The strict syscall filter blocks every call its description names

- The strict filter (experimental, off by default) promised to block
  access to other processes and the NUMA memory calls. It now also blocks
  `process_madvise`, `pidfd_getfd` and `kcmp`, which reach into another
  process as far as `ptrace`, and `get_mempolicy`, `set_mempolicy` and
  `set_mempolicy_home_node`. The documentation says what no system call
  filter can block (`/proc/<pid>/mem`).
