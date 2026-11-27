### The syscall filter is written in one place

- SAM's syscall filter was written three times: a hand-made front part,
  a part for 32-bit apps and a list compiled by a library. A call added
  to one could be forgotten in another (review K-3: 32-bit apps once ran
  without a filter). Now one table names every refused call with its
  numbers for this processor and for 32-bit x86, and one short piece of
  code turns it into the filter.
- What the filter refuses is unchanged: a new test records its answer
  for every call, argument and setting, and the new code gives the same
  answers.
