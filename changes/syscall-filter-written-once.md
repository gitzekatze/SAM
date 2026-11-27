### The syscall filter is written in one place

- SAM's syscall filter was written three times: a hand-made front part,
  a part for 32-bit apps and a list compiled by a library. A call added
  to one could be forgotten in another (review K-3: 32-bit apps once ran
  without a filter). Now one table names every refused call with its
  numbers for this processor and for 32-bit x86, and one short piece of
  code turns it into the filter.
- What the filter refuses is unchanged. A new test records the filter's
  answers under all 16 settings, for call numbers 0 to 1023 (also with
  the x32 bit set) and four extreme numbers, with each argument the filter
  reads varied alone over a fixed list of values. One record per
  processor, both made from the code before the change: on x86_64 here,
  and on aarch64 on CI's ARM runner. The new code gives the same answers
  on x86_64 here; CI's ARM job checks aarch64.
