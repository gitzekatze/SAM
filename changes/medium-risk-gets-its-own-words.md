### Medium risk has its own words: Some access

- An app or a permission rated *medium* (sound, the GPU, a shared folder)
  now reads **Some access** instead of **Harmless**, in the window and on
  the command line alike. Only *low* is still called Harmless. These grants
  are ordinary, but they are access, and the old word said less than SAM
  knows.
- `sam-jail list --risk harmless` now selects only apps rated *low*. Use
  `--risk some-access` (or `--risk medium`) for apps rated *medium*.
- When SAM asks first does not change: it still asks before anything rated
  *Think twice* or *Dangerous*. The colors stay as they were (grey for
  Harmless and Some access).
- Applying a preset now names the risk before and after in these words too.
- The JSON interface is unchanged: it still names the levels `low`,
  `medium`, `high` and `dangerous`.
