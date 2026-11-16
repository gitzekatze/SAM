# When something outside SAM changes

SAM builds on programs, the kernel and the desktop, and none of them stand
still: Bubblewrap gets new options, distributions move files, the kernel adds
syscalls. This page is the playbook for that. The idea: when something
breaks, a light names the exact part, and the part's entry says what to do.

## The map behind it

Every assumption SAM makes about the outside world is a **contract** in
[`docs/contracts.toml`](../contracts.md): what SAM assumes, what SAM does
when it breaks, which of SAM's functions rely on it, how it is checked and a
playbook. CI fails when the code uses an outside program, option, path,
variable, D-Bus name, syscall or Wayland protocol that no contract covers,
so the map cannot fall behind the code.

What SAM does when a contract breaks is always one of these, and always on
the safe side:

| When it breaks | Meaning |
|---|---|
| refuse | SAM does not start the sandbox and says why |
| safer | SAM falls back to less access (for example no network) |
| warn | the start goes ahead with a visible warning ("Protection missing") |
| feature | one feature is unavailable; the sandbox is unaffected |
| none | the assumption only ever narrows access |

## The lights, and where they come on

| Where | What it tells you |
|---|---|
| **An issue "Early warning: Fedora Rawhide: pasta-splice-only"** | the nightly run found a contract broken on a distribution that is not released yet: you have weeks before users get it |
| **An issue "Upstream: Bubblewrap 0.14.0"** | the weekly watch found release notes that mention an option SAM uses, or a removal |
| **A red CI run** | the run's summary ends with "What changed outside SAM": the versions and contract states that differ from the last green run. "No component changed" means the cause is in the change itself |
| **A failed sandbox test** | starts with "CONTRACT BROKEN: …" when a contract SAM cannot work without broke (the outside world changed), or ends with "SAM ERROR: the contracts this test relies on hold" (SAM's own code). A broken contract SAM falls back from (an old pasta, for example) does not stop the test: the test checks the fallback |
| **A bug report** | its "Contracts" section lists what does not hold on that computer, with every version |
| **On your computer** | `sam-jail doctor --contracts` checks everything now |

## What to do

1. **Read the contract.** The light names it; [docs/contracts.md](../contracts.md)
   has its entry with the playbook.
2. **Confirm it.** On your computer: `sam-jail doctor --contracts`. For an
   early warning: open the run (Actions → Early warning) and read
   `tests.log` of that distribution.
3. **Fix it as the playbook says.** Usually one place in the code: an option
   that was renamed, a file that moved, a new name to add.
4. **Prove it.** The contract's tests must pass, and the nightly run must
   turn green: start it by hand under Actions → Early warning → Run
   workflow. The issue then closes itself.

Ask Claude with the issue's link: the issue holds everything needed.

## A new syscall

The baseline syscall filter blocks a list of dangerous syscalls and allows
the rest. A syscall the kernel adds later is therefore allowed until someone
looks at it. The test `every_known_syscall_has_been_reviewed` compares the
kernel headers with [`docs/syscalls-reviewed.txt`](../syscalls-reviewed.txt)
and names every syscall missing there. The nightly run does this on
tomorrow's kernels.

For each new one, decide: could it harm the computer or reach outside the
sandbox? Then block it in `crates/sam-runner/src/kernel.rs` (and mark it
`blocked`). Otherwise mark it `allowed`, with a comment saying why. The
first one, `fchroot` from Linux 7.3, is an example in the file.

## When the code adds an assumption

CI says so: "program run0 (crates/…) is covered by no contract". Add the
item to the `covers` of the contract it belongs to, or write a new contract
with all its fields (`scripts/contract-map.py` says what is missing). A new
contract needs a test, and a quick check where one is possible
(`crates/sam-runner/src/contracts.rs`).

## Why this works for one person

The hard part of maintenance is rarely the fix; it is finding the cause.
Named contracts, early runs on tomorrow's distributions and the "what
changed outside" diff turn that search into reading a light. And because
every contract breaks to the safe side, an unnoticed change costs a feature,
not your security.
