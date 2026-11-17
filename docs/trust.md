# Trust SAM

SAM protects you from programs you download, so it should not ask for blind
trust. This section publishes what anyone needs to judge it: how the sandbox
works, what it cannot do, and the tests that check every promise, with their
results.

- **[Dashboard](../DEVELOPMENT.md):** whether SAM is healthy right now, what
  the tests prove area by area, and how the results changed over time.
- **[Security](security.md):** what the sandbox shows and hides, layer by
  layer, and how it is built.
- **[Threat model](threat-model.md):** who SAM protects you from, and just as
  clearly, what it does not.
- **[Functions and their tests](functions.md):** all <!-- fact:functions -->40<!-- /fact -->
  functions SAM promises, each with the tests that prove it.
- **[Test library](test-library.md):** every one of the <!-- fact:tests -->300<!-- /fact -->
  tests and the promise it keeps.
- **[Real AppImages](reports/real-apps-2026-11-15.md):** how each of the <!-- fact:apps_total -->120<!-- /fact --> test AppImages did in its sandbox.
- **[Mutation testing](reports/mutants-2026-11-16.md):** <!-- fact:mutants_tested -->3,011<!-- /fact -->
  deliberate mistakes put into the security code, to see whether the tests
  notice them.
- **[Security review](reports/security-review-2026-11-10.md):** the review
  that checked every security promise against a test.
- **[How SAM is tested](testing.md):** the kinds of tests, what each one
  proves, and how to run them yourself.
- **[Architecture](architecture.md):** SAM's parts, how they work together,
  and where the trust boundary runs.
- **[Reports](reports/README.md):** every report the checks have written,
  newest first, so each claim can be checked against where it came from.
- **[Licenses](../THIRD-PARTY-LICENSES.md):** the parts SAM is built from and
  their licenses.

## How to check SAM yourself

- **Read the promises and their attacks.** The [threat model](threat-model.md)
  lists each threat with what stops it and the test that proves it. Every
  promise on the [security page](security.md) is attacked by a breakout test
  from inside a real sandbox, and the [test library](test-library.md) links
  each test to its code.
- **Watch the tests run.** The tests run on every change on GitHub, on Ubuntu
  and Fedora, and the results are public in the repository's
  [Actions](https://github.com/gitzekatze/SAM/actions) tab.
- **Check a download.** Releases are signed, and
  [SECURITY.md](../SECURITY.md#checking-a-download) shows how to check one.
- **See how SAM keeps up with Linux.** Linux keeps changing under SAM. Every
  assumption SAM makes about it is a [contract](contracts.md) with a test, and
  every night SAM is built and tested on the distributions that come next, so
  a change is noticed before it reaches you.
- **Report a way out.** If you find a way out of the sandbox, report it
  privately through
  [GitHub's security tab](https://github.com/gitzekatze/SAM/security/advisories/new).

## How SAM is made

SAM is a one-person project, built with Claude, Anthropic's AI model, as a
coding assistant. The [README](../README.md#how-sam-is-made) explains who
decides what, and why every change needs passing tests. No one outside the
project has reviewed SAM yet; an outside security review is planned before
the first public beta.
