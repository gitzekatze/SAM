### A repair step the app's output raised stays the app's request under the name of one of SAM's hints

- When an app's last start printed something that SAM turned into a
  repair step with the same name as one of SAM's own first-run hints
  (`network`, `keyring`, `x11`, `gpu`), `sam-jail repair APP --next` and
  `--apply` found the hint first and lost the mark that the step came
  from the app's output. A step rated *Some access* (such as `gpu`) was
  then applied without `--yes`, and a riskier one was asked for as SAM's
  own hint (`hint-needs-yes`), so a script that confirms SAM's own hints
  could grant the network or the keyring on the app's word.
- Now such a step keeps the mark: `repair` refuses it without `--yes`
  with `repair-needs-yes`, as any step from the app's own output. Found
  by an independent review on 2026-11-27.
