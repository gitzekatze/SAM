### The real-app run gives SAM's own risky first-run hints the yes a person gives

- The real-app run (`tests/real-apps/test-one.sh`) and the window smoke
  test (`tests/gui/smoke.sh`) gave a yes only to a risky repair step
  (`step-needs-yes`). A risky first-run hint (`hint-needs-yes`), which is
  SAM's own suggestion as well, ended the repair rounds, although the
  window asks the person and the run stands in for that person. In the
  240-app run, UVtools stopped at the X11 hint for this reason.
- Both scripts now retry with `--yes` after either refusal. A step that
  comes from what the app printed (`repair-needs-yes`) still ends the
  rounds: the app controls that text, and SAM refuses it before it judges
  hints and steps. Only test scripts change; SAM itself does not.
