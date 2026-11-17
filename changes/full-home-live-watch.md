### A new startup file is moved aside while the app runs

- With full home access, SAM no longer waits until the app ends: Linux
  reports every change in the folders that hold startup files, and SAM
  moves a new `.bash_profile`, `.xprofile` or the like aside within moments
  and puts replaced links back at once. A terminal opened while the app
  still runs no longer finds the file. The watch costs nothing while
  nothing changes. The real sandbox test checks that the file is gone while
  the app is still running.
