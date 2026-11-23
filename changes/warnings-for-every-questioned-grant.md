### Warnings for every access that deserves a second thought

- Passwords & keyring, the webcam, the SSH agent, privileged Wayland
  protocols, and the syscall filter or Landlock switched off now show a
  warning, like the risk words already did. Nested namespaces are noted.
- The warning about private keys under full home access stays even when
  the full-home warning is switched off in the preferences.
- Full access to the session bus is shown as a danger, as the risk words
  already rated it.
