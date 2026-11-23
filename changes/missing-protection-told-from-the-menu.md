### A start from the menu says when it runs without some of its protection

- When a start lacks a protection layer its settings ask for (Landlock that
  could not be applied, SAM's helper not found, a Wayland security context
  the desktop refused), a start from the menu now shows a notification
  while the app runs, with a button to the app's page. Before, only the
  command line warned, after the app had ended; from the menu nothing was
  said until you opened the app's page.
