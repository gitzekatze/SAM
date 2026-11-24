### Always blocked D-Bus names are blocked everywhere

- A name on the list of **Always blocked names** stayed blocked only for
  talking to it, and only when it was written out in full. A name the
  app may own, a function it may call or a signal it may receive under
  that name still got through, and a blocked entry like `org.example.*`
  blocked nothing. Now a blocked name stays blocked for all of these,
  and a wildcard blocks every name below it, as the setting promises.
- SAM no longer learns a name the app asks for when you blocked it: it
  says so in the log instead of starting the app again for nothing.
- The D-Bus filter works per program, not per name: a program that holds
  both a blocked name and a name the app may talk to can still be
  reached through the allowed name. The setting's help now says so.
