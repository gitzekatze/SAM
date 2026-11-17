### Full home access protects the startup places for real

- With read and write access to the whole home, an app can no longer leave
  something that runs later outside its sandbox in the usual places: the
  folders above protected places cannot be renamed, missing protected
  folders are created empty first, key folders that are links are hidden
  where they point, and after every start SAM moves aside any new startup
  file (`.bash_profile`, `.xprofile` and the like) or replaced link, and says
  so on the command line and on the app's page. A real sandbox test attacks
  each of these routes.
- More startup files are protected: `.bash_login`, `.bash_logout`, `.zshenv`,
  `.zlogin`, `.zlogout`, `.xsessionrc`, `.xsession`, `.gvimrc`, `.exrc`, tmux,
  screen and Mercurial settings.
