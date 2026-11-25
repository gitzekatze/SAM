### SAM follows a moved AppImage only when it is the one SAM unpacked

- When an app's AppImage is gone and you add a file with the same
  content elsewhere, SAM follows the file with the app's sandbox. It
  recognized the file by its last seen checksum, which "Check all
  AppImages for changes" also records for a file another program
  swapped. A swapped file moved elsewhere was then offered as the app's
  moved file, and adding it made SAM treat it as what it had unpacked,
  also for updates.
- Now SAM offers and follows a moved file only when its content is what
  SAM unpacked for the app. Any other file is added as an app of its
  own, with its own settings.
- The app keeps its marks when it follows its file. An app whose file
  had changed is ready again once you add its real file back.
