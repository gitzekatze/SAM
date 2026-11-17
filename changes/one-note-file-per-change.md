### Pull requests no longer collide in the change list

- Each change describes itself in a file of its own in `changes/`; the
  release joins them into `CHANGELOG.md`, and the website shows them under
  *What's new* until then. Before, every pull request wrote at the top of
  `CHANGELOG.md`, so merging one made every other open one conflict.
