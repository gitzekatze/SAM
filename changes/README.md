# Notes of changes not yet released

Every pull request that changes what users notice adds **one new file** here,
named after the change (for example `writable-folders-in-a-read-only-home.md`).
Never edit `CHANGELOG.md` directly: when every pull request wrote at its top,
merging one made all the others conflict.

A note looks like a section of the change list: a heading that says what
changes for users, then short points in plain words.

```markdown
### A writable folder stays writable in a read-only home

- With the whole home read-only, a folder set to read & write (Documents,
  for example) was read-only too. It is now writable, as its switch says.
```

The website shows these notes under *What's new* right away. The release
(`scripts/release.sh`) moves them into `CHANGELOG.md` under the new version and
deletes the files (`scripts/changes.py collect`).
