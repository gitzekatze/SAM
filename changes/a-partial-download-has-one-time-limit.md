### An update download has one time limit, also when only the changed parts are downloaded

- Downloading an update now ends within an hour in all, the changed parts
  and the whole file after them together. Before, a slow server could keep
  a partial (zsync) download going for about a day, one request after
  another, and the app could not start meanwhile.
- When a server ignores requests for parts of the file and sends the whole
  file each time, SAM notices at the first answer and downloads the whole
  file once. Before, it downloaded the whole file for every part it asked
  for.
- A partial update is written to a new file that SAM creates itself, never
  through a link, and it is on the disk before SAM uses it, so a power
  loss during SAM's own update cannot leave an empty SAM behind.
- One block more is reused from the old version when the published file
  ends in a short block, so a little less is downloaded.
