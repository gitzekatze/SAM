### SAM names the key that really signed an AppImage

- An AppImage could carry a trusted key (for example SAM's public release
  key) next to its own and be signed with its own: `gpgv` accepts that, and
  SAM named the first key as the signer. A forged update of SAM, or of a
  signed app, could pass as genuine. SAM now takes the signer from `gpgv`'s
  own report of the signature and refuses files that carry more than one
  key.
- Every GnuPG step has a 20-second time limit.
- `sam-jail doctor` checks that the installed GnuPG still names the real
  signer (contract `signatures-gnupg`).
