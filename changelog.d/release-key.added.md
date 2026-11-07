- `lostname.allowed_signers` holds the public key that signs release tags (SSH, ed25519). Verify a tag with
  `git -c gpg.ssh.allowedSignersFile=lostname.allowed_signers tag -v vX.Y.Z`.
