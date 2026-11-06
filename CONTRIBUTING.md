# Contributing

Thank you for considering it. Lostname is young and the design is still moving, so please open an issue before a large change.

## The ground rules
- **Licence and sign-off.** Contributions are accepted under [EUPL-1.2](LICENSE), inbound equals outbound. Sign off every commit with the [Developer Certificate of Origin](https://developercertificate.org/) (`git commit -s`).
- **Tests come with the change.** Fixtures use only reserved names (`example`, `.test`, `.invalid`, RFC 2606 and RFC 6761). A test fails on any other domain.
- **No secrets, no real zones.** Never commit credentials, provider account ids or exports of a real organisation's zone.
- **Fail closed.** A check that cannot get an authoritative answer must report "no verdict", never success. Changes that weaken this are not accepted.
- **Build on DNSControl.** Lostname calls the official DNSControl binary. Provider support belongs in DNSControl upstream, not here.

## What may be public
Every file is classified in `publication.txt` (public, verbatim, generated, internal), and the pre-commit hook runs `tools/public_check.py`, which blocks an unclassified file. Documents that mix public and private text are written once in `private/src/`, with private passages between `<!-- private -->` markers; `python tools/publicize.py` generates the public version in `docs/`. Run `python tools/install_hooks.py` once per clone. Never bypass the hook.

## AI use
AI-assisted contributions are welcome. Say how the change was made in the merge request (the template has four levels) and in an `Assisted-by:` trailer on the commits. This tells reviewers where to look harder; it does not block a contribution.

## Standards and citations
When a rule rests on a standard, cite it at the rule (RFC number and section) and add it to `docs/references.md`. Claims about provider behaviour carry the date and the evidence of the test that established them.

## Security
Do not open public issues for vulnerabilities. See `SECURITY.md`.
