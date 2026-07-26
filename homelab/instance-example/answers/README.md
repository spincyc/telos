# Recorded installer answer sets

One JSON file per machine, recording what was typed at its installation. These
are a record, not an input: there is no unattended path and nothing reads them
back to skip a prompt (ADR 0058).

They exist so a rebuild can be performed with the same parameters as the
original without anyone having to remember them, and so a machine's manifest
can be compared against what was intended.

    <hostname>.json

Never record the LUKS2 passphrase here.
