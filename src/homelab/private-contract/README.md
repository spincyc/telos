# Public/private homelab contract

This directory is the public interface between Telos and a sibling private
repository. Telos contains reusable roles, builders, tests, and documentation.
`../telos-private` contains the facts that identify one household or machine.
Neither repository contains plaintext secrets.

The contract version is `1`. A private instance declares that version in
`contract_version`; automation must stop when it encounters a newer version.
Additive optional fields do not change the version. Removing a field, changing
its meaning, or making an optional field required increments the version.

## What belongs where

| Public Telos | Private Git repository | Encrypted secret store |
|---|---|---|
| JSON schema and redacted example | People and group names | Passwords |
| Network design rules | Real subnets, VLANs, and SSIDs | Wi-Fi credentials |
| Ansible roles and image builders | Hostnames and machine inventory | Private keys and keytabs |
| Verification procedures | MAC addresses and disk serials | Recovery keys and join credentials |
| Empty deployment templates | Share names and access policy | Tokens and certificate private keys |

A private repository is not a secret store. Git history preserves deleted
values, and repository visibility can be changed accidentally.

## Guided bootstrap

A future `make homelab-private-bootstrap` target should implement this exact
conversation:

1. Refuse to continue if the destination exists or is inside the public Telos
   worktree.
2. Create the sibling directory `../telos-private`.
3. Initialize a Git repository with private-repository warnings in its README.
4. Ask one question at a time. Explain what the answer controls before asking.
5. Write only nonsecret answers to `homelab/instance.json`.
6. Validate the file before showing any Git commands.
7. Print a redacted review. Require an explicit confirmation before the first
   commit.
8. If GitHub publication is requested, verify that the remote repository is
   private before pushing. Never create or push to a public remote.

The minimum questions are the permanent identity domain and realm, site label,
networks, user and administrative group membership, controller endpoints, and
each machine's stable inventory. Password and Wi-Fi prompts must instead name
the configured encrypted secret-store key; they must never accept the secret
value as a command-line argument.

## Files

- `instance.schema.json` is the machine-readable contract.
- `instance.example.json` is synthetic and safe to publish.
- `validate.py` performs dependency-free structural and cross-reference checks
  and emits a redacted review.

Validate an instance:

```sh
python src/homelab/private-contract/validate.py \
  ../telos-private/homelab/instance.json
```

Review without exposing inventory identifiers:

```sh
python src/homelab/private-contract/validate.py --review \
  ../telos-private/homelab/instance.json
```

Validation is a publication and deployment gate. It does not prove that an
address is unused, that a VLAN exists in UniFi, or that a disk serial identifies
the intended disk; deployment preflight must verify those live facts.
