---
schema_version: 1
event_uuid: "ccaa10cb-edfd-431c-8374-32c4ffe0ade6"
event_type: "checkpoint"
scope: "task"
task_ids: ["cfcab9ef-1f05-46d5-967e-a5a4bb43d923"]
agent_instance_uuid: "6cbf7aa9-f882-451b-a9b1-d109807fc2f1"
created_at: "2026-07-28T01:45:39Z"
---

# WinPE injected inputs resolved beside startup batch

The source-mount diagnostic reported code 29 before `ipconfig` or SMB access:
the injected password file is not at the WinPE `X:\` root. The executing
startup batch itself proves wimboot made its injection directory available.
The qcow2 remained effectively empty.

The startup batch now binds `inputs` to `%~dp0` and resolves the injected
password, layout, and unattended answer files beside itself. DiskPart scratch
files remain on writable `X:\`. Exact disk checks and mutation ordering are
unchanged. All thirteen Windows install contract tests pass.
