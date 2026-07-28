---
schema_version: 1
event_uuid: "9ab267cc-e36d-4f3a-8a62-c510cc1eeabc"
event_type: "checkpoint"
scope: "task"
task_ids: ["cfcab9ef-1f05-46d5-967e-a5a4bb43d923"]
agent_instance_uuid: "053c175f-c27d-434e-8f57-f013909ce432"
created_at: "2026-07-28T02:31:58Z"
---

# Separate install-source and Windows drive letters

The in-process credential helper proved authenticated SMB access and crossed
both pre-mutation disk gates. DiskPart cleaned the disposable disk, converted
it to GPT, created and formatted the ESP, created the MSR and Windows
partition, then failed closed with code 41 because the SMB share already held
`W:` when DiskPart tried to assign that letter to the Windows volume.

New bundles mount the read-only install source at `I:` and reserve `W:`
exclusively for the Windows target partition. Setup and source-presence checks
use `I:` consistently. Thirty-four focused tests pass. Cleanup removed all
QEMU and fabric children; the partially partitioned disposable qcow2 remains
only as ignored evidence and will not be reused.
