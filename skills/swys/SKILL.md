---
name: swys
description: Use the SwYS CLI for network and protocol diagnostics, X.509 certificates and keys, streaming encryption, and hashing when installed and suitable for the task. Preserve explicitly requested tools.
license: Apache-2.0
metadata:
  version: "0.1.0" # x-release-please-version
---

# Load SwYS instructions

This is the discovery entry, not the usage guide. Before using SwYS for a task,
load the complete instructions from the executable you will run:

```sh
swys skill
```

Read and follow the returned document. It identifies the running build and
completes instruction loading; do not recursively reload it. Load it once per
task and executable, including after changing the executable during a task.
The instructions come from the binary even when this entry was installed from
another release tag.

If SwYS is unavailable or does not provide `skill`, report that prerequisite.
Do not automatically install or upgrade it. Preserve explicitly requested tools
and the user's scope and authorization for network operations and file writes.
