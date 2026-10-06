# Security reporting

Do not post suspected vulnerabilities, exploit details, private keys, passwords,
or tokens in public issues or pull requests.

Report suspected vulnerabilities privately through
[GitHub's report form](https://github.com/sosheskaz/swys/security/advisories/new).
If the form is unavailable, do not post sensitive details publicly.

Include the affected version or commit, operating system, expected and observed
behavior, and a minimal reproduction using disposable data. Describe the impact
and any workaround you have verified. Include the output of `swys --version`
to identify the exact build.

Cryptographic operations can leave output after a late error: streaming AES
decryption emits each authenticated chunk as it completes. Callers must check
the exit status before treating the full result as successful. Certificate
inspection can also export a peer certificate independently of whether its
chain is trusted; inspect the verification result before using it as a trust
anchor. The embedded command guides describe these contracts in detail.
