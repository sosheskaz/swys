# Enable PowerShell completion

Generate PowerShell completion and evaluate it for the current session or add generation to a trusted profile.

## Load it for the current PowerShell session

This example uses PowerShell commands.

```powershell
swys completion powershell | Out-String | Invoke-Expression
```

Review profile security and execution policy before making completion persistent. Regenerate completion when the installed SwYS command tree changes.

## Reference

```sh
swys completion powershell --help
```
