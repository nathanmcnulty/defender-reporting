# PowerShell baseline

Maintained PowerShell entrypoints require PowerShell 7.6 or later. Their effective
script requirement is `#Requires -Version 7.6`; a version mentioned in a comment,
example, string or deployment payload is not an entrypoint guard.

`tests/Invoke-SetupRuntimeRegression.ps1` maintains three explicit path lists and
compares them with Git's tracked and nonignored new PowerShell sources. A new,
removed or renamed `.ps1`, `.psm1` or `.psd1` must be classified deliberately.
There are no blanket directory exceptions for new test or helper scripts.

| Classification | Policy |
| --- | --- |
| Owning entrypoint | Requires its own effective 7.6 guard. Includes root commands, build commands, tests/manual commands, native helper subprocess adapters, the Azure Functions startup profile and generated executable scripts. |
| Inherited fragment | Loaded or inlined by an owning entrypoint. Includes the shared/provisioning/validation source fragments, import shims, private build functions and explicitly listed test helper libraries. It may also declare 7.6, but is not a separate command surface. |
| Data file | Analyzer settings and the Functions managed-dependency declaration are data, not entrypoint guards. Their version values describe their own schemas or dependencies. |

The source lists are authoritative. In particular, a filename under
`tests/helpers` does not establish that it is an inherited fragment: the owner,
bridge, crash-control, exit-observer and fixture scripts are separately launched
and therefore own guards. `InstalledInventory.ps1` is a dot-sourced function
library; its regression script is an owning entrypoint.

Generated entrypoints must agree with their canonical source. Change
`build/azure/runbook-source.ps1` and the package builders, then regenerate the
checked-in Azure runbook/template publisher and any maintained generated Function
entrypoint through the existing build process. Do not patch a derived guard as a
substitute for fixing its source. Temporary build outputs and installed/vendor
directories excluded by Git are outside this maintained source inventory. A
vendored or historical script newly committed to this repository needs an
explicit policy decision; no current vendor/historical wildcard exemption exists.

Historical evidence, migration documentation, negative-test samples and unrelated
data/API/package version literals may legitimately mention earlier versions.
Changing every `7.0`, `7.2` or `7.4` string would erase evidence or change unrelated
contracts. The AST regression inspects actual script requirements and separately
retains the assertions for both setup runtime payloads, the distinct Automation
environment identity, explicit runbook binding and generated runtime guidance.
Its finite in-memory negative cases reject 7.0, 7.2, 7.4, a missing guard and a
guard that appears only as string data; these samples are parsed, never invoked.
Runtime tables are read with AST `SafeGetValue()`, never by invoking candidate
source text. A side-effect expression must be rejected while its marker remains
unchanged. The regression also extracts the single literal `$functionAppHeader`
assignment from the Function App builder with `SafeGetValue()` and checks its
effective guard, covering the generated entrypoint even when build output is
ignored by Git. The builder itself is not executed by this regression.

Run the existing bespoke regression with PowerShell 7.6+ from a Git checkout:

```powershell
pwsh -NoProfile -File tests/Invoke-SetupRuntimeRegression.ps1
```

This check does not run setup, authenticate, provision resources, install tools,
invoke Pester or prove an Azure-hosted runtime. Issue #92's live Azure validation
remains open until separately authorized execution supplies that evidence. The
repository guard and setup payload checks establish source intent, not live
runtime availability or endpoint behavior.

For a reviewed Automation deployment, `Setup-AzureResources.ps1` accepts
`-AutomationAzAccountsVersion` as an optional stable `major.minor.patch` value
(for example, the format `5.3.1`). Select the actual reviewed module version;
the example is not a package availability or compatibility claim. Setup uses
`https://www.powershellgallery.com/api/v2/package/Az.Accounts/<version>` and
requires the imported package's reported `properties.version` to match exactly
after its import completes. A missing/different version, failed/canceled import
or the existing 300-second import timeout stops pinned setup. Omitting the
parameter retains the existing latest Gallery URI and polling behavior.

This option applies only to Automation; Function App modules are bundled by
the package builder, and setup rejects this option with `-ComputeType FunctionApp`.
The existing named Automation runtime environment is still the target, so review
the effect on runbooks already bound to it before updating its module version.
The [Automation Package GET contract](https://learn.microsoft.com/en-us/rest/api/automation/package/get?view=rest-automation-2024-10-23)
documents the reported version. A versioned URI plus version readback is not
cryptographic package identity: this option does not fetch/hash a local Gallery
archive, supply a content hash, prove module loading, or establish source/package
correspondence for #92. Retain the selected source/package/module hashes and real
host observations separately in that deployment's evidence.
