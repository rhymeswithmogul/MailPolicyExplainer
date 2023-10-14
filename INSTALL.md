# Installing MailPolicyExplainer

## PowerShell Gallery

This is the recommended method of installation.

```powershell
Install-PSResource -Name "MailPolicyExplainer" -Repository "PSGallery"
```

## Manually

Copy all of these files into a subfolder in one of your user or system [PowerShell modules directories](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath).  By default, per-user modules are saved in:
- Windows: `~\Documents\PowerShell\Modules`
- macOS or Linux: `~/.local/share/powershell/Modules`

To find your module folders, `Write-Output $env:PSModulePath`.
