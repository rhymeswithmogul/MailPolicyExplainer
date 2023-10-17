# This file is part of MailPolicyExplainer.
#
# MailPolicyExplainer is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# MailPolicyExplainer is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
# for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with MailPolicyExplainer. If not, see <https://www.gnu.org/licenses/>. 

#Requires -Module Microsoft.PowerShell.Security, PSScriptAnalyzer, @{ModuleName='Pester';ModuleVersion='5.0.0'}

If (-Not $IsWindows) {
	Throw [PlatformNotSupportedException]::new('This script requires Microsoft Windows.')
}

#region Create a build directory.
# We will copy all important files to a temporary folder.  We're using
# New-Temporary file only to create a filename that the runtime guarantees to
# be unique.
$TempFile = New-TemporaryFile
Remove-Item -Path $TempFile
$DestinationPath = (Join-Path -Path $env:Temp -ChildPath $TempFile.Name)
$DestinationPath = (Join-Path -Path $DestinationPath -ChildPath 'MailPolicyExplainer')

Write-Output "Copying module to $DestinationPath"
New-Item -Path $DestinationPath -ItemType Directory -ErrorAction Stop
Copy-Item -Path '*' -Destination $DestinationPath -Recurse -Exclude @(
	'.git*',		# This can be retrieved from GitHub.
	'coverage.xml',	# junk
	'man',			# Get-Help should be used instead.
	'icon',			# we don't need in-module icons for a release.
	'release'		# You don't need this script.  Only I do.
)
Push-Location -Path $DestinationPath
#endregion

#region Sign all script files.
# This portion of the script signs all files with my code signing certificate.
# Since the command's default parameters are defined in my shell, and my private
# key requires protection, there are no secrets to hide in this script.  This
# will silently fail on all other computers except mine.
Write-Output "Signing all script files"
Get-ChildItem -Recurse -Include @('*.ps1','*.ps?1') | ForEach-Object {
	Set-AuthenticodeSignature $_ | Format-Table -AutoSize
}

Write-Output "Generating catalog"
New-FileCatalog -Path . -CatalogFilePath MailPolicyExplainer.cat -CatalogVersion 2.0
Set-AuthenticodeSignature 'MailPolicyExplainer.cat'
#endregion

#region Invoke PSScriptAnalyzer.
Write-Output "Calling PSScriptAnalyzer with Gallery settings"
$analysis = Invoke-ScriptAnalyzer -Path . -Recurse -Settings PSGallery
Write-Output $analysis
If ($analysis.Count -gt 0)
{
	Throw 'Please correct PSScriptAnalyzer errors and try again.'
}
#endregion

#region Run Pester tests.
Write-Output "Running Pester tests"
Invoke-Pester
#endregion

Start-Process -FilePath 'C:\Windows\Explorer.exe' -ArgumentList $DestinationPath
Pop-Location