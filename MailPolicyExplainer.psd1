﻿#
# Module manifest for module 'MailPolicyExplainer'
#
# Generated by: Colin Cogle
#
# Generated on: 4/18/2018
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'src/MailPolicyExplainer.psm1'

# Version number of this module.
ModuleVersion = '1.3.1'

# Supported PSEditions
CompatiblePSEditions = @('Core', 'Desktop')

# ID used to uniquely identify this module
GUID = 'b3ec0108-05d3-43f1-a5ba-cc8f7f4cc8cc'

# Author of this module
Author = 'Colin Cogle'

# Company or vendor of this module
#CompanyName = ''

# Copyright statement for this module
Copyright = '(c) 2018, 2020, 2023 Colin Cogle. All rights reserved.'

# Description of the functionality provided by this module
Description = "Explains a domain's email DNS records, including MX, SPF, DKIM, DMARC, and more."

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.1'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
#RequiredModules = @('Resolve-DnsNameCrossPlatform')

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = ''

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
	'Test-MailPolicy',
	'Test-MXRecord',
	'Test-IPVersions',
	'Test-DkimSelector',
	'Test-AdspRecord',
	'Test-DmarcRecord',
	'Test-BimiSelector',
	'Test-MtaStsPolicy',
	'Test-SmtpTlsReportingPolicy',
	'Test-SpfRecord',
	'Test-DaneRecord',
	'Invoke-GooglePublicDnsApi'
)

# Variables to export from this module
VariablesToExport = ''

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @(
	'Test-BimiRecord',
	'Test-DaneRecords',
	'Test-DkimRecord',
	'Test-DomainKeysRecord',
	'Test-DomainKeysSelector',
	'Test-MtaStsRecord',
	'Test-MXRecords',
	'Test-NullMXRecord',
	'Test-TlsaRecord',
	'Test-TlsaRecords'
)

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
FileList = @(
	'en-US/about_BIMI.help.txt',
	'en-US/about_DANERecords.help.txt',
	'en-US/about_DANERecordsAcronyms.help.txt',
	'en-US/about_DANERecordsUsage.help.txt',
	'en-US/about_DKIM.help.txt',
	'en-US/about_DKIMADSP.help.txt',
	'en-US/about_DKIMEd25519.help.txt',
	'en-US/about_DKIMRSAKeyUpdates.help.txt',
	'en-US/about_DMARC.help.txt',
	'en-US/about_IDNEmailAuthentication.help.txt',
	'en-US/about_MailPolicyExplainer.help.txt',
	'en-US/about_MTA-STS.help.txt',
	'en-US/about_MXRecords.help.txt',
	'en-US/about_NullMXRecords.help.txt',
	'en-US/about_SMTP.help.txt',
	'en-US/about_SMTPTLSReporting.help.txt',
	'en-US/about_SPF.help.txt',
	'src/MailPolicyExplainer.psm1',
	'AUTHORS.txt',
	'CHANGELOG.md',
	'CODE_OF_CONDUCT.md',
	'CONTRIBUTING.md',
	'INSTALL.md',
	'LICENSE.txt',
	'MailPolicyExplainer.psd1',
	'NEWS.md',
	'README.md',
	'SECURITY.md'
)

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

	PSData = @{
		#Prerelease = 'git'

		# Tags applied to this module. These help with module discovery in online galleries.
		Tags = @(
			'email', 'mail', 'SPF', 'DKIM', 'DMARC', 'BIMI', 'DNSSEC', 'DANE', 'MTA-STS', 'MX',
			'TLSRPT', 'STARTTLS', 'domainkey', 'TLS', 'TLSA', 'ADSP',  'DNS', 'policy', 'SenderID',
			'tester', 'Reporting', 'Test', 'Exchange', 'Office365', 'Google', 'Network', 'Cloud',
			'security', 'audit', 'IPv4', 'IPv6', 'SMTP', 'RSA', 'Ed25519',
			'Windows', 'MacOS', 'Linux', 'PSEdition_Core', 'PSEdition_Desktop'
		)

		# A URL to the license for this module.
		LicenseUri = 'https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/LICENSE.txt'

		# A URL to the main website for this project.
		ProjectUri = 'https://github.com/rhymeswithmogul/MailPolicyExplainer'

		# A URL to an icon representing this module.
		IconUri = 'https://raw.githubusercontent.com/rhymeswithmogul/MailPolicyExplainer/main/icon/PSGallery.png'

		# ReleaseNotes of this module
		ReleaseNotes = 'This release adds one new feature: IP version checks are now indented when run from `Test-MailPolicy`.

Many bugs were fixed, too:
- Implied MX records are now displayed correctly.
- `Test-DaneRecords` now correctly checks DANE records for domains without MX records.
- The DMARC `fo` token is now parsed correctly when multiple values are present.
- The DMARC `rf` token is now parsed correctly.
- The IntelliSense handling of `Test-SpfRecord` has been improved by hiding some internal-use-only parameters.
- The IP version checks now work with implied MX records.
- The MTA-STS policy file test returns a better error message when the file does not have the correct CRLF line endings.
- The SMTP TLS reporting policy test now checks to make sure exactly one `v` tag is present with the value `TLSRPTv1`.
- The SMTP TLS reporting policy test now fails gracefully when invalid text is returned.
- The SPF `exists` and `mx` token parsers no longer generate a spurious error when not counting DNS lookups.
- Online help is fixed for `Test-SmtpTlsReportingPolicy`, `Test-MtaStsPolicy`, and `Test-SpfRecord`.
- Cleaned up the output of `Test-DaneRecords` a little.
- Miscellaneous code cleanup.
'

	} # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

