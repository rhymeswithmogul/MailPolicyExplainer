﻿<#
MailPolicyExplainer.psm1 -- source file for said module
Copyright (C) 2018, 2020, 2023-2025 Colin Cogle.  All Rights Reserved.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along
with this program.  If not, see <https://www.gnu.org/licenses/>.
#>

#region Helper functions
# The following functions are used internally by MailPolicyExplainer and are not
# exposed to the end user.

Function Write-GoodNews
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Output colored text in a PS5-compatible manner.')]
	[OutputType([Void])]
	Param(
		[Parameter(Position=0)]
		[AllowNull()]
		[String] $Message
	)

	Write-Host -ForegroundColor Green -Object "✅`t$Message"
}

Function Write-BadPractice
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Output colored text in a PS5-compatible manner.')]
	[OutputType([Void])]
	Param(
		[Parameter(Position=0)]
		[AllowNull()]
		[String] $Message
	)

	Write-Host -ForegroundColor Yellow -Object "🟨`t$Message"
}

Function Write-BadNews
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Output colored text in a PS5-compatible manner.')]
	[OutputType([Void])]
	Param(
		[Parameter(Position=0)]
		[AllowNull()]
		[String] $Message
	)

	Write-Host -ForegroundColor Red -Object "❌`t$Message"
}

Function Write-Informational
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Output colored text in a PS5-compatible manner.')]
	[OutputType([Void])]
	Param(
		[Parameter(Mandatory, Position=0)]
		[AllowNull()]
		[String] $Message
	)

	Write-Host -ForegroundColor White -Object "ℹ️`t$Message"
}

Function Write-DnsLookups
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='We are counting multiple lookups.')]
	[OutputType([String])]
	Param(
		[Parameter(Mandatory, Position=0)]
		[UInt32] $DnsLookups,

		[Switch] $Enabled
	)

	If ($Enabled) {
		Return " ($DnsLookups/10 DNS lookups)"
	}
}

Function Get-RandomString
{
	[OutputType([String])]
	Param()

	# We're going to return a random string of varying length to prevent passive
	# cryptanalysis attacks (which are extremely unlikely).  16 to 256 bytes of
	# added entropy should be sufficient, without pushing our packets too close
	# to the smallest-possible MTU of 576 bytes (for IPv4).
	$retvalLength = Get-Random -Minimum 16 -Maximum 256

	# Per Google's advice, we will use random padding consisting of URL-safe
	# characters:  A-Z, a-z, 0-9, period, underscore, hyphen, and tilde.
	# Because Get-Random removes an item after selecting it, we're "multiplying"
	# this string array by 30, so that we can pull up to $(2048 - 90) characters
	# in Invoke-GooglePublicDnsApi (in case someone decides to increase the
	# -Maximum value to the previous Get-Random call).
	$chars = [Char[]]('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~._-' * 30)
	Return ((Get-Random -InputObject $chars -Count $retvalLength) -Join '')
}

Function Get-RSAPublicKeyLength
{
	[OutputType([UInt16])]
	Param(
		[Parameter(Mandatory, Position=0)]
		[String] $PublicKey
	)

	$rsa = [Security.Cryptography.RSACryptoServiceProvider]::new()

	# .NET 7 adds the ImportFromPem method to instances of the RSA class.
	# If it's available, use it.
	If ($null -ne (Get-Member -InputObject $rsa | Where-Object Name -eq 'ImportFromPem'))
	{
		$rsa.ImportFromPem("-----BEGIN PUBLIC KEY-----`r`n$PublicKey`r`n-----END PUBLIC KEY-----")
		Return $rsa.KeySize
	}
	# If we're using the older .NET Framework (Windows PowerShell), then we can
	# only guess on the key length by looking at the size of the encoded data.
	# If anyone knows a better way to make this work on .NET 6 and older, please
	# submit a pull request!
	Else {
		Write-Verbose 'Accurate DKIM key length detection requires PowerShell 7.  We will do our best to guess.'
		Switch ($PublicKey.Length) {
			392		{Return 2048}
			216		{Return 1024}
			168		{Return 768}
			128		{Return 512}
			default	{Return 'unknown'}
		}
	}
}

Function Test-IPv4Address
{
	[CmdletBinding()]
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[String] $HostName
	)

	Return (Invoke-GooglePublicDnsApi $HostName -Type 'A').PSObject.Properties.Name -Match 'Answer'
}

Function Test-IPv6Address
{
	[CmdletBinding()]
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[String] $HostName
	)

	Return (Invoke-GooglePublicDnsApi $HostName -Type 'AAAA').PSObject.Properties.Name -Match 'Answer'
}
#endregion Helper functions

Function Invoke-GooglePublicDnsApi
{
	[CmdletBinding()]
	[OutputType([PSObject])]
	Param(
		[Parameter(Position=0, Mandatory)]
		[ValidateNotNullOrEmpty()]
		[String] $InputObject,

		[Parameter(Position=1)]
		[ValidateSet('A', 'AAAA', 'CNAME', 'MX', 'SPF', 'TLSA', 'TXT')]
		[String] $Type = 'A',

		[Alias('CD', 'DnssecCD', 'NoDnssec', 'DisableDnssec')]
		[Switch] $DisableDnssecVerification
	)

	$MaxLengthOfPadding = 1958 - $InputObject.Length - $Type.Length

	If ($DisableDnssecVerification) {
		$CD = 1
	} Else {
		$CD = 0
	}

	$ToSend = @{
		'name'           = $InputObject
		'type'           = $Type
		'ct'             = 'application/x-javascript'
		'cd'             = $CD	# enable DNSSEC validation (by default)...
		'do'             = 0	# ...but don't return RRSIGs. Trust the resolver.
		'random_padding' = Get-RandomString -MaxLength $MaxLengthOfPadding -MinLength $MaxLengthOfPadding
	}

	Write-Verbose "Sending $($ToSend.random_padding.Length) characters of random padding."

	# DNS-over-HTTPS requests are supposed to use HTTP/2 or newer.  However,
	# Invoke-RestMethod's -HttpVersion parameter was added in PowerShell 7.3.
	# Downlevel versions of PowerShell only used HTTP/1.1, which is thankfully
	# supported by the Google Public DNS API.
	#
	# Thus, our code will attempt to use HTTP/3 if it's available, and fall back
	# to the system default if not.
	$RequestParams = @{
		'Method'  = 'GET'
		'Uri'     = 'https://dns.google/resolve'
		'Body'    = $ToSend
		'Verbose' = $VerbosePreference
	}
	If ((Get-Command 'Invoke-RestMethod').Parameters.Keys -Contains 'HttpVersion') {
		$RequestParams += @{'HttpVersion' = '3.0'}
	}

	$result = Invoke-RestMethod @RequestParams
	Write-Debug $result
	Return $result
}

Function Test-IPVersions
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='We are always testing both IP versions.')]
	[CmdletBinding()]
	[OutputType([Void])]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[String] $HostName,

		[Parameter(DontShow)]
		[Switch] $IndentOutput
	)

	$Indent = ''
	If ($IndentOutput) {
		$Indent = '├──'
	}

	If (Test-IPv4Address $HostName) {
		Write-GoodNews "${Indent}IP: The server $HostName has an IPv4 address."
	}
	Else {
		Write-BadPractice "${Indent}IP: The server $HostName has no IPv4 addresses. IPv4-only clients cannot reach this server."
	}

	If (Test-IPv6Address $HostName) {
		Write-GoodNews "${Indent}IP: The server $HostName has an IPv6 address."
	}
	Else {
		Write-BadPractice "${Indent}IP: The server $HostName has no IPv6 addresses. IPv6-only clients cannot reach this server!"
	}
}

Function Test-AdspRecord
{
	[CmdletBinding()]
	[OutputType([Void])]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[string] $DomainName,

		[Alias('CD', 'DnssecCD', 'NoDnssec', 'DisableDnssec')]
		[Switch] $DisableDnssecVerification
	)

	$DnsLookup = Invoke-GooglePublicDnsApi "_adsp._domainkey.$DomainName" 'TXT' -Debug:$DebugPreference -DisableDnssecVerification:$DisableDnssecVerification
	$ADSPRecordFound = $DnsLookup.PSObject.Properties.Name -Contains 'Answer' -and $DnsLookup.Status -ne 3

	#region DNSSEC check
	# Since DKIM ADSP is historic, I don't want the DNSSEC-authenticated denial
	# of existence to show up when using Test-MailPolicy.  Only show the DNSSEC
	# information when calling this function directly, or if there is an ADSP
	# record to display.
	If (-Not $DisableDnssecVerification -and ($ADSPRecordFound -or ((Get-PSCallStack).Command)[1] -ne 'Test-MailPolicy'))
	{
		If ($DnsLookup.AD) {
			Write-GoodNews "DKIM ADSP: This DNS lookup is secure."
		}
		Else {
			Write-BadPractice "DKIM ADSP: This DNS lookup is insecure. Enable DNSSEC for this domain."
		}
	}
	#endregion

	If (-Not $ADSPRecordFound)
	{
		Write-Verbose 'DKIM ADSP: No ADSP record was found.'
	}
	Else
	{
		Write-BadPractice "DKIM ADSP: Author Domain Signing Practices is declared historic and should not be relied on."
		$AdspRecord = $DnsLookup.Answer.Data

		If ($AdspRecord -Eq "dkim=unknown") {
			Write-Informational "DKIM ADSP: This domain's ADSP is unknown; it may sign no, some, most, or all email with DKIM."
		}
		ElseIf ($AdspRecord -Eq "dkim=all") {
			Write-GoodNews "DKIM ADSP: ADSP says all email from this domain will have a DKIM signature."
		}
		ElseIf ($AdspRecord -Eq "dkim=discardable") {
			Write-GoodNews "DKIM ADSP: ADSP says all email from this domain will have a DKIM signature, and mail with a missing or bad signature should be discarded."
		}
		Else {
			Write-BadNews "DKIM ADSP: An invalid ADS practice was specified ($AdspRecord)."
		}
	}
}

Function Test-BimiSelector
{
	[CmdletBinding()]
	[OutputType([Void])]
	[Alias('Test-BimiRecord')]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[string] $DomainName,

		[Parameter(Position=1)]
		[Alias('Selector', 'SelectorName')]
		[string] $Name = 'default',

		[Alias('CD', 'DnssecCD', 'NoDnssec', 'DisableDnssec')]
		[Switch] $DisableDnssecVerification
	)

	$DnsLookup = Invoke-GooglePublicDnsApi "$Name._bimi.$DomainName" 'TXT' -Debug:$DebugPreference -DisableDnssecVerification:$DisableDnssecVerification

	#region DNSSEC check
	If (-Not $DisableDnssecVerification) {
		If ($DnsLookup.AD) {
			Write-GoodNews "BIMI selector ${Selector}: This DNS lookup is secure."
		}
		Else {
			Write-BadPractice "BIMI selector ${Selector}: This DNS lookup is insecure. Enable DNSSEC for this domain."
		}
	}
	#endregion

	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-Informational "BIMI selector ${Selector}: Not found!"
		Return
	}

	$BimiRecord = ($DnsLookup.Answer | Where-Object type -eq 16).Data
	If ($null -eq $BimiRecord)
	{
		Write-BadNews "BIMI selector ${Selector}: A record exists with no valid data!"
		Return
	}

	ForEach ($token in ($BimiRecord -Split ';')) {
		$token = $token.Trim()

		If ($token -Eq "v=BIMI1") {
			Write-GoodNews "BIMI selector ${Selector}: This is a BIMI version 1 record."
		}

		# BIMI evidence document tag
		ElseIf ($token -Like "a=*") {
			$policy = $token -Replace 'a='
			If ($null -ne $policy) {
				Write-GoodNews "BIMI selector ${Selector}: An authority evidence document can be found at $policy."
			}
			Else {
				Write-Informational 'BIMI selector ${Selector}: No authority evidence is available.'
			}
		}
		ElseIf ($token -Like "l=*") {
			$locationURI = $token -Replace 'l='
			If ($null -eq $locationURI) {
				Write-Informational "BIMI selector ${Selector}: This domain does not participate in BIMI."
			}
			ElseIf ($locationURI -Like 'https://*') {
				Write-GoodNews "BIMI selector ${Selector}: The brand indicator is at $locationURI."
			}
			Else {
				Write-BadNews "BIMI selector ${Selector}: The brand indicator must be available over HTTPS! ($locationURI)"
			}
		}
		ElseIf ($token.Length -gt 0) {
			Write-BadNews "BIMI selector ${Selector}: An invalid tag was specified ($token)."
		}
	}
}

Function Test-DaneRecord
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DisableDnssecVerification', Justification='This is for compatibility purposes and does not do anything.')]
	[CmdletBinding()]
	[OutputType([Void])]
	[Alias('Test-DaneRecords', 'Test-TlsaRecord', 'Test-TlsaRecords')]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[String] $DomainName,

		[Parameter(DontShow)]
		[Alias('CD', 'DnssecCD', 'NoDnssec', 'DisableDnssec')]
		[Switch] $DisableDnssecVerification
	)

	# Fetch all MX records for this domain.
	$MXServers = @()
	Invoke-GooglePublicDnsApi $DomainName 'MX' -Debug:$DebugPreference `
		| Select-Object -ExpandProperty Answer `
		| Where-Object type -eq 15 `
		| Select-Object -ExpandProperty Data `
		| ForEach-Object `
	{
		$Preference, $Name = $_ -Split "\s+"
		$MXServers += @{'Preference'=[UInt16]$Preference; 'Server'=$Name}
	}

	If ($MXServers.Count -eq 1 -and $MXServers[0].Server -eq '.') {
		Write-Verbose 'DANE: This domain does not receive email.'
		Return
	}

	# Check for the confusing case where a domain has no MX servers, and does
	# not publish a null MX record. In that case, the domain's A and AAAA records
	# will be substituted as a mail exchanger with preference 0. (Really, that's
	# what it says to do in the RFC.  Go look it up.)
	#
	# We're checking for a count of zero, or a count of one where the server
	# name is blank, just in case I add options for other DNS APIs in the future.
	# Google Public DNS's API returns the latter format.
	If ($MXServers.Count -eq 0)
	{
		$MXServers = @(@{'Preference'=0; 'Server'=$DomainName})
	}

	$MXServers | Sort-Object Preference | ForEach-Object {
		# Strip the trailing dot, if present. This is done for display purposes.
		$MXName = $_.Server -Replace '\.$'

		$DnsLookup = Invoke-GooglePublicDnsApi "_25._tcp.$MXName" 'TLSA' -Debug:$DebugPreference
		$FoundDANERecords = ($DnsLookup.PSObject.Properties.Name -Contains 'Answer') -and ($DnsLookup.Status -ne 2) -and ($DnsLookup.Status -ne 3)

		#region DNSSEC check
		# Complain if the user attempted to disable DNSSEC checking.  That's a
		# requirement for DANE.  Politely refuse to honor the user's request and
		# check DNSSEC anyway. This will only happen if the user is entering
		# this function call via Test-MailPolicy.
		If ($FoundDANERecords)
		{
			If ($DisableDnssecVerification -and -not $ShowedDnssecWarning)
			{
				Write-Informational 'DANE: Records must be signed with DNSSEC. Validating DANE anyway.'
				$ShowedDnssecWarning = $true
			}

			If ($DnsLookup.AD) {
				Write-GoodNews "DANE: ${MXName}: The DNS lookup is secure."
			}
			Else {
				Write-BadNews "DANE: ${MXName}: The DNS lookup is insecure; the DANE records cannot be used!  Enable DNSSEC for this domain."
				Return
			}
		}
		#endregion

		If (-Not $FoundDANERecords)
		{
			Write-BadNews "DANE: DANE records are not present for ${MXName}, TCP port 25."
			Return
		}

		($DnsLookup.Answer | Where-Object type -eq 52).Data | ForEach-Object {
			$Usage, $Selector, $Type, $CertData = $_ -Split '\s+'

			If ($Selector -NotIn 0,1) {
				Write-BadNews "DANE: ${MXName}: The DANE record is invalid! (Unknown Selector $Selector)"
				Continue
			}
			ElseIf ($Type -NotIn 0,1,2) {
				Write-BadNews "DANE: ${MXName}: The DANE record is invalid! (Unknown Type $Selector)"
				Continue
			}

			Switch ($Usage) {
				0 {
					Write-BadPractice "DANE: ${MXName}: Found a PKIX-TA record, which is not supported for SMTP: $Usage $Selector $Type $CertData (not checked)"
				}
				1 {
					Write-BadPractice "DANE: ${MXName}: Found a PKIX-EE record, which is not supported for SMTP: $Usage $Selector $Type $CertData (not checked)"
				}
				2 {
					Write-GoodNews "DANE: ${MXName}: Found a DANE-TA record: $Usage $Selector $Type $CertData (not checked)"
				}
				3 {
					Write-GoodNews "DANE: ${MXName}: Found a DANE-EE record: $Usage $Selector $Type $CertData (not checked)"
				}
				default {
					Write-BadNews "DANE: ${MXName}: The DANE record is invalid! (Unknown Usage $Usage)"
				}
			}
		}
	}
}

Function Test-DkimSelector
{
	[CmdletBinding()]
	[OutputType([Void])]
	[Alias('Test-DkimRecord', 'Test-DomainKeysSelector', 'Test-DomainKeysRecord')]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[string] $DomainName,

		[Parameter(Mandatory, Position=1)]
		[Alias('Selector', 'SelectorName', 'KeyName')]
		[string]$Name,

		[Alias('CD', 'DnssecCD', 'NoDnssec', 'DisableDnssec')]
		[Switch] $DisableDnssecVerification
	)

	$DnsLookup = Invoke-GooglePublicDnsApi "$Name._domainkey.$DomainName" 'TXT' -Debug:$DebugPreference -DisableDnssecVerification:$DisableDnssecVerification
	$Name = " $Name"

	#region DNSSEC check
	If (-Not $DisableDnssecVerification) {
		If ($DnsLookup.AD) {
			Write-GoodNews "DKIM selector${Name}: This DNS lookup is secure."
		}
		Else {
			Write-BadPractice "DKIM selector${Name}: This DNS lookup is insecure. Enable DNSSEC for this domain."
		}
	}
	#endregion

	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-BadNews "DKIM selector${Name}: This selector was not found."
		Return
	}

	$DkimKeyRecord = ($DnsLookup.Answer | Where-Object type -eq 16).Data
	If ($null -eq $DkimKeyRecord)
	{
		Write-BadNews "DKIM selector${Name}: This selector was not found in DNS."
		Return
	}
	Else {
		Write-Verbose "DKIM selector${Name}: `"$DkimKeyRecord`""
	}

	#region Check for default values.
	# If there is no "k=" token, it's assumed to be "k=rsa" (per the RFC).
	# Additionally, if there is no "v=" token, it's assumed to be "v=DKIM1".
	$VersionImplied = $false
	$KeyTypeImplied = $false

	If ($DkimKeyRecord -NotLike "*v=*")
	{
		$DkimKeyRecord = "v=DKIM1; $DkimKeyRecord"
		$VersionImplied = $true
	}
	If ($DkimKeyRecord -NotLike "*k=*")
	{
		$DkimKeyRecord = $DkimKeyRecord.Replace(';', ';k=rsa;', 1)
		$KeyTypeImplied = $true
	}
	#endregion

	ForEach ($token in ($DkimKeyRecord -Split ';')) {
		$token = $token.Trim()
		If ($token -Like "v=*") {
			$version = $token -Replace 'v=',''
			If ($VersionImplied) {
				Write-GoodNews "DKIM selector${Name}: This is implied to conform to DKIM version 1."
			}
			ElseIf ($version -Eq 'DKIM1') {
				Write-GoodNews "DKIM selector${Name}: This conforms to DKIM version 1."
			} Else {
				Write-BadNews "DKIM selector${Name}: This does not conform to DKIM version 1."
				Return
			}
		}
		ElseIf ($token -Like "s=*") {
			ForEach ($purpose in ($token -Replace 's=' -Split ':')) {
				$purpose = $purpose.Trim()
				If ($purpose -Eq '*') {
					Write-GoodNews "DKIM selector${Name}: This key is valid for all purposes."
				}
				ElseIf ($purpose -Eq 'email') {
					Write-GoodNews "DKIM selector${Name}: This key is valid for email."
				}
				Else {
					Write-BadPractice "DKIM selector${Name}: This key is valid for $purpose, which is not part of the DKIM specification."
				}
			}
		}
		ElseIf ($token -Like "k=*") {
			$algorithm  = $token -Replace 'k='

			If ($KeyTypeImplied) {
				Write-GoodNews "DKIM selector${Name}: This is implied to have an RSA key."
			}
			ElseIf ($algorithm -Eq 'rsa') {
				Write-GoodNews "DKIM selector${Name}: This has an RSA key."
			}
			ElseIf ($algorithm -eq 'ed25519') {
				Write-GoodNews "DKIM selector${Name}: This has an Ed25519 key.  Not all verifiers can verify these newer keys."
			}
			Else {
				Write-BadNews "DKIM selector${Name}: This has an unknown key type ($algorithm)!"
			}
		}
		ElseIf ($token -Like "h=*") {
			ForEach ($algorithm in ($token -Replace 'h=' -Split ':')) {
				$algorithm = $algorithm.Trim()
				If ($algorithm -Eq 'sha1') {
					Write-BadPractice "DKIM selector${Name}: This key will sign only SHA-1 hashes, which are deprecated."
				}
				ElseIf ($algorithm -Eq 'sha256') {
					Write-GoodNews "DKIM selector${Name}: This key will sign only SHA-256 hashes."
				}
				Else {
					Write-BadNews "DKIM selector${Name}: This key will sign only $algorithm hashes, which are not part of the DKIM specification."
				}
			}
		}
		ElseIf ($token -Like 't=*') {
			ForEach ($flag in ($token -Replace 't=' -Split ':')) {
				$flag = $flag.Trim()
				If ($flag -Eq 'y') {
					Write-Informational "DKIM selector${Name}: This domain is testing DKIM; recipients should treat signed and unsigned messages identically."
				}
				ElseIf ($flag -Eq 's') {
					Write-GoodNews "DKIM selector${Name}: This selector is not valid for subdomains."
				}
				Else {
					Write-BadNews "DKIM selector${Name}: An unknown flag $flag was specified."
				}
			}
		}
		ElseIf ($token -Like "g=*") {
			$username = $token -Replace 'g='
			Write-Informational "DKIM selector${Name}: This selector will only sign emails from the username $username."
		}
		ElseIf ($token -Like 'p=*') {
			$publickey = $token -Replace 'p='

			If ($DkimKeyRecord -match 'k=ed25519') {
				Write-GoodNews "DKIM selector${Name}: The Ed25519 public key size is 256 bits."
			}
			ElseIf ($DkimKeyRecord -Match 'k=rsa') {
				$bits = Get-RSAPublicKeyLength $publickey
				If ($bits -gt 4096) {
					Write-BadPractice "DKIM selector${Name}: The RSA public key size is $bits bits. Verifiers may not support keys this large."
				}
				ElseIf ($bits -ge 2048) {
					Write-GoodNews "DKIM selector${Name}: The RSA public key size is $bits bits."
				}
				ElseIf ($bits -ge 1024) {
					Write-BadPractice "DKIM selector${Name}: The RSA public key size is only $bits bits.  Upgrade to 2048 bits."
				}
				Else {
					Write-BadNews "DKIM selector${Name}: The RSA public key size is only $bits bits. This key is too small to be used. Replace it with an Ed25519 or 2048-bit RSA key!"
				}
			}
		}
		ElseIf ($token -Like 'n=*') {
			Write-Informational "DKIM selector${Name}: Some notes: $($token -Replace 'n=')"
		}
		ElseIf ($token.Length -gt 0) {
			Write-BadNews "DKIM selector${Name}: An invalid selector token was specified ($token)."
		}
	}
}

Function Test-DmarcRecord
{
	[CmdletBinding()]
	[OutputType([Void])]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[string] $DomainName,

		[Alias('CD', 'DnssecCD', 'NoDnssec', 'DisableDnssec')]
		[Switch] $DisableDnssecVerification
	)

	$DnsLookup = Invoke-GooglePublicDnsApi "_dmarc.$DomainName" 'TXT' -Debug:$DebugPreference -DisableDnssecVerification:$DisableDnssecVerification

	#region DNSSEC check
	If (-Not $DisableDnssecVerification) {
		If ($DnsLookup.AD) {
			Write-GoodNews "DMARC: This DNS lookup is secure."
		}
		Else {
			Write-BadPractice "DMARC: This DNS lookup is insecure. Enable DNSSEC for this domain."
		}
	}
	#endregion

	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-BadNews "DMARC: Not found!"
		Return
	}

	$DmarcRecord = ($DnsLookup.Answer | Where-Object type -eq 16).Data
	If ($null -eq $DmarcRecord)
	{
		Write-BadNews "DMARC: A record exists with no valid data!"
		Return
	}

	ForEach ($token in ($DmarcRecord -Split ';')) {
		$token = $token.Trim()

		If ($token -Eq "v=DMARC1") {
			Write-GoodNews "DMARC: This is a DMARC version 1 record."
		}
		ElseIf ($token -Like "p=*") {
			$policy = $token -Replace 'p='
			If ($policy -Eq 'none') {
				Write-Informational 'DMARC: Report but deliver messages that fail DMARC.'
			} ElseIf ($policy -Eq 'quarantine') {
				Write-GoodNews 'DMARC: Quarantine messages that fail DMARC.'
			} ElseIf ($policy -Eq 'reject') {
				Write-GoodNews 'DMARC: Reject messages that fail DMARC.'
			} Else {
				Write-BadNews "DMARC: An invalid policy was specified ($policy)."
			}
		}
		ElseIf ($token -Like "sp=*") {
			$subdomainpolicy = $token -Replace 'sp='
			If ($subdomainpolicy -Eq 'none') {
				Write-Informational 'DMARC: Report but deliver messages from subdomains (without their own DMARC records) that fail DMARC.'
			} ElseIf ($subdomainpolicy -Eq 'quarantine') {
				Write-GoodNews 'DMARC: Quarantine messages from subdomains (without their own DMARC records) that fail DMARC.'
			} ElseIf ($subdomainpolicy -Eq 'reject') {
				Write-GoodNews 'DMARC: Reject messages from subdomains (without their own DMARC records) that fail DMARC.'
			} Else {
				Write-BadNews "DMARC: An invalid subdomain policy was specified ($subdomainpolicy)."
			}
		}
		ElseIf ($token -Like "pct=*") {
			$pct = [Byte]($token -Replace 'pct=')
			If ($pct -eq 100) {
				If ($policy -Match "reject") {
					Write-Informational "DMARC: Reject 100% of email that fails DMARC (default)."
				}
				ElseIf ($policy -Match 'quarantine') {
					Write-Informational "DMARC: Quarantine 100% of email that fails DMARC (default)."
				}
			}
			Else {
				If ($policy -Match "reject") {
					Write-Informational "DMARC: Only reject ${pct}% of unaligned email; the rest will be quarantined."
				}
				ElseIf ($policy -Match 'quarantine') {
					Write-BadPractice "DMARC: Only quarantine ${pct}% of unaligned email; the rest will be delivered."
				}
			}
		}
		ElseIf ($token -Like "aspf=*") {
			Switch ($token -Replace 'aspf=') {
				's'  { Write-Informational 'DMARC: SPF alignment is strict (From domain = MailFrom domain).' }
				'r'  { Write-Informational 'DMARC: SPF alignment is relaxed (From domain = MailFrom domain or a subdomain; default).' }
				Else { Write-BadNews  "DMARC: An invalid SPF alignment was specified ($token)." }
			}
		}
		ElseIf ($token -Like "adkim=*") {
			Switch ($token -Replace 'adkim=') {
				's'  { Write-Informational 'DMARC: DKIM alignment is strict (domain = signing domain).' }
				'r'  { Write-Informational 'DMARC: DKIM alignment is relaxed (domain = signing domain or a subdomain; default).' }
				Else { Write-BadNews  "DMARC: An invalid DKIM alignment was specified ($token)." }
			}
		}
		ElseIf ($token -Like 'fo=*') {
			If ($DmarcRecord -Match 'ruf=') {
				Switch ($token.Substring(3) -Split ':') {
					0    { Write-Informational 'DMARC: Generate a forensic report if SPF and DKIM both fail (default).' }
					1    { Write-Informational 'DMARC: Generate a forensic report if either SPF or DKIM fail.'}
					'd'  { Write-Informational 'DMARC: Generate a forensic report if DKIM fails, even if DMARC passes.' }
					's'  { Write-Informational 'DMARC: Generate a forensic report if SPF fails, even if DMARC passes.' }
					Else { Write-BadNews  "DMARC: An invalid failure reporting tag was specified ($token)." }
				}
			} Else {
				Write-BadPractice 'DMARC: The failure reporting options will be ignored because a forensic report destination (ruf) was not specified.'
			}
		}
		ElseIf ($token -Like 'rf=*') {
			$formats = $token.Substring(3) -Split ':'
			ForEach ($format in $formats) {
				$format = $format.Trim()
				If ($format -eq 'afrf') {
					Write-Informational 'DMARC: Failure reports can be sent in AFRF format (default).'
				}
				Else {
					Write-BadNews "DMARC: The reporting format $format is not an allowed format.  Mail receivers may ignore the entire DMARC record."
				}
			}
		}
		ElseIf ($token -Like 'ri=*') {
			$interval = [UInt32]($token -Replace 'ri=')
			If ($interval -Eq 86400) {
				Write-Informational "DMARC: Aggregate reports should (if possible) be sent no more than daily (default)."
			} Else {
				Write-Informational "DMARC: Aggregate reports should (if possible) be sent no more than every $interval seconds."
			}
		}
		ElseIf ($token -Like 'rua=*') {
			ForEach ($destination in ($token -Replace 'rua=' -Split ',')) {
				Write-Informational "DMARC: Aggregate reports will be sent to $destination."
			}
		}
		ElseIf ($token -Like 'ruf=*') {
			ForEach ($destination in ($token -Replace 'ruf=' -Split ',')) {
				Write-Informational "DMARC: Forensic reports will be sent to $destination (if the sender supports forensic reports)."
			}
		}
		ElseIf ($token.Length -gt 0) {
			Write-BadNews "DMARC: An invalid tag was specified ($token)."
		}
	}
}

Function Test-MailPolicy
{
	[CmdletBinding()]
	[OutputType([Void])]
	Param(
		[Parameter(Mandatory, Position=0)]
		[String] $DomainName,

		[Alias('Recurse')]
		[Switch] $CountSpfDnsLookups,

		[Alias('dkim')]
		[String[]] $DkimSelectorsToCheck,

		[Alias('ExchangeOnline', 'Microsoft365', 'Microsoft365Dkim', 'Office365', 'Office365Dkim')]
		[Switch] $ExchangeOnlineDkim,

		[Alias('bimi')]
		[String[]] $BimiSelectorsToCheck,

		[Alias('CD', 'DnssecCD', 'NoDnssec', 'DisableDnssec')]
		[Switch] $DisableDnssecVerification
	)

	Write-Output "Analyzing email records for $DomainName"
	Test-MXRecord $DomainName -DisableDnssecVerification:$DisableDnssecVerification
	Test-SpfRecord $DomainName -Recurse:$CountSpfDnsLookups -DisableDnssecVerification:$DisableDnssecVerification
	If ($ExchangeOnlineDkim) {
		$x = @('selector1', 'selector2')
		ForEach ($selector in $DkimSelectorsToCheck) {
			If ($selector -ne 'selector1' -and $selector -ne 'selector2') {
				$x += $selector
			}
		}
		$DkimSelectorsToCheck = $x
	}
	If ($DkimSelectorsToCheck.Count -gt 0) {
		$DkimSelectorsToCheck | ForEach-Object {
			Test-DkimSelector $DomainName -Name $_ -DisableDnssecVerification:$DisableDnssecVerification
		}
	}
	Test-ADSPRecord $DomainName -DisableDnssecVerification:$DisableDnssecVerification
	Test-DmarcRecord $DomainName -DisableDnssecVerification:$DisableDnssecVerification
	If ($BimiSelectorsToCheck.Count -gt 0) {
		$BimiSelectorsToCheck | ForEach-Object {
			Test-BimiSelector $DomainName -Name $_ -DisableDnssecVerification:$DisableDnssecVerification
		}
	}
	Test-MtaStsPolicy $DomainName -DisableDnssecVerification:$DisableDnssecVerification
	Test-SmtpTlsReportingPolicy $DomainName -DisableDnssecVerification:$DisableDnssecVerification
	Test-DaneRecord $DomainName -DisableDnssecVerification:$DisableDnssecVerification
}

Function Test-MtaStsPolicy
{
	[CmdletBinding()]
	[OutputType([Void])]
	[Alias('Test-MtaStsRecord')]
	Param(
		[Parameter(Mandatory, Position=0)]
		[String] $DomainName,

		[Alias('CD', 'DnssecCD', 'NoDnssec', 'DisableDnssec')]
		[Switch] $DisableDnssecVerification
	)

	$DnsLookup = Invoke-GooglePublicDnsApi "_mta-sts.$DomainName" 'TXT' -Debug:$DebugPreference -DisableDnssecVerification:$DisableDnssecVerification

	#region DNSSEC check
	If (-Not $DisableDnssecVerification) {
		If ($DnsLookup.AD) {
			Write-GoodNews "MTA-STS Record: This DNS lookup is secure."
		}
		Else {
			Write-BadPractice "MTA-STS Record: This DNS lookup is insecure. Enable DNSSEC for this domain."
		}
	}
	#endregion

	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-BadNews "MTA-STS Record: Not found! (Skipping policy test.)"
		Return
	}

	$MtaStsRecord = ($DnsLookup.Answer | Where-Object Type -eq 16).Data
	If ($null -eq $MtaStsRecord)
	{
		Write-BadNews "MTA-STS Record: A record exists with no valid data!"
		Return
	}

	$validSTSrecords = 0
	ForEach ($token in ($MtaStsRecord -Split ';')) {
		$token = $token.Trim()

		If ($token -CLike "v=*") {
			If ($token -eq 'v=STSv1') {
				Write-GoodNews "MTA-STS Record: This domain's STS record is version 1."
				$validSTSrecords++
			}
			Else {
				Write-BadNews "MTA-STS Record: This domain's STS record is an unsupported version ($($token -Replace 'v='))."
			}
		}
		ElseIf ($token -CLike 'id=*') {
			Write-Informational "MTA-STS Record: The domain's policy tag is $($token -Replace 'id=')."
		}
		ElseIf ($token.Length -gt 0) {
			Write-BadNews "MTA-STS Record: An unknown tag was found: $token"
		}
	}
	If ($validSTSrecords -ne 1) {
		Write-BadNews "MTA-STS Record: We did not find exactly one STS TXT record.  We must assume MTA-STS is not supported!"
		Return
	}

	#region Fetch the MTA-STS policy file.
	# Connect to the remote server and download the file. We'll try with TLS 1.3
	# first, then again with TLS 1.2.  (TLS version support depends on the host
	# operating system and PowerShell version.)
	Test-IPVersions "mta-sts.$DomainName"

	$oldSP      = [Net.ServicePointManager]::SecurityProtocol
	$ModuleInfo = (Get-Module 'MailPolicyExplainer')
	$iwrParams  = @{
		'Method'          = 'GET'
		'Uri'             = "https://mta-sts.$DomainName/.well-known/mta-sts.txt"
		'UseBasicParsing' = $true
		'UserAgent'       = "Mozilla/5.0 ($($PSVersionTable.Platform); $($PSVersionTable.OS); $PSCulture) PowerShell/$($PSVersionTable.PSVersion) MailPolicyExplainer/$($ModuleInfo.Version)"
		'ErrorAction'     = 'Stop'
	}
	Try {
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13
		$policy = Invoke-WebRequest @iwrParams
		Write-GoodNews "MTA-STS Policy: Downloaded the policy file from mta-sts.$DomainName using TLS 1.3."
	}
	Catch {
		Try {
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
			$policy = Invoke-WebRequest @iwrParams
			Write-GoodNews "MTA-STS Policy: Downloaded the policy file from mta-sts.$DomainName using TLS 1.2."
		}
		Catch {
			Write-BadNews "MTA-STS Policy: Could not connect to mta-sts.$DomainName using TLS 1.2 or 1.3. Older TLS versions are not permitted."
			Return
		}
	}
	[Net.ServicePointManager]::SecurityProtocol = $oldSP
	#endregion

	#region Parse the downloaded file.
	# It must be a text/plain document.
	If (-Not ($policy.Headers.'Content-Type' -Match "^text/plain(;.*)?$")) {
		Write-BadNews "MTA-STS Policy: It was found, but was returned with the wrong content type ($($policy.Headers.'Content-Type'))."
	}
	Else {
		#region Make sure the file has the correct line endings.
		# The MTA-STS RFC says that they should end with CRLF (i.e., "`r`n").
		# Split it up two different ways and see if we get the same results.
		# If not, then someone probably saved the file with UNIX ("`r") endings.
		# We're going to be strict and refuse to parse the file in this case.
		$lines   = $policy.Content -Split "`r`n"
		$LFlines = $policy.Content -Split "`n"

		If ($lines.Count -ne $LFLines.Count) {
			Write-Debug "This file has $($lines.Count) CRLF-terminated lines and $($LFlines.Count) LF-terminated lines."
			Write-BadNews "MTA-STS Policy: The policy file does not have the correct CRLF line endings!"
			Return
		}
		#endregion

		$lines | ForEach-Object {
			$line = $_.Trim()
			If ($line -CLike 'version: *') {
				If (($line -Split ':')[1].Trim() -Eq 'STSv1') {
					Write-GoodNews "MTA-STS Policy: This domain's STS policy is version 1."
				}
				Else {
					Write-BadNews "MTA-STS Policy: This domain's STS policy has an undefined version ($line)."
				}
			}
			ElseIf ($line -CLike 'mode: *') {
				$mode = ($line -Split ':')[1].Trim()
				If ($mode -Eq 'enforce') {
					Write-GoodNews 'MTA-STS Policy: This domain enforces MTA-STS.  Senders must not deliver mail to hosts that do not offer STARTTLS with a valid, trusted certificate.'
				} ElseIf ($mode -Eq 'testing') {
					Write-Informational 'MTA-STS Policy: This domain is in testing mode.  MTA-STS failures will be reported, but the message will be delivered.'
				} ElseIf ($mode -Eq 'none') {
					Write-BadPractice 'MTA-STS Policy: This domain has no active policy.'
				} Else {
					Write-BadNews "MTA-STS Policy: The unknown mode $mode was specified."
				}
			} ElseIf ($line -CLike 'mx: *') {
				If ($line -Match '\*') {
					Write-GoodNews "MTA-STS Policy: This domain has MX hosts with STARTTLS and valid certificates matching $((($line -Split ':')[1]).Trim())."
				}
				Else {
					Write-GoodNews "MTA-STS Policy: The domain has an MX host with STARTTLS and a valid certificate at $((($line -Split ':')[1]).Trim())."
				}
			}
			ElseIf ($line -CLike 'max_age: *') {
				# RFC 8461 doesn't define a data type for max_age, only saying that it is a "plaintext non-negative
				# integer seconds" with a maximum of 31557600.  The smallest type that can hold that is UInt32.
				$seconds = [UInt32]$(($line -Split ':')[1].Trim())
				If ($seconds -gt 31557600) {
					Write-BadPractice "MTA-STS Policy: This policy should be cached for $seconds seconds, which is longer than the maximum of 31557600 seconds."
				}
				Else {
					Write-Informational "MTA-STS Policy: This policy should be cached for $seconds seconds."
				}
			}
			ElseIf ($line.Length -gt 0) {
				Write-BadNews "MTA-STS Policy: An unknown key/value pair was specified: $line"
			}
		}
	}
	#endregion
}

Function Test-MXRecord
{
	[CmdletBinding()]
	[OutputType([Void])]
	[Alias('Test-MXRecords', 'Test-NullMXRecord')]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[String] $DomainName,

		[Alias('CD', 'DnssecCD', 'NoDnssec', 'DisableDnssec')]
		[Switch] $DisableDnssecVerification
	)

	$Results   = @()
	$DnsLookup = Invoke-GooglePublicDnsApi $DomainName 'MX' -Debug:$DebugPreference -DisableDnssecVerification:$DisableDnssecVerification

	#region DNSSEC check
	If (-Not $DisableDnssecVerification) {
		If ($DnsLookup.AD) {
			Write-GoodNews "MX: This DNS lookup is secure."
		}
		Else {
			Write-BadPractice "MX: This DNS lookup is insecure. Enable DNSSEC for this domain."
		}
	}
	#endregion DNSSEC check

	#region Implied MX record check
	# Check to see if we should create an implied MX record from the root A/AAAA
	# records, or if there are proper MX records alread in place.
	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-BadPractice "MX: There are no MX records! This implies the domain will receive its own email."
		$Results += @{"Preference"=0; "Server"=$DomainName; "Implied"=$true}
	}
	ElseIf ($DnsLookup.Status -eq 0)
	{
		($DnsLookup.Answer | Where-Object Type -eq 15).Data | ForEach-Object {
			$Pref, $Server = $_ -Split "\s+"
			$Results += @{"Preference"=[UInt16]$Pref; "Server"=$Server; "Implied"=$false}
		}
	}
	Else {
		Write-Error "MX: DNS lookup failed with status $($DnsLookup.Status)."
	}
	#endregion

	#region Null MX check
	If ($Results.Count -eq 1 -and $Results[0].Server -eq '.') {
		Write-Informational 'MX: This domain does not send or receive email.'
		Return
	}
	#endregion

	$Results | Sort-Object Preference | ForEach-Object {
		If ($_.Implied) {
			Write-GoodNews "MX: This domain is its own MX server."
		}
		Else {
			Write-GoodNews "MX: The server $($_.Server) can receive mail for this domain (at priority $($_.Preference))."
		}
		Test-IPVersions ($_.Server) -Indent
	}
}

Function Test-SmtpTlsReportingPolicy
{
	[CmdletBinding()]
	[OutputType([Void])]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[string] $DomainName,

		[Alias('CD', 'DnssecCD', 'NoDnssec', 'DisableDnssec')]
		[Switch] $DisableDnssecVerification
	)

	$DnsLookup = Invoke-GooglePublicDnsApi "_smtp._tls.$DomainName" 'TXT' -Debug:$DebugPreference -DisableDnssecVerification:$DisableDnssecVerification

	#region DNSSEC check
	If (-Not $DisableDnssecVerification) {
		If ($DnsLookup.AD) {
			Write-GoodNews "TLSRPT: This DNS lookup is secure."
		}
		Else {
			Write-BadPractice "TLSRPT: This DNS lookup is insecure. Enable DNSSEC for this domain."
		}
	}
	#endregion DNSSEC check

	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-BadNews "TLSRPT: SMTP TLS Reporting is not enabled for this domain."
		Return
	}
	ElseIf (($DnsLookup.Answer | Where-Object type -eq 16).Count -gt 1) {
		Write-BadNews "TLSRPT: More than one DNS record was found.  SMTP TLS Reporting must be assumed not to be supported!"
		Return
	}

	$TlsRptPolicy = ($DnsLookup.Answer | Where-Object type -eq 16).Data
	If ($null -eq $TlsRptPolicy)
	{
		Write-Verbose "TLSRPT: A policy record exists with no valid data!"
		Return
	}

	# The "rua" tag must appear at least once, and the "v" tag must appear
	# exactly once.  We'll count how many times we see each one.
	$ruas     = 0
	$versions = 0

	ForEach ($token in ($TlsRptPolicy -Split ';'))
	{
		$splits = $token -Split '='
		$key    = $splits[0].Trim()
		$value  = ''
		If ($null -ne $splits[1]) {
			$value = $splits[1].Trim()
		}

		If ($key -eq 'v')
		{
			If ($value -eq 'TLSRPTv1') {
				Write-GoodNews 'TLSRPT: This is a version 1 policy.'
				$versions++
			} Else {
				Write-BadNews "TLSRPT: This is an unsupported version ($value)!"
			}
		}
		ElseIf ($key -eq 'rua') {
			$ruas++
			Write-Informational "TLSRPT: Aggregate information will be sent to: $value"
		}
		Else {
			Write-BadNews "TLSRPT: An invalid token was specified ($token)."
		}
	}

	If ($versions -ne 1) {
		Write-BadNews "TLSRPT: The required `"v`" tag did not appear exactly once.  (It appeared $versions times.)"
	}
	If ($ruas -eq 0) {
		Write-BadNews 'TLSRPT: The required "rua" tag was not found!'
	}
}

Function Get-SPFTokenComponents
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='This function returns multiple things.')]
	[CmdletBinding()]
	[OutputType([Object[]])]
	Param(
		[Parameter(Mandatory, Position=0)]
		[String] $token
	)

	#region Break the token into its components
	# We're going to pull all the important stuff from the token.  There can be
	# an optional qualifier; then a mandatory IP address (for the ip4: and ip6:
	# mechanisms), an optional hostname (a:, mx:, ptr:), or a mandatory hostname
	# (include: or exists:); and an optional mask (for a:, ip4:, ip6:, mx:) that
	# can cover IPv4 or IPv6 addresses depending on the protocol version in use
	# by the MTA at the time of message receipt.
	#
	# There's a lot of null checks because I'm still supporting PowerShell 5.1
	# in this version of the module.
	#
	$token -Match '(?<qualifier>[+\-~\?])?[a|exists|include|ip4|ip6|mx|ptr](?::(?<hostname>([^\/]*)))?(?:\/(?<mask>\d{1,3}))?' | Out-Null

	# If there is no qualifier, then it's assumed to be '+'.
	If ($null -ne $Matches.qualifier) {
		$qualifier = $Matches.qualifier
	}
	Else {
		$qualifier = '+'
	}

	# If a hostname is specified in the a/exists/include/mx/ptr token (i.e., "a:mail.contoso.com"), then use that.
	# Otherwise, the hostname is implied to be the bare domain name.
	#
	# This same code pulls the IP address out of the ip4: and ip6: tokens, but it's mandatory for those.
	If ($null -ne $Matches.hostname) {
		$hostname = $Matches.hostname
	}
	Else {
		$hostname = $DomainName
	}

	# If there is no mask given, it's assumed to be /32 for IPv4 and /128 for IPv6. There's no way to tell which address
	# family a given host will resolve to, though.  That's left up to the MTA and I don't really have a good way to test
	# that at the DNS level.  (This is why the language in this module doesn't refer to a specific IP version, except in
	# checking ip4: or ip6: tokens.)
	If ($null -ne $Matches.mask) {
		$mask = $Matches.mask
	}
	Else {
		$mask = $null
	}

	Write-Debug "q=$qualifier h=$hostname m=$mask"
	Return @($qualifier, $hostname, $mask)
}

Function Test-SpfRecord
{
	[CmdletBinding()]
	[OutputType([Void])]
	[Alias('Test-SenderIdRecord')]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[Alias('Name')]
		[String] $DomainName,

		[Alias('Recurse', 'CountSpfDnsLookups')]
		[Switch] $CountDnsLookups,

		[Alias('CD', 'DnssecCD', 'NoDnssec', 'DisableDnssec')]
		[Switch] $DisableDnssecVerification,

		[Parameter(DontShow)]
		[ref] $Recursions,

		[Parameter(DontShow)]
		[ref] $DnsLookups
	)

	# This is a recursive function.  We do not expect the user to specify the
	# $Recursions or $DnsLookups parameters themselves (in fact, they're hidden
	# from help because they're for internal use only).  Thus, if an explicit
	# value is not specified, re-call this function with one.
	Write-Debug "Entering Test-SpfRecord as $($MyInvocation.InvocationName)."
	If ($CountDnsLookups)
	{
		If ($null -eq $Recursions)
		{
			$r = -1		# it will be incremented to zero on the first run.
			$d = 0
			If ($MyInvocation.InvocationName -eq 'Test-SenderIdRecord')
			{
				Test-SenderIdRecord -DomainName $DomainName -CountDnsLookups:$CountDnsLookups -DisableDnssecVerification:$DisableDnssecVerification -Recursions ([ref]$r) -DnsLookups ([ref]$d)
			}
			ElseIf ($MyInvocation.InvocationName -eq 'Test-SpfRecord') {
				Test-SpfRecord -DomainName $DomainName -CountDnsLookups:$CountDnsLookups -DisableDnssecVerification:$DisableDnssecVerification -Recursions ([ref]$r) -DnsLookups ([ref]$d)
			}
			Else {
				Throw 'Unsupported invocation.'
			}
			Return	# do not recurse
		}
		Else {
			# PowerShell requires us to use the Value property to get the content
			# of a variable passed by reference.
			$Recursions.Value++
		}
	}

	#region Fetch the SPF record.
	# For historical reasons, we can also fetch Sender ID records.  That was
	# Microsoft's failed attempt to make an "SPF 2.0".  It can operate on either
	# of the two MailFrom headers, or both.  It never really took off.  Support
	# for Sender ID may be removed from this module in the future.
	$DnsLookup  = Invoke-GooglePublicDnsApi "$DomainName" 'TXT' -Debug:$DebugPreference -DisableDnssecVerification:$DisableDnssecVerification
	$TxtRecords = ($DnsLookup.Answer | Where-Object type -eq 16).Data
	$SpfRecord  = @()
	$NoSPF      = $false

	Write-Debug "We have $($TxtRecords.Count) TXT records to consider."
	ForEach ($x in $TxtRecords) {
		Write-Debug "Candidate: $x"
	}

	Write-Debug "We are running the function $($MyInvocation.InvocationName)."
	If ($MyInvocation.InvocationName -eq 'Test-SenderIdRecord')
	{
		$SpfRecord = $TxtRecords | Where-Object {$_ -CLike "spf2.0/*"}
		Write-Debug "FOUND: $SpfRecord"
		$RecordType = 'Sender ID'
	}
	ElseIf ($MyInvocation.InvocationName -eq 'Test-SpfRecord')
	{
		$SpfRecord = $TxtRecords | Where-Object {$_ -CLike "v=spf1 *"}
		Write-Debug "FOUND: $SpfRecord"
		$RecordType = 'SPF'
	}
	Else {
		Throw "Unsupported invocation."
	}

	If ($null -eq $SpfRecord) {
		$NoSPF = $true
	}

	# Add indentation when doing recursive SPF lookups.
	$RecordTypePrintable = $RecordType -Split '─' | Select-Object -Last 1
	If ($CountDnsLookups) {
		$RecordType = "$('├──' * $Recursions.Value)$RecordType"
	}
	#endregion

	#region DNSSEC check
	If (-Not $DisableDnssecVerification) {
		If ($DnsLookup.AD) {
			Write-GoodNews "${RecordType}: This DNS lookup is secure."
		}
		Else {
			Write-BadPractice "${RecordType}: This DNS lookup is insecure. Enable DNSSEC for this domain."
		}
	}
	#endregion

	# Did we get a working TXT record?
	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-BadNews "${RecordType}: No TXT records were found for $DomainName!"
	}
	ElseIf ($NoSPF)
	{
		Write-BadNews "${RecordType}: A TXT record was found for $DomainName, but it is not a $RecordTypePrintable record!"
	}
	Else
	{
		Write-Verbose "Checking the $RecordTypePrintable record: `"$SpfRecord`""
		ForEach ($token in ($SpfRecord -Split ' ')) {
			#region Check SPF versions
			If ($token -Eq "v=spf1") {
				Write-GoodNews "${RecordType}: This is an SPF version 1 record."
			}
			ElseIf ($token -Eq "spf2.0/pra") {
				Write-BadPractice "${RecordType}: Sender ID records are historic and should be replaced with SPF TXT records."
				Write-GoodNews "${RecordType}: This is a Sender ID record checking the purported return address."
			}
			ElseIf ($token -Eq "spf2.0/mfrom") {
				Write-BadPractice "${RecordType}: Sender ID records are historic and should be replaced with SPF TXT records."
				Write-GoodNews "${RecordType}: This is a Sender ID record checking the mail From: address (like SPF)."
			}
			ElseIf ($token -Eq "spf2.0/pra,mfrom" -Or $token -Eq "spf2.0/mfrom,pra") {
				Write-BadPractice "${RecordType}: Sender ID records are historic and should be replaced with SPF TXT records."
				Write-GoodNews "${RecordType}: This is a Sender ID record checking the mail From: and purported return addresses."
			}
			#endregion

			#region Check redirect modifier.
			# If we're using the -CountDnsLookups/-Recurse parameter, this function
			# will be recursive and check the redirected SPF record.
			ElseIf ($token -Like 'redirect=*') {
				$Domain = ($token -Split '=')[1]
				If ($CountDnsLookups) {
					$DnsLookups.Value++
				}

				Write-Informational "${RecordType}: Use the $RecordTypePrintable record at $Domain instead.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				If ($CountDnsLookups) {
					If ($RecordType -eq 'Sender ID') {
						Test-SenderIdRecord $Domain -CountDnsLookups:$CountDnsLookups -DisableDnssecVerification:$DisableDnssecVerification -Recursions $Recursions -DnsLookups $DnsLookups
					}
					Else {
						Test-SpfRecord $Domain -CountDnsLookups:$CountDnsLookups -DisableDnssecVerification:$DisableDnssecVerification -Recursions $Recursions -DnsLookups $DnsLookups
					}
				}
			}
			#endregion

			#region Check A tokens.
			ElseIf ($token -Match '^[\+\-\?\~]?a([:/]*)' -and $token -NotMatch "all$")
			{
				If ($CountDnsLookups) {
					$DnsLookups.Value++
				}

				$qualifier, $hostname, $mask = Get-SPFTokenComponents $token

				If ($null -eq $mask)
				{
					If ($qualifier -eq '+') {
						Write-GoodNews "${RecordType}: Accept mail from $hostname's IP address(es).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
					ElseIf ($qualifier -eq '-') {
						Write-GoodNews "${RecordType}: Reject mail from $hostname's IP address(es).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
					ElseIf ($qualifier -eq '~') {
						Write-BadPractice "${RecordType}: Accept but mark mail from $hostname's IP address(es).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
					ElseIf ($qualifier -eq '?') {
						Write-BadPractice "${RecordType}: No opinion on mail from $hostname's IP address(es).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
				}
				ElseIf ($null -ne $mask)
				{
					If ($qualifier -eq '+') {
						Write-GoodNews "${RecordType}: Accept mail from all hosts in the same IP /$mask as $hostname.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
					ElseIf ($qualifier -eq '-') {
						Write-GoodNews "${RecordType}: Reject mail from all hosts in the same IP /$mask as $hostname.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
					ElseIf ($qualifier -eq '~') {
						Write-BadPractice "${RecordType}: Accept but mark mail from all hosts in the same IP /$mask as $hostname.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
					ElseIf ($qualifier -eq '?') {
						Write-BadPractice "${RecordType}: No opinion on mail from all hosts in the same IP /$mask as $hostname.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
				}
				Else {
					Write-BadNews "${RecordType}: PermError while processing the A token $token."
					Return
				}
			}
			#endregion

			#region Check MX tokens.
			ElseIf ($token -Match '^[\+\-\?\~]?mx([:/]*)')
			{
				If ($CountDnsLookups) {
					$DnsLookups.Value++
				}

				$qualifier, $hostname, $mask = Get-SPFTokenComponents $token

				If ($null -eq $mask)
				{
					If ($qualifier -eq '+') {
						Write-GoodNews "${RecordType}: Accept mail from $hostname's MX server(s).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
					ElseIf ($qualifier -eq '-') {
						Write-GoodNews "${RecordType}: Reject mail from $hostname's MX server(s).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
					ElseIf ($qualifier -eq '~') {
						Write-BadPractice "${RecordType}: Accept but mark mail from $hostname's MX server(s).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
					ElseIf ($qualifier -eq '?') {
						Write-BadPractice "${RecordType}: No opinion on mail from $hostname's MX server(s).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
				}
				ElseIf ($null -ne $mask)
				{
					If ($qualifier -eq '+') {
						Write-GoodNews "${RecordType}: Accept mail from all hosts in the same IP /$mask as $hostname's MX server(s).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
					ElseIf ($qualifier -eq '-') {
						Write-GoodNews "${RecordType}: Reject mail from all hosts in the same IP /$mask as $hostname's MX server(s).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
					ElseIf ($qualifier -eq '~') {
						Write-BadPractice "${RecordType}: Accept but mark mail from all hosts in the same IP /$mask as $hostname's MX server(s).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
					ElseIf ($qualifier -eq '?') {
						Write-BadPractice "${RecordType}: No opinion on mail from all hosts in the same IP /$mask as $hostname's MX server(s).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					}
				}
				Else {
					Write-BadNews "${RecordType}: PermError while processing the MX token $token."
					Return
				}
			}
			#endregion

			#region Check exists tokens
			ElseIf ($token -Match "^[\+\-\?\~]?exists:.*")
			{
				If ($CountDnsLookups) {
					$DnsLookups.Value++
				}

				$qualifier, $hostname = Get-SPFTokenComponents $token

				Switch ($qualifier)
				{
					'+' {Write-GoodNews    "${RecordType}: Accept mail if $hostname resolves to an A record.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"}
					'-' {Write-GoodNews    "${RecordType}: Reject mail if $hostname resolves to an A record.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"}
					'~' {Write-BadPractice "${RecordType}: Accept but mark mail if $hostname resolves to an A record.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"}
					'?' {Write-BadPractice "${RecordType}: No opinion if $hostname resolves to an A record.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"}
					default {
						Write-BadNews "${RecordType}: PermError while processing the Exists token $token."
						Return
					}
				}
			}
			#endregion

			#region Check ip4: and ip6: tokens
			ElseIf ($token -Match "^[\+\-\?\~]?ip4:*") {
				$ip4addr = $token -Replace '[\+\-\?\~]?ip4:' -Replace '/32'
				If ($token -Match "/" -And -Not ($token -Like "*/32")) {
					If ($token -Match "^\+?ip4:.*") {
						Write-GoodNews "${RecordType}: Accept mail from the IPv4 subnet $ip4addr."
					}
					ElseIf ($token -Like "-ip4:*") {
						Write-GoodNews "${RecordType}: Reject mail from the IPv4 subnet $ip4addr."
					}
					ElseIf ($token -Like "~ip4:*") {
						Write-BadPractice "${RecordType}: Accept but mark mail from the IPv4 subnet $ip4addr."
					}
					ElseIf ($token -Like "?ip4:*") {
						Write-BadPractice "${RecordType}: No opinion on mail from the IPv4 subnet $ip4addr."
					}
					Else {
						Write-BadNews "${RecordType}: PermError while processing the IPv4 token $token."
						Return
					}
				} Else {
					If ($token -Match "^\+?ip4:.*") {
						Write-GoodNews "${RecordType}: Accept mail from the IPv4 address $ip4addr."
					}
					ElseIf ($token -Like "-ip4:*") {
						Write-GoodNews "${RecordType}: Reject mail from the IPv4 address $ip4addr."
					}
					ElseIf ($token -Like "~ip4:*") {
						Write-BadPractice "${RecordType}: Accept but mark mail from the IPv4 address $ip4addr."
					}
					ElseIf ($token -Like "?ip4:*") {
						Write-BadPractice "${RecordType}: No opinion on mail from the IPv4 address $ip4addr."
					}
					Else {
						Write-BadNews "${RecordType}: PermError: Could not parse the IPv4 token $token."
						Return
					}
				}
			}
			ElseIf ($token -Match "^[\+\-\?\~]?ip6:*") {
				$ip6addr = $token -Replace '[\+\-\?\~]?ip6:' -Replace '/128'
				If ($token -Match "/" -And -Not ($token -Like "*/128")) {
					If ($token -Match "^\+?ip6:*") {
						Write-GoodNews "${RecordType}: Accept mail from the IPv6 subnet $ip6addr."
					}
					ElseIf ($token -Like "-ip6:*") {
						Write-GoodNews "${RecordType}: Reject mail from the IPv6 subnet $ip6addr."
					}
					ElseIf ($token -Like "~ip6:*") {
						Write-BadPractice "${RecordType}: Accept but mark mail from the IPv6 subnet $ip6addr."
					}
					ElseIf ($token -Like "?ip6:*") {
						Write-BadPractice "${RecordType}: No opinion on mail from the IPv6 subnet $ip6addr."
					}
					Else {
						Write-BadNews "${RecordType}: PermError while processing the IPv6 token $token."
						Return
					}
				} Else {
					If ($token -Match "^\+?ip6:*") {
						Write-GoodNews "${RecordType}: Accept mail from the IPv6 address $ip6addr."
					}
					ElseIf ($token -Like "-ip6:*") {
						Write-GoodNews "${RecordType}: Reject mail from the IPv6 address $ip6addr."
					}
					ElseIf ($token -Like "~ip6:*") {
						Write-BadPractice "${RecordType}: Accept but mark mail from the IPv6 address $ip6addr."
					}
					ElseIf ($token -Like "?ip6:*") {
						Write-BadPractice "${RecordType}: No opinion on mail from the IPv6 address $ip6addr."
					}
					Else {
						Write-BadNews "${RecordType}: PermError while processing the IPv6 token $token."
						Return
					}
				}
			}
			#endregion

			#region Check PTR tokens
			# The PTR mechanism is deprecated and should be avoided whenever possible.
			ElseIf ($token -Match "^[\+\-\?\~]?ptr(:.*)?") {
				If ($CountDnsLookups) {
					$DnsLookups.Value++
				}

				If ($token -Match "^\+?ptr$") {
					Write-BadPractice "${RecordType}: Accept mail from IP's that have a reverse DNS record ending in $DomainName.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Eq "-ptr") {
					Write-BadPractice "${RecordType}: Reject mail from IP's that have a reverse DNS record ending in $DomainName.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Eq "~ptr") {
					Write-BadPractice "${RecordType}: Accept but mark mail from IP's that have a reverse DNS record ending in $DomainName.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Eq "?ptr") {
					Write-BadPractice "${RecordType}: No opinion on mail from IP's that have a reverse DNS record ending in $DomainName.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^\+?ptr:.*") {
					Write-BadPractice "${RecordType}: Accept mail from IP's that have a reverse DNS record ending in $($token -Replace '\+' -Replace 'ptr:').$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Like "-ptr:*") {
					Write-BadPractice "${RecordType}: Reject mail from IP's that have a reverse DNS record ending in $($token -Replace '-ptr:').$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Like "~ptr:*") {
					Write-BadPractice "${RecordType}: Accept but mark mail from IP's that have a reverse DNS record ending in $($token -Replace '-ptr:').$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Like "?ptr:*") {
					Write-BadPractice "${RecordType}: No opinion on mail from IP's that have a reverse DNS record ending in $($token -Replace '\?ptr:').$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				Else {
					Write-BadNews "${RecordType}: PermError while processing the PTR token $token."
					Return
				}
			}
			#endregion

			#region Check include: tokens
			# When running with the -CountDnsLookups/-Recurse parameter, the values
			# of the "include:" tokens will be checked recursively.
			ElseIf ($token -Match "^[\+\-\?\~]?include\:") {
				If ($CountDnsLookups) {
					$DnsLookups.Value++
				}
				$NextRecord = $token -Replace '^[\+\-\~\?]?include:',''

				If ($token -Match "^\+?include:*") {
					Write-GoodNews "${RecordType}: Accept mail that passes the $RecordTypePrintable record at $nextRecord.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					If ($CountDnsLookups) {
						If ($RecordType -eq 'Sender ID') {
							Test-SenderIdRecord -DomainName $NextRecord -CountDnsLookups:$CountDnsLookups -DisableDnssecVerification:$DisableDnssecVerification -Recursions $Recursions -DnsLookups $DnsLookups
						} Else {
							Test-SpfRecord -DomainName $NextRecord -CountDnsLookups:$CountDnsLookups -DisableDnssecVerification:$DisableDnssecVerification -Recursions $Recursions -DnsLookups $DnsLookups
						}
					}
				}
				ElseIf ($token -Like "-include:*") {
					Write-GoodNews "${RecordType}: Reject mail that passes the $RecordTypePrintable record at $NextRecord.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					If ($CountDnsLookups) {
						If ($RecordType -eq 'Sender ID') {
							Test-SenderIdRecord -DomainName $NextRecord -CountDnsLookups:$CountDnsLookups -DisableDnssecVerification:$DisableDnssecVerification -Recursions $Recursions -DnsLookups $DnsLookups
						} Else {
							Test-SpfRecord -DomainName $NextRecord -CountDnsLookups:$CountDnsLookups -DisableDnssecVerification:$DisableDnssecVerification -Recursions $Recursions -DnsLookups $DnsLookups
						}
					}
				}
				ElseIf ($token -Like "~include:*") {
					Write-BadPractice "${RecordType}: Accept but mark mail that passes the $RecordTypePrintable record at $NextRecord.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					If ($CountDnsLookups) {
						If ($RecordType -eq 'Sender ID') {
							Test-SenderIdRecord -DomainName $NextRecord -CountDnsLookups:$CountDnsLookups -DisableDnssecVerification:$DisableDnssecVerification -Recursions $Recursions -DnsLookups $DnsLookups
						} Else {
							Test-SpfRecord -DomainName $NextRecord -CountDnsLookups:$CountDnsLookups -DisableDnssecVerification:$DisableDnssecVerification -Recursions $Recursions -DnsLookups $DnsLookups
						}
					}
				}
				ElseIf ($token -Like "?include:*") {
					Write-BadPractice "${RecordType}: No opinion on mail that passes the $RecordTypePrintable record at $NextRecord.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
					If ($CountDnsLookups) {
						If ($RecordType -eq 'Sender ID') {
							Test-SenderIdRecord -DomainName $NextRecord -CountDnsLookups:$CountDnsLookups -DisableDnssecVerification:$DisableDnssecVerification -Recursions $Recursions -DnsLookups $DnsLookups
						} Else {
							Test-SpfRecord -DomainName $NextRecord -CountDnsLookups:$CountDnsLookups -DisableDnssecVerification:$DisableDnssecVerification -Recursions $Recursions -DnsLookups $DnsLookups
						}
					}
				}
				Else {
					Write-BadNews "${RecordType}: PermError while processing the Include token $token"
					Return
				}
			}
			#endregion

			#region Check for the "all" token.
			ElseIf ($token -Match "^[\+\-\?\~]?all")
			{
				If ($token -Match "^\+?all") {
					Write-BadPractice "${RecordType}: Accept all other mail."
				} ElseIf ($token -Eq "-all") {
					Write-GoodNews "${RecordType}: Reject all other mail."
				} ElseIf ($token -Eq "~all") {
					Write-BadPractice "${RecordType}: Accept but mark all other mail (this domain is likely testing $RecordTypePrintable)."
				} ElseIf ($token -Eq "?all") {
					Write-BadPractice "${RecordType}: Do whatever with all other mail."
				} Else {
					Write-BadNews "${RecordType}: PermError while processing the All token $token"
					Return
				}
			}
			#endregion

			#region Check the exp= modifier
			# We will always attempt to resolve this and return the custom error
			# message.  Note that this one does not count toward the ten DNS lookup
			# limit of SPF.
			ElseIf ($token -Like "exp=*")
			{
				$ExplanationRecord  = $token -Replace 'exp='
				$ExplanationMessage = ((Invoke-GooglePublicDnsApi $ExplanationRecord 'TXT').Answer | Where-Object Type -eq 16).Data
				Write-Informational "${RecordType}: Include this explanation with $RecordTypePrintable failures: `"$ExplanationMessage`""
			}
			#endregion

			ElseIf ($token.Length -gt 0) {
				Write-BadNews "${RecordType}: PermError while processing the unknown token $token"
				Return
			}
		}
	}

	# If this is the first instance of Test-SpfRecord (that is, we are not in
	# the middle of some recursion), then print the number of DNS lookups and
	# remove the script-level counter variable.
	If ($CountDnsLookups)
	{
		If ($Recursions.Value -gt 0) {
			$Recursions.Value--
		}
		ElseIf ($DnsLookups.Value -gt 10) {
			Write-BadNews "${RecordType}: PermError due to too many DNS lookups. $($DnsLookups.Value) lookups were required, but only 10 are allowed."
		}
	}
	Return
}
