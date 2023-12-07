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
	$rsa.ImportFromPem("-----BEGIN PUBLIC KEY-----`r`n$PublicKey`r`n-----END PUBLIC KEY-----")
	Return $rsa.KeySize
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
		[String] $Type = 'A'
	)

	$MaxLengthOfPadding = 1958 - $InputObject.Length - $Type.Length

	$ToSend = @{
		'name'           = $InputObject
		'type'           = $Type
		'ct'             = 'application/x-javascript'
		'cd'             = 0	# enable DNSSEC validation...
		'do'             = 0	# ...but don't return RRSIGs. Trust the resolver.
		'random_padding' = Get-RandomString -MaxLength $MaxLengthOfPadding -MinLength $MaxLengthOfPadding
	}

	Write-Verbose "Sending $($ToSend.random_padding.Length) characters of random padding."
	
	$RequestParams = @{
		'Method'      = 'GET'
		'Uri'         = 'https://dns.google/resolve'
		'Body'        = $ToSend
		'Verbose'     = $VerbosePreference
		'HttpVersion' = '3.0'	# DoH requires HTTP/2 or newer.
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
		[string] $DomainName
	)

	$DnsLookup = Invoke-GooglePublicDnsApi "_adsp._domainkey.$DomainName" 'TXT' -Debug:$DebugPreference

	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-Verbose 'DKIM ADSP: No ADSP record was found.'
	}
	Else
	{
		If ($DnsLookup.AD) {
			Write-GoodNews "DKIM ADSP: This DNS lookup is secure."
		}
		Else {
			Write-BadPractice "DKIM ADSP: This DNS lookup is insecure. Enable DNSSEC for this domain."
		}

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
		[string] $Name = 'default'
	)

	$DnsLookup = Invoke-GooglePublicDnsApi "$Name._bimi.$DomainName" 'TXT' -Debug:$DebugPreference

	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-Informational "BIMI selector ${Selector}: Not found!"
		Return
	}

	If ($DnsLookup.AD) {
		Write-GoodNews "BIMI selector ${Selector}: This DNS lookup is secure."
	}
	Else {
		Write-BadPractice "BIMI selector ${Selector}: This DNS lookup is insecure. Enable DNSSEC for this domain."
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
	[CmdletBinding()]
	[OutputType([Void])]
	[Alias('Test-DaneRecords', 'Test-TlsaRecord', 'Test-TlsaRecords')]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[String] $DomainName
	)

	# Fetch all MX records for this domain.  We won't do a DNSSEC check here,
	# since we did that if the user entered here via Test-MailFlow.
	$MXServers = @()
	((Invoke-GooglePublicDnsApi $DomainName 'MX' -Debug:$DebugPreference).Answer `
		| Where-Object type -eq 15).Data `
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
	If ($MXServers.Count -eq 0 -or ($MXServers.Count -eq 1 -and $null -eq $MXServers[0].Name))
	{
		$MXServers = @(@{'Preference'=0; 'Server'=$DomainName})
	}

	$MXServers | Sort-Object Preference | ForEach-Object {
		# Strip the trailing dot, if present. This is done for display purposes.
		$MXName = $_.Server -Replace '\.$'

		$DnsLookup = Invoke-GooglePublicDnsApi "_25._tcp.$MXName" 'TLSA' -Debug:$DebugPreference
		If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 2 -or $DnsLookup.Status -eq 3)
		{
			Write-BadNews "DANE: DANE records are not present for $MXName, TCP port 25."
			Return
		}

		If ($DnsLookup.AD) {
			Write-GoodNews "DANE: ${MXName}: The DNS lookup is secure."
		}
		Else {
			Write-BadNews "DANE: ${MXName}: The DNS lookup is insecure; the DANE records cannot be used!  Enable DNSSEC for this domain."
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
		[string]$Name
	)

	$DnsLookup = Invoke-GooglePublicDnsApi "$Name._domainkey.$DomainName" 'TXT' -Debug:$DebugPreference

	$Name = " $Name"

	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-BadNews "DKIM selector${Name}: This selector was not found."
		Return
	}

	If ($DnsLookup.AD) {
		Write-GoodNews "DKIM selector${Name}: This DNS lookup is secure."
	}
	Else {
		Write-BadPractice "DKIM selector${Name}: This DNS lookup is insecure. Enable DNSSEC for this domain."
	}

	$DkimKeyRecord = ($DnsLookup.Answer | Where-Object type -eq 16).Data
	If ($null -eq $DkimKeyRecord)
	{
		Write-BadNews "DKIM selector${Name}: This selector was not found in DNS."
		Return
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
		[string] $DomainName
	)

	$DnsLookup = Invoke-GooglePublicDnsApi "_dmarc.$DomainName" 'TXT' -Debug:$DebugPreference

	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-BadNews "DMARC: Not found!"
		Return
	}

	If ($DnsLookup.AD) {
		Write-GoodNews "DMARC: This DNS lookup is secure."
	}
	Else {
		Write-BadPractice "DMARC: This DNS lookup is insecure. Enable DNSSEC for this domain."
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
				If ($DmarcPolicy -Match "reject") {
					Write-Informational "DMARC: Reject 100% of email that fails DMARC (default)."
				}
				ElseIf ($DmarcPolicy -Match 'quarantine') {
					Write-Informational "DMARC: Quarantine 100% of email that fails DMARC (default)."
				}
			}
			Else {
				If ($DmarcPolicy -Match "reject") {
					Write-Informational "DMARC: Only reject ${pct}% of unaligned email; the rest will be quarantined."
				}
				ElseIf ($DmarcPolicy -Match 'quarantine') {
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

		[String[]] $DkimSelectorsToCheck,

		[String[]] $BimiSelectorsToCheck
	)

	Write-Output "Analyzing email records for $DomainName"
	Test-MXRecord $DomainName
	Test-SpfRecord $DomainName -Recurse:$CountSpfDnsLookups
	If ($DkimSelectorsToCheck.Count -gt 0) {
		$DkimSelectorsToCheck | ForEach-Object {
			Test-DkimSelector $DomainName -Name $_
		}
	}
	Test-ADSPRecord $DomainName
	Test-DmarcRecord $DomainName
	If ($BimiSelectorsToCheck.Count -gt 0) {
		$BimiSelectorsToCheck | ForEach-Object {
			Test-BimiSelector $DomainName -Name $_
		}
	}
	Test-MtaStsPolicy $DomainName
	Test-SmtpTlsReportingPolicy $DomainName
	Test-DaneRecord $DomainName
}

Function Test-MtaStsPolicy
{
	[CmdletBinding()]
	[OutputType('Void')]
	[Alias('Test-MtaStsRecord')]
	Param(
		[Parameter(Mandatory, Position=0)]
		[String] $DomainName
	)

	$DnsLookup = Invoke-GooglePublicDnsApi "_mta-sts.$DomainName" 'TXT' -Debug:$DebugPreference

	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-BadNews "MTA-STS Record: Not found! (Skipping policy test.)"
		Return
	}

	If ($DnsLookup.AD) {
		Write-GoodNews "MTA-STS Record: This DNS lookup is secure."
	}
	Else {
		Write-BadPractice "MTA-STS Record: This DNS lookup is insecure. Enable DNSSEC for this domain."
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

	Test-IPVersions "mta-sts.$DomainName"

	Try {
		$policy = Invoke-WebRequest -Method GET -Uri "https://mta-sts.$DomainName/.well-known/mta-sts.txt" -SslProtocol Tls13 -ErrorAction Stop
		Write-GoodNews "MTA-STS Policy: Downloaded the policy file from mta-sts.$DomainName using TLS 1.3."
	}
	Catch {
		Try {
			$policy = Invoke-WebRequest -Method GET -Uri "https://mta-sts.$DomainName/.well-known/mta-sts.txt" -SslProtocol Tls12 -ErrorAction Stop
			Write-GoodNews "MTA-STS Policy: Downloaded the policy file from mta-sts.$DomainName using TLS 1.2."
		}
		Catch {
			Write-BadNews "MTA-STS Policy: Could not connect to mta-sts.$DomainName using TLS 1.2 or 1.3. Older TLS versions are not permitted."
			Return
		}
	}

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
		$lines   = $policy.Content.Split("`r`n")
		$LFlines = $policy.Content -Split "`r?`n"
		
		If ($lines -ne $LFLines) {
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
}

Function Test-MXRecord
{
	[CmdletBinding()]
	[OutputType([Void])]
	[Alias('Test-MXRecords', 'Test-NullMXRecord')]
	Param(
		[Parameter(Mandatory, Position=0)]
		[ValidateNotNullOrEmpty()]
		[String] $DomainName
	)

	$Results   = @()
	$DnsLookup = Invoke-GooglePublicDnsApi $DomainName 'MX' -Debug:$DebugPreference

	#region DNSSEC check
	If ($DnsLookup.AD) {
		Write-GoodNews "MX: This DNS lookup is secure."
	}
	Else {
		Write-BadPractice "MX: This DNS lookup is insecure. Enable DNSSEC for this domain."
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
		[string] $DomainName
	)

	$DnsLookup = Invoke-GooglePublicDnsApi "_smtp._tls.$DomainName" 'TXT' -Debug:$DebugPreference
	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-BadNews "TLSRPT: SMTP TLS Reporting is not enabled for this domain."
		Return
	}
	ElseIf (($DnsLookup.Answer | Where-Object type -eq 16).Count -gt 1) {
		Write-BadNews "TLSRPT: More than one DNS record was found.  SMTP TLS Reporting must be assumed not to be supported!"
		Return
	}

	#region DNSSEC check
	If ($DnsLookup.AD) {
		Write-GoodNews "TLSRPT: This DNS lookup is secure."
	}
	Else {
		Write-BadPractice "TLSRPT: This DNS lookup is insecure. Enable DNSSEC for this domain."
	}
	#endregion DNSSEC check

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
		$value  = $splits[1]?.Trim()

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

		[Parameter(DontShow)]
		[ref] $Recursions,

		[Parameter(DontShow)]
		[ref] $DnsLookups
	)

	# This is a recursive function.  We do not expect the user to specify the
	# $Recursions or $DnsLookups parameters themselves (in fact, they're hidden
	# from help because they're for internal use only).  Thus, if an explicit
	# value is not specified, re-call this function with one.
	If ($CountDnsLookups)
	{
		If ($null -eq $Recursions)
		{
			$r = -1		# it will be incremented to zero on the first run.
			$d = 0
			Test-SpfRecord -DomainName $DomainName -CountDnsLookups:$CountDnsLookups -Recursions ([ref]$r) -DnsLookups ([ref]$d)
			Return	# do not recurse
		}
		Else {
			# PowerShell requires us to use the Value property to get the content
			# of a variable passed by reference.
			$Recursions.Value++
		}
	}
	
	$DnsLookup = Invoke-GooglePublicDnsApi "$DomainName" 'TXT' -Debug:$DebugPreference
	If ($DnsLookup.PSObject.Properties.Name -NotContains 'Answer' -or $DnsLookup.Status -eq 3)
	{
		Write-BadNews "SPF: No TXT records were found at the root of $DomainName!"
		Return
	}

	$SpfRecord = ($DnsLookup.Answer | Where-Object type -eq 16).Data | Where-Object {$_ -CLike "v=spf1 *" -or $_ -CLike "spf2.0/*"}
	If ($SpfRecord -CLike "v=spf1 *") {
		$RecordType = 'SPF'
	}
	ElseIf ($SpfRecord -CLike "spf2.0/*") {
		$RecordType = 'Sender ID'
	}
	Else {
		Write-BadNews "SPF: No SPF record was found."
		Return
	}

	# Add indentation when doing recursive SPF lookups.
	If ($CountDnsLookups) {
		$RecordType = "$('├──' * $Recursions.Value)$RecordType"
	}

	If ($DnsLookup.AD) {
		Write-GoodNews "${RecordType}: This DNS lookup is secure."
	}
	Else {
		Write-BadPractice "${RecordType}: This DNS lookup is insecure. Enable DNSSEC for this domain."
	}

	Write-Verbose "Checking the $RecordType record: `"$SpfRecord`""
	If ($DnssecSecured) {
		Write-GoodNews "${RecordType}: This DNS lookup is secured with DNSSEC."
	}

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
			Write-GoodNews "${RecordType}: This is a Sender ID record checking the mail From: address."
		}
		ElseIf ($token -Eq "spf2.0/pra,mfrom" -Or $token -Eq "spf2.0/mfrom,pra") {
			Write-BadPractice "${RecordType}: Sender ID records are historic and should be replaced with SPF TXT records."
			Write-GoodNews "${RecordType}: This is a Sender ID record checking the mail From: and purported return addresses (like SPF)."
		}
		#endregion

		ElseIf ($token -Like 'redirect=*') {
			$Domain = ($token -Split '=')[1]
			If ($CountDnsLookups) {
				$DnsLookups.Value++
			}

			Write-Informational "${RecordType}: Use the SPF record at $Domain instead.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			If ($CountDnsLookups) {
				Test-SpfRecord $Domain -CountDnsLookups:$CountDnsLookups -Recursions $Recursions -DnsLookups $DnsLookups
			}
		}

		#region Check A tokens.
		ElseIf ($token -Match '^[\+\-\?\~]?a([:/]*)' -and $token -NotMatch "all$")
		{
			If ($CountDnsLookups) {
				$DnsLookups.Value++
			}
			
			If ($token -Match "^\+?a$") {
				Write-GoodNews "${RecordType}: Accept mail from $DomainName's IP address(es).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Eq "-a") {
				Write-GoodNews "${RecordType}: Reject mail from $DomainName's IP address(es).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Eq "~a") {
				Write-BadPractice "${RecordType}: Accept but mark mail from $DomainName's IP address(es).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Eq "?a") {
				Write-BadPractice "${RecordType}: No opinion on mail from $DomainName's IP address(es).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Match "^\+?a:*") {
				Write-GoodNews "${RecordType}: Accept mail from $($token -Replace '\+' -Replace 'a:')'s IP address(es).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Like "-a:*") {
				Write-GoodNews "${RecordType}: Reject mail from $($token -Replace '-a:')'s IP address(es).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Like "~a:*") {
				Write-BadPractice "${RecordType}: Accept but mark mail from $($token -Replace '?a:')'s IP address(es).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Like "?a:*") {
				Write-BadPractice "${RecordType}: No opinion on mail from $($token -Replace '?a:')'s IP address(es).$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Match "/") {
				$mask = ($token -Split '/')[1]
				If ($token -Match "^\+?a/[0-3]?[0-9]$") {
					Write-GoodNews "${RecordType}: Accept mail from all hosts in the same IPv4 /$mask as $DomainName.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^-a/[0-3]?[0-9]$") {
					Write-GoodNews "${RecordType}: Reject mail from all hosts in the same IPv4 /$mask as $DomainName.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^~a/[0-3]?[0-9]$") {
					Write-BadPractice "${RecordType}: Accept but mark mail from all hosts in the same IPv4 /$mask as $DomainName.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^?a/[0-3]?[0-9]$") {
					Write-BadPractice "${RecordType}: No opinion on mail from all hosts in the same IPv4 /$mask as $DomainName.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^\+?a:*/[0-3]?[0-9]$") {
					Write-GoodNews "${RecordType}: Accept mail from all hosts in the same IPv4 /$mask as $($token -Replace '\+' -Replace 'a:' -Replace '/[0-3]?[0-9]').$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^-a:*/[0-3]?[0-9]$") {
					Write-GoodNews "${RecordType}: Reject mail from all hosts in the same IPv4 /$mask as $($token -Replace '-a:' -Replace '/[0-3]?[0-9]').$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^~a:*/[0-3]?[0-9]$") {
					Write-BadPractice "${RecordType}: Accept but mark mail from all hosts in the same IPv4 /$mask as $($token -Replace '~a:' -Replace '/[0-3]?[0-9]').$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^?a:*/[0-3]?[0-9]$") {
					Write-BadPractice "${RecordType}: No opinion on mail from all hosts in the same IPv4 /$mask as $($token -Replace '?a:' -Replace '/[0-3]?[0-9]').$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				Else {
					Write-BadNews "${RecordType}: PermError while processing the A token $token."
					Return
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

			If ($token -Match "^\+?mx$") {
				Write-GoodNews "${RecordType}: Accept mail from $DomainName's MX servers.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Eq "-mx") {
				Write-GoodNews "${RecordType}: Reject mail from $DomainName's MX servers.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Eq "?mx") {
				Write-BadPractice "${RecordType}: No opinion on mail from $DomainName's MX servers.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Eq "~mx") {
				Write-BadPractice "${RecordType}: Accept but mark mail from $DomainName's MX servers.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Match "^\+?mx:.*$") {
				Write-GoodNews "${RecordType}: Accept mail from $($token -Replace '\+' -Replace 'mx:')'s MX servers.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Like "-mx:.*$") {
				Write-GoodNews "${RecordType}: Reject mail from $($token -Replace '-mx:')'s MX servers.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Like "~mx:.*$") {
				Write-BadPractice "${RecordType}: Accept but mark mail from $($token -Replace '?mx:')'s MX servers.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Like "?mx:.*$") {
				Write-BadPractice "${RecordType}: No opinion on mail from $($token -Replace '?mx:')'s MX servers.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Match "/") {
				$mask = ($token -Split '/')[1]
				If ($token -Match "^\+?mx/[0-3]?[0-9]$") {
					Write-GoodNews "${RecordType}: Accept mail from all hosts in the same IPv4 /$mask as $DomainName's MX records.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^-mx/[0-3]?[0-9]$") {
					Write-GoodNews "${RecordType}: Reject mail from all hosts in the same IPv4 /$mask as $DomainName's MX records.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^\?mx/[0-3]?[0-9]$") {
					Write-BadPractice "${RecordType}: No opinion on mail from all hosts in the same IPv4 /$mask as $DomainName's MX records.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^~mx/[0-3]?[0-9]$") {
					Write-BadPractice "${RecordType}: Accept but mark mail from all hosts in the same IPv4 /$mask as $DomainName's MX records.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^\+?mx:.*/[0-3]?[0-9]$") {
					Write-GoodNews "${RecordType}: Accept mail from all hosts in the same IPv4 /$mask as $($token -Replace '\+' -Replace 'mx:' -Replace '/[0-3]?[0-9]')'s MX records.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^-mx:.*/[0-3]?[0-9]$") {
					Write-GoodNews "${RecordType}: Reject mail from all hosts in the same IPv4 /$mask as $($token -Replace '-mx:' -Replace '/[0-3]?[0-9]')'s MX records.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^\?mx:.*/[0-3]?[0-9]$") {
					Write-BadPractice "${RecordType}: No opinion on mail from all hosts in the same IPv4 /$mask as $($token -Replace '?mx:' -Replace '/[0-3]?[0-9]')'s MX records.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				ElseIf ($token -Match "^~mx:.*/[0-3]?[0-9]$") {
					Write-BadPractice "${RecordType}: Accept but mark mail from all hosts in the same IPv4 /$mask as $($token -Replace '?mx:' -Replace '/[0-3]?[0-9]')'s MX records.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				}
				Else {
					Write-BadNews "${RecordType}: PermError while processing the MX token $token."
					Return
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

			If ($token -Match "^\+?exists:.*") {
				Write-GoodNews "${RecordType}: Accept mail if $($token -Replace '\+' -Replace 'exists:') resolves to an A record.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Like "-exists:*") {
				Write-GoodNews "${RecordType}: Reject mail if $($token -Replace '-exists:') resolves to an A record.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Like "~exists:*") {
				Write-BadPractice "${RecordType}: Accept but mark mail if $($token -Replace '~exists:') resolves to an A record.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			ElseIf ($token -Like "?exists:*") {
				Write-BadPractice "${RecordType}: No opinion if $($token -Replace '?exists:') resolves to an A record.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
			}
			Else {
				Write-BadNews "${RecordType}: PermError while processing the Exists token $token."
				Return
			}
		}
		#endregion

		#region Check ip4: and ip6: tokens
		ElseIf ($token -Match "^[\+\-\?\~]?ip4:*") {
			If ($token -Match "/" -And -Not ($token -Like "*/32")) {
				$ip4net = $token -Replace 'ip4:'
				If ($token -Match "^\+?ip4:.*") {
					Write-GoodNews "${RecordType}: Accept mail from the IPv4 subnet $ip4net."
				}
				ElseIf ($token -Like "-ip4:*") {
					Write-GoodNews "${RecordType}: Reject mail from the IPv4 subnet $ip4net."
				}
				ElseIf ($token -Like "~ip4:*") {
					Write-BadPractice "${RecordType}: Accept but mark mail from the IPv4 subnet $ip4net."
				}
				ElseIf ($token -Like "?ip4:*") {
					Write-BadPractice "${RecordType}: No opinion on mail from the IPv4 subnet $ip4net."
				}
				Else {
					Write-BadNews "${RecordType}: PermError while processing the IPv4 token $token."
					Return
				}
			} Else {
				$ip4addr = $token -Replace 'ip4:' -Replace '/32'
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
			If ($token -Match "/" -And -Not ($token -Like "*/128")) {
				$ip6net = $token -Replace 'ip6:'
				If ($token -Match "^\+?ip6:*") {
					Write-GoodNews "${RecordType}: Accept mail from the IPv6 subnet $ip6net."
				}
				ElseIf ($token -Like "-ip6:*") {
					Write-GoodNews "${RecordType}: Reject mail from the IPv6 subnet $ip6net."
				}
				ElseIf ($token -Like "~ip6:*") {
					Write-BadPractice "${RecordType}: Accept but mark mail from the IPv6 subnet $ip6net."
				}
				ElseIf ($token -Like "?ip6:*") {
					Write-BadPractice "${RecordType}: No opinion on mail from the IPv6 subnet $ip6net."
				}
				Else {
					Write-BadNews "${RecordType}: PermError while processing the IPv6 token $token."
					Return
				}
			} Else {
				$ip6addr = $token -Replace 'ip6:' -Replace '/128'
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
		ElseIf ($token -Match "^[\+\-\?\~]?include\:") {
			If ($CountDnsLookups) {
				$DnsLookups.Value++
			}
			$NextRecord = $token -Replace '^[\+\-\~\?]?include:',''

			If ($token -Match "^\+?include:*") {
				Write-GoodNews "${RecordType}: Accept mail that passes the SPF record at $nextRecord.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				If ($CountDnsLookups) {
					Test-SpfRecord -DomainName $NextRecord -CountDnsLookups:$CountDnsLookups -Recursions $Recursions -DnsLookups $DnsLookups
				}
			}
			ElseIf ($token -Like "-include:*") {
				Write-GoodNews "${RecordType}: Reject mail that passes the SPF record at $NextRecord.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				If ($CountDnsLookups) {
					Test-SpfRecord -DomainName $NextRecord -CountDnsLookups:$CountDnsLookups -Recursions $Recursions -DnsLookups $DnsLookups
				}
			}
			ElseIf ($token -Like "~include:*") {
				Write-BadPractice "${RecordType}: Accept but mark mail that passes the SPF record at $NextRecord.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				If ($CountDnsLookups) {
					Test-SpfRecord -DomainName $NextRecord -CountDnsLookups:$CountDnsLookups -Recursions $Recursions -DnsLookups $DnsLookups
				}
			}
			ElseIf ($token -Like "?include:*") {
				Write-BadPractice "${RecordType}: No opinion on mail that passes the SPF record at $NextRecord.$(Write-DnsLookups $DnsLookups -Enabled:$CountDnsLookups)"
				If ($CountDnsLookups) {
					Test-SpfRecord -DomainName $NextRecord -CountDnsLookups:$CountDnsLookups -Recursions $Recursions -DnsLookups $DnsLookups
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
				Write-BadPractice "${RecordType}: Accept but mark all other mail (this domain is likely testing SPF)."
			} ElseIf ($token -Eq "?all") {
				Write-BadPractice "${RecordType}: Do whatever with all other mail."
			} Else {
				Write-BadNews "${RecordType}: PermError while processing the All token $token"
				Return
			}
		}
		#endregion

		# This one does not count toward the ten DNS lookup limit of SPF.
		ElseIf ($token -Like "exp=*")
		{
			$ExplanationRecord  = $token -Replace 'exp='
			$ExplanationMessage = ((Invoke-GooglePublicDnsApi $ExplanationRecord 'TXT').Answer | Where-Object Type -eq 16).Data
			Write-Informational "${RecordType}: Include this explanation with SPF failures: `"$ExplanationMessage`""
		}

		ElseIf ($token.Length -gt 0) {
			Write-BadNews "${RecordType}: PermError while processing the unknown token $token"
			Return
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
