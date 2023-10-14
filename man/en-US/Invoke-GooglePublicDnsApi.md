---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Invoke-GooglePublicDnsApi.md
schema: 2.0.0
---

# Invoke-GooglePublicDnsApi

## SYNOPSIS
Performs a DNS lookup against the Google Public DNS API.

## SYNTAX

```
Invoke-GooglePublicDnsApi [-InputObject] <String> [[-Type] <String>] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet will perform a DNS lookup using the Google Public DNS API.  Data is submitted automatically via something like DNS-over-HTTPS (DoH), and DNSSEC-validated responses are returned and decoded into a native PowerShell object.

## EXAMPLES

### Example 1
```powershell
PS C:\> Invoke-GooglePublicDnsApi "_dmarc.contoso.com" -Type "TXT"
```

Fetches the DNSSEC-validated DMARC record for contoso.com.

## PARAMETERS

### -InputObject
The fully-qualified domain name that will be looked up.  You do not need to specify a trailing period.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Type
The resource record type to look up.  Currently, only types required by MailPolicyExplainer are supported, as this is only visible to end users to assist with debugging of this module under varying network conditions.

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: A, AAAA, CNAME, MX, SPF, TLSA, TXT

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
This cmdlet does not accept pipeline input.

## OUTPUTS

### System.Management.Automation.PSObject
A PSObject is returned containing the JSON-decoded response from Google Public DNS.

## NOTES
This cmdlet intended to be used to debug the module operation, and should not be used by end users.  DNSSEC is mandatory but checked only by the resolver, and only a subset of resource records are supported.  This cmdlet is subject to change and may be modified, removed, or replaced at any time.

## RELATED LINKS

[Resolve-DnsName]()
[JSON API for DoH](https://developers.google.com/speed/public-dns/docs/doh/json)