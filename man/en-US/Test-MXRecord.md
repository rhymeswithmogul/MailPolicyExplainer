---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-MXRecord.md
schema: 2.0.0
---

# Test-MXRecord

## SYNOPSIS
Tests a domain's MX records.

## SYNTAX

```
Test-MXRecord [-DomainName] <String> [-DisableDnssecVerification] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet will check the MX records for a domain.  MX records define which servers receive a domain's email, and in which order they should be tried.

A lack of MX records does not imply that the domain does not receive email!  If there are no MX records, then the root A and AAAA records will be used for mail delivery.   To indicate that a domain does not receive (or send) email, a null MX record should be used (server = ".", priority 0).

## EXAMPLES

### Example 1
```powershell
PS C:\> Test-MXRecord contoso.com
```

Tests the DNS MX records (if they exist) for "contoso.com."

## PARAMETERS

### -DisableDnssecVerification
Disable DNSSEC validation.  This cmdlet will not request authenticated data from the resolver;  thus, DNSSEC validation of resource records will not occur, nor will the user be informed about unauthenticated denial of existence of DNS records.  Using this switch is NOT RECOMMENDED for production use and should only be used for diagnostic and troubleshooting purposes only!

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: CD, DnssecCD, NoDnssec, DisableDnssec

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainName
The domain name to test.  Be sure to include any applicable subdomains (i.e., "contoso.com" and "newsletters.contoso.com" are two different domains).

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
This cmdlet does not accept pipeline input.

## OUTPUTS

### System.Void
This cmdlet does not generate pipeline output.

## NOTES
MX records were defined way back in RFC 974, with updates in RFC 5321.  Null MX records are defined in RFC 7505.

## RELATED LINKS

[about_MXRecords]()
[about_NullMXRecords]()
[about_SMTP]()
