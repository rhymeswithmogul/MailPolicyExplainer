---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-AdspRecord.md
schema: 2.0.0
---

# Test-AdspRecord

## SYNOPSIS
Tests a domain's DKIM Author Domain Signing Practices record.

## SYNTAX

```
Test-AdspRecord [-DomainName] <String> [-DisableDnssecVerification] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet will test a domain's DKIM Author Domain Signing Practices record.

ADSP records describe outbound DKIM signing practices, and whether or not outgoing emails are expected to have DKIM Author Domain Signatures (that is, where the signature email or domain is the same as the sender's email or domain).  Stored as the DNS TXT record "_adsp._domainkey", this can be set to one of three values:

1. "dkim=unknown" says that the domain might sign some or all email.
2. "dkim=all" says that all mail from the domain contains an Author Domain Signature.
3. "dkim=discardable" says that all mail from the domain contains an Author Domain Signature, and unsigned or incorrectly-signed messages may be discarded by the receiving server.

## EXAMPLES

### Example 1
```powershell
PS C:\> Test-AdspRecord contoso.com
```

Tests the DNS TXT record "_adsp._domainkey.contoso.com".

## PARAMETERS

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
This cmdlet does not accept pipeline input.

## OUTPUTS

### System.Void
This cmdlet does not generate pipeline output.

## NOTES
DKIM ADSP was finalized in 2009, but it never saw much use.  Due to its lack of popularity, it was declared "historic" by the IETF only four years later.  Thus, its use is discouraged;  it is perfectly acceptable, normal, and expected not to see domains with defined ADS policies.

## RELATED LINKS

[about_DKIMADSP]()
[Test-DkimSelector]()
