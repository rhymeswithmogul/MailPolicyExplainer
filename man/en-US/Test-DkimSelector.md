---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-DkimSelector.md
schema: 2.0.0
---

# Test-DkimSelector

## SYNOPSIS
Tests a DKIM selector for correctness and best practices.

## SYNTAX

```
Test-DkimSelector [-DomainName] <String> [-Name] <String> [-DisableDnssecVerification] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet will test a domain's DKIM selector for correctness and to ensure that it follows best practices.

DKIM (DomainKeys Identified Mail) is a method of applying a digital signature to an email to prove that a message came from a certain domain.  The message body and some headers are hashed, and that hash is signed by a keypair.  A receiving mail server will fetch the public key from DNS and use that to verify the hash.

There can be many DKIM keys ("selectors") for a domain, so you must specify which one you want to check.

DKIM selectors can use RSA or Ed25519 keys.  Ed25519 keys are always 256-bit;  acceptable RSA keys range from 1024 to at least 4096 bits.

## EXAMPLES

### Example 1
```powershell
PS C:\> Test-DkimSelector -DomainName contoso.com -SelectorName selector1
```

Tests contoso.com's DKIM selector named "selector1".  The DNS TXT record to be resolved will be "selector1._domainkey.contoso.com."

### Example 2
```powershell
PS C:\> Test-DkimSelector shop.fabrikam.com receipts
```

Tests shop.fabrikam.com's DKIM selector named "receipts".  The DNS TXT record to be resolved will be "receipts._domainkey.shop.fabrikam.com."

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

### -Name
The name of the DKIM selector to test.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Selector, SelectorName, KeyName

Required: True
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

### System.Void
This cmdlet does not generate pipeline output.

## NOTES
This cmdlet will only verify that the DKIM DNS record is syntactically correct and up to best practices.  This cmdlet cannot check to make sure that outgoing mail is being properly signed by an MTA or milter.

DKIM is defined in RFC 6376, with updates in RFC 8301, RFC 8463, and RFC 8616.

## RELATED LINKS

[Test-DkimAdspRecord]()
[about_DKIM]()
[about_DKIMRSAKeyUpdates]()
[about_DKIMEd25519]()
