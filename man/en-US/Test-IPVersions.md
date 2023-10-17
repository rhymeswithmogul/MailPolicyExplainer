---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-IPVersions.md
schema: 2.0.0
---

# Test-IPVersions

## SYNOPSIS
Tests to make sure a server has both IPv4 and IPv6 addresses.

## SYNTAX

```
Test-IPVersions [-HostName] <String> [<CommonParameters>]
```

## DESCRIPTION
This cmdlet will test a server to make sure that it has both IPv4 addresses and IPv6 addresses listed in DNS.

Clients may only have one address family available, so it is important for your server to be reachable over both IP versions.

## EXAMPLES

### Example 1
```powershell
PS C:\> Test-IPVersions 'mail.contoso.com'
```

Checks to make sure "mail.contoso.com" has both A and AAAA records in DNS.

## PARAMETERS

### -HostName
The hostname to test.

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
This cmdlet merely tests to make sure DNS A and AAAA records exist.  It does not test to make sure that these IP addresses are actually working.  This is done because not all hosts running this cmdlet are guaranteed to have both IPv4 and IPv6 addresses (i.e., an IPv4-only network or a NAT64 network without CLAT).

## RELATED LINKS
[Test-MailPolicy](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-MailPolicy.md)
[about_MailPolicyExplainer](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/en-US/about_MailPolicyExplainer.help.txt)
