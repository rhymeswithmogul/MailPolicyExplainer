# MailPolicyExplainer News
What's new in version 1.5?

## Quicker Exchange Online DKIM checks
For everyone supporting Exchange Online environments, it's such a pain to type out `Test-MailPolicy -DkimSelectorsToCheck selector1,selector2`, even with tab completion!  Now, you can use a quicker synonym:  `Test-MailPolicy -ExchangeOnlineDkim` (which you can tab-complete to your heart's content!).  Of course, you can still use `-DkimSelectorsToCheck` to check additional selectors for other services.

## Better support for Sender ID records
From the "rearranging deck chairs on the Titanic" department, this version contains several fixes to Sender ID lookups (you know, the `spf2.0` thing that Microsoft tried to shove down our throats in the early 2000's).

- Firstly, `Test-SenderIdRecord` may not have been exported at all.
- Even if it was, it only checked SPF records.
- Even if it did work as intended, it still used the word "SPF" when it meant "Sender ID".
- Secondly, when doing recursive lookups, SPF and Sender ID records would get mixed together when things `include:`d published both.  This was annoying at best, and it mistakenly countd more DNS lookups than actually happened.

All of this has been corrected.

## Cleaning up the news file
Older news can be found in the ONEWS.md (old news) file.

