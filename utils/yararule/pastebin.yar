/*
    These rules attempt to find pastebin
*/

rule pastebin_filter
{
    meta:
        author = "@andreyglauzer"
        score = 10

    strings:
	$pastebin_add = /\bpastebin\b/
    condition:
        any of them

}
