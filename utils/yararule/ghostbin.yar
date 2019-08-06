/*
    These rules attempt to find ghostbin
*/

rule ghostbin_filter
{
    meta:
        author = "@andreyglauzer"
        score = 10

    strings:
	$ghostbin_add = /\bghostbin\b/
    condition:
        any of them

}
