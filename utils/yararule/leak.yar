/*
    These rules attempt to find leaks
*/

rule leak_filter
{
    meta:
        author = "@andreyglauzer"
        score = 10

    strings:
	$leak_add = /\bleak\b/
    condition:
        any of them

}
