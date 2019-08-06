/*
    These rules attempt to find gist
*/

rule gist_filter
{
    meta:
        author = "@andreyglauzer"
        score = 10

    strings:
	$gist_add = /\bgist\b/
    condition:
        any of them

}
