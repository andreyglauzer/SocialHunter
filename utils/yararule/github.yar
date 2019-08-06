/*
    These rules attempt to find github
*/

rule github_filter
{
    meta:
        author = "@andreyglauzer"
        score = 10

    strings:
	$github_add = /\bgithub\b/
    condition:
        any of them

}
