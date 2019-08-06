/*
    These rules attempt to find pwned
*/

rule pwned_filter
{
    meta:
        author = "@andreyglauzer"
        score = 10

    strings:
	$pwned_add = /\bpwned\b/
    condition:
        any of them

}


rule core_keywords
{
    meta:
        author = "@andreyglauzer"
        score = 20

    strings:
        $tango_down = "TANGO DOWN" wide ascii nocase
        $antisec = "antisec" wide ascii nocase
        $hacked = "hacked by" wide ascii nocase
        $nmap_scan = "Nmap scan report for" wide ascii nocase
        $enabled_sec = "enable secret" wide ascii nocase
        $enable_pass = "enable password" wide ascii nocase
    condition:
        any of them

}
