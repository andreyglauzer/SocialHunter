/*
    These rules attempt to find email leaks
*/

rule email_filter
{
    meta:
        author = "@kovacsbalu"
        score = 30

    strings:
	$email_add = /\b[\w-]+(\.[\w-]+)*@[\w-]+(\.[\w-]+)*\.[a-zA-Z-]+[\w-]\b/
    condition:
        any of them

}
