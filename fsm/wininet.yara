rule sc {
 strings:
   $str1 = "Set-Cookie:" fullword ascii
 condition:
   $str1
}

rule lm {
 strings:
   $str2 = "Last-Modified:" fullword ascii
 condition:
   $str2
}
