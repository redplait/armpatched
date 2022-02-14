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

rule edge {
 strings:
  $str3 = "AppData\\Local\\Packages\\microsoft.microsoftedge_8wekyb3d8b" wide
 condition:
   $str3
}
