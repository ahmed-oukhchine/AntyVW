// Example custom YARA rules for AntyVW.
// Add your own rules here; AntyVW loads every *.yar / *.yara in this folder
// and combines them with its built-in rules.

rule Example_Eicar_Test {
    meta:
        description = "EICAR anti-malware test file signature"
        severity = "low"
        reference = "https://www.eicar.org/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Example_Mimikatz_Strings {
    meta:
        description = "Common Mimikatz-related strings"
        severity = "high"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "lsadump::sam" nocase
        $m3 = "kerberos::golden" nocase
        $m4 = "gentilkiwi" nocase
    condition:
        any of them
}
