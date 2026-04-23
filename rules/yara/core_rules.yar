rule Ragnar_Powershell_EncodedCommand : script
{
    meta:
        severity = 70
        description = "PowerShell encoded command pattern"
        category = "script"
    strings:
        $ps1 = "powershell" ascii nocase
        $ps2 = "pwsh" ascii nocase
        $enc1 = "-enc" ascii nocase
        $enc2 = "-encodedcommand" ascii nocase
    condition:
        uint16(0) != 0x5A4D and
        any of ($ps*) and any of ($enc*)
}

rule Ragnar_MemoryInjection_Apis : script
{
    meta:
        severity = 75
        description = "Memory injection APIs found together"
        category = "binary"
    strings:
        $a1 = "CreateRemoteThread" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "VirtualAllocEx" ascii wide
        $a4 = "NtWriteVirtualMemory" ascii wide
        $a5 = "NtCreateThreadEx" ascii wide
    condition:
        uint16(0) != 0x5A4D and
        2 of them
}

rule Ragnar_RunKey_Persistence : script
{
    meta:
        severity = 55
        description = "Run key persistence markers"
        category = "persistence"
    strings:
        $r1 = "CurrentVersion\\Run" ascii wide nocase
        $r2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $r3 = "Winlogon\\Shell" ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and
        any of them
}

rule Ragnar_LOLBin_ScriptChain : script
{
    meta:
        severity = 60
        description = "Suspicious LOLBin script chain"
        category = "execution"
    strings:
        $m1 = "mshta" ascii wide nocase
        $m2 = "rundll32" ascii wide nocase
        $m3 = "regsvr32" ascii wide nocase
        $m4 = "wscript" ascii wide nocase
        $m5 = "cscript" ascii wide nocase
        $m6 = "Invoke-Expression" ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and
        2 of them
}
