import "pe"

rule Ragnar_PE_UPX_Sections : pe packer
{
    meta:
        severity = 38
        description = "PE exposes classic UPX section naming"
        category = "packer"
    condition:
        pe.is_pe and
        for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == "UPX0" or
            pe.sections[i].name == "UPX1" or
            pe.sections[i].name == "UPX2"
        )
}

rule Ragnar_PE_RWX_Section : pe
{
    meta:
        severity = 32
        description = "PE contains a section that is both writable and executable"
        category = "memory"
    condition:
        pe.is_pe and
        for any i in (0 .. pe.number_of_sections - 1): (
            (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE) != 0 and
            (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) != 0
        )
}

rule Ragnar_PE_Injection_APIs : pe
{
    meta:
        severity = 44
        description = "PE imports a classic remote injection chain"
        category = "injection"
    condition:
        pe.is_pe and
        (
            pe.imports("kernel32.dll", "CreateRemoteThread") or
            pe.imports("ntdll.dll", "NtCreateThreadEx")
        ) and
        (
            pe.imports("kernel32.dll", "VirtualAllocEx") or
            pe.imports("kernel32.dll", "WriteProcessMemory") or
            pe.imports("ntdll.dll", "NtWriteVirtualMemory")
        )
}

rule Ragnar_PE_LowImport_Overlay : pe packer
{
    meta:
        severity = 24
        description = "PE combines a very small import table with a non-trivial overlay"
        category = "packer"
    condition:
        pe.is_pe and
        pe.overlay.size >= 4096 and
        pe.number_of_sections <= 5 and
        pe.number_of_imported_functions <= 12
}

rule Ragnar_PE_RecoverySabotage_Strings : pe ransomware
{
    meta:
        severity = 62
        description = "PE embeds common recovery sabotage command patterns"
        category = "ransomware"
    strings:
        $s1 = "vssadmin delete shadows" ascii wide nocase
        $s2 = "wbadmin delete catalog" ascii wide nocase
        $s3 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $s4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $s5 = "wevtutil cl" ascii wide nocase
        $s6 = "diskshadow" ascii wide nocase
        $s7 = "cipher /w:" ascii wide nocase
    condition:
        pe.is_pe and
        2 of them
}

rule Ragnar_PE_Dropper_Inject_Combo : pe malware
{
    meta:
        severity = 58
        description = "PE combines downloader/dropper and remote-injection behavior"
        category = "dropper"
    condition:
        pe.is_pe and
        (
            pe.imports("urlmon.dll", "URLDownloadToFileA") or
            pe.imports("urlmon.dll", "URLDownloadToFileW") or
            pe.imports("wininet.dll", "InternetOpenUrlA") or
            pe.imports("wininet.dll", "InternetOpenUrlW") or
            pe.imports("winhttp.dll", "WinHttpOpenRequest")
        ) and
        (
            pe.imports("kernel32.dll", "CreateRemoteThread") or
            pe.imports("ntdll.dll", "NtCreateThreadEx")
        ) and
        (
            pe.imports("kernel32.dll", "VirtualAllocEx") or
            pe.imports("kernel32.dll", "WriteProcessMemory") or
            pe.imports("ntdll.dll", "NtWriteVirtualMemory")
        )
}
