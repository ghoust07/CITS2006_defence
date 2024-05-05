rule Detect_PowerShell_Scripts {
    meta:
        author = "OLIVER"
        description = "Detects potentially malicious PowerShell scripts used in attacks"
    strings:
        $ps1 = "Invoke-Expression" wide ascii
        $ps2 = "DownloadString" wide ascii
        $ps3 = "IEX" wide ascii 
        $ps4 = /powershell\.exe -nop -exec bypass/
    condition:
        any of them
}

rule Detect_Bash_Scripts {
    meta:
        author = "OLIVER"
        description = "Detects potentially malicious Bash scripts"
    strings:
        $bash1 = "#!/bin/bash" wide ascii
        $bash2 = "curl " wide ascii
        $bash3 = "wget " wide ascii
        $bash4 = "chmod 777" wide ascii 
    condition:
        any of them
}

rule Detect_Python_Scripts {
    meta:
        author = "OLIVER"
        description = "Detects potentially malicious Python scripts"
    strings:
        $py1 = "#!/usr/bin/env python" wide ascii
        $py2 = "import os" wide ascii
        $py3 = "subprocess" wide ascii
        $py4 = "sys.executable" wide ascii
    condition:
        any of them
}
rule Detect_JavaScript_in_Files {
    meta:
        author = "OLIVER"
        description = "Detects JavaScript embedded in HTML or PDF files that may be used for malicious purposes"
    strings:
        $js1 = "<script>" wide ascii
        $js2 = "eval(" wide ascii
        $js3 = "Function(" wide ascii
        $js4 = /document\.getElementById\(/
    condition:
        any of them and (filetype == "html" or filetype == "pdf")
}

