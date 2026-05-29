/* =========================================================
   Laravel / PHP webshell & backdoor heuristics
   Per-file prefix: lar_
   NOTE: removed the original 'filename matches /.../' clause
   because YARA has no built-in `filename` keyword — that rule
   would not compile.
   ========================================================= */

rule lar_obfuscated_php
{
    meta:
        description = "PHP file using obfuscation primitives commonly seen in shells"
        category    = "RCE/Malware"
        severity    = "high"
        confidence  = "medium"

    strings:
        $eval              = /\beval\s*\(/
        $base64            = /\bbase64_decode\s*\(/
        $gz                = /\b(gzinflate|gzuncompress)\s*\(/
        $rot13             = /\bstr_rot13\s*\(/
        $strrev            = /\bstrrev\s*\(/
        $preg_replace_eval = /preg_replace\s*\(\s*['"][^'"]*\/e['"]/

    condition:
        uint16(0) == 0x3f3c and
        ( $preg_replace_eval or
          ( $eval and 1 of ($base64, $gz, $rot13, $strrev) ) )
}

rule lar_webshell_signatures
{
    meta:
        description = "Known PHP web-shell identifiers combined with command exec primitives"
        category    = "RCE/Malware"
        severity    = "critical"
        confidence  = "high"

    strings:
        $s1 = "b374k" nocase
        $s2 = "r57shell" nocase
        $s3 = "FilesMan" nocase
        $s4 = "WSO " nocase
        $s5 = "Mini Shell" nocase
        $s6 = "c99shell" nocase
        $e1 = /\bshell_exec\s*\(/
        $e2 = /\bsystem\s*\(/
        $e3 = /\bpassthru\s*\(/
        $e4 = /\bpopen\s*\(/
        $e5 = /\bproc_open\s*\(/

    condition:
        uint16(0) == 0x3f3c and 1 of ($s*) and 1 of ($e*)
}

rule lar_route_closure_dangerous_exec
{
    meta:
        description = "Laravel route closure containing eval/system/exec within ~500 bytes — likely backdoor"
        category    = "Backdoor"
        severity    = "critical"
        confidence  = "high"

    strings:
        $route_closure = /Route::(get|post|any|match|put|patch|delete)\s*\([^)]{0,200}function\s*\([^)]*\)\s*\{/ nocase
        $exec          = /\b(eval|system|exec|shell_exec|passthru|proc_open)\s*\(/

    condition:
        filesize < 5MB and $route_closure and $exec and
        for any i in (1..#exec) : (
            for any j in (1..#route_closure) : (
                @exec[i] > @route_closure[j] and
                @exec[i] < @route_closure[j] + 500
            )
        )
}

rule lar_php_dropper_writes_php_file
{
    meta:
        description = "PHP file that writes another PHP file from base64 — common dropper pattern"
        category    = "Backdoor"
        severity    = "critical"
        confidence  = "high"

    strings:
        $fpc     = /file_put_contents\s*\([^)]{0,200}\.php['"]/ nocase
        $b64     = /base64_decode\s*\(/
        $fpc_b64 = /file_put_contents\s*\([^)]{0,200}base64_decode/ nocase

    condition:
        uint16(0) == 0x3f3c and ( $fpc_b64 or ( $fpc and $b64 ) )
}
