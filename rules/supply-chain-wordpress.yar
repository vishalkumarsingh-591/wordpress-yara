/* =========================================================
   WordPress plugin/theme supply-chain attacks
   Per-file prefix: sup_
   ========================================================= */

rule sup_remote_fetch_then_execute
{
    meta:
        description = "Plugin/theme fetches remote payload and feeds it to eval/assert/system"
        category    = "SupplyChain/RCE"
        severity    = "critical"
        confidence  = "high"

    strings:
        $fetch1 = "wp_remote_get(" nocase
        $fetch2 = "wp_remote_post(" nocase
        $fetch3 = "file_get_contents("
        $fetch4 = "curl_exec("
        $exec1  = /\beval\s*\(/
        $exec2  = /\bassert\s*\(/
        $exec3  = /\bshell_exec\s*\(/
        $exec4  = /\bexec\s*\(/
        $exec5  = /\bsystem\s*\(/

    condition:
        filesize < 10MB and any of ($fetch*) and any of ($exec*)
}

rule sup_obfuscated_payload_dropper
{
    meta:
        description = "Multiple obfuscation primitives combined with file_put_contents/fopen"
        category    = "SupplyChain/Dropper"
        severity    = "high"
        confidence  = "high"

    strings:
        $obf1   = /base64_decode\s*\(/
        $obf2   = /gzinflate\s*\(/
        $obf3   = /gzuncompress\s*\(/
        $obf4   = /str_rot13\s*\(/
        $write1 = /file_put_contents\s*\(/
        $write2 = /fopen\s*\(/

    condition:
        filesize < 10MB and 2 of ($obf*) and any of ($write*)
}

rule sup_external_update_server
{
    meta:
        description = "Plugin overrides update transient and fetches HTTP(S) URL"
        category    = "SupplyChain/Update"
        severity    = "high"
        confidence  = "medium"

    strings:
        $update1 = "pre_set_site_transient_update_plugins" nocase
        $update2 = /set_site_transient\s*\(\s*['"]update_plugins['"]/ nocase
        $update3 = "plugins_api_result" nocase
        $remote_get = /wp_remote_(get|post)\s*\(\s*['"]https?:\/\//i

    condition:
        filesize < 10MB and any of ($update*) and $remote_get
}

rule sup_external_zip_download_install
{
    meta:
        description = "Plugin downloads ZIP from arbitrary URL and unzips it"
        category    = "SupplyChain/ZIP"
        severity    = "critical"
        confidence  = "high"

    strings:
        $download = "download_url(" nocase
        $unzip1   = "unzip_file(" nocase
        $unzip2   = "ZipArchive" nocase
        $remote   = /https?:\/\//

    condition:
        filesize < 10MB and $download and any of ($unzip*) and $remote
}

rule sup_hidden_admin_user_creation
{
    meta:
        description = "Creates user and assigns administrator role / wp_capabilities directly"
        category    = "SupplyChain/Backdoor"
        severity    = "critical"
        confidence  = "high"

    strings:
        $user1 = "wp_create_user(" nocase
        $user2 = "wp_insert_user(" nocase
        $meta  = "update_user_meta(" nocase
        $role1 = /['"]administrator['"]/
        $caps  = /['"]wp_capabilities['"]/

    condition:
        filesize < 10MB and
        ( any of ($user1, $user2) or ( $meta and $caps ) ) and
        ( $role1 or $caps )
}

rule sup_vendor_folder_contains_exec
{
    meta:
        description = "Executable backdoor logic inside /vendor/ subtree"
        category    = "SupplyChain/Backdoor"
        severity    = "high"
        confidence  = "low"

    strings:
        $vendor = "/vendor/"
        $exec1  = /\beval\s*\(/
        $exec2  = /\bshell_exec\s*\(/
        $exec3  = /\bsystem\s*\(/
        $exec4  = /\bproc_open\s*\(/

    condition:
        filesize < 10MB and $vendor and any of ($exec*)
}

rule sup_typosquatted_library
{
    meta:
        description = "Possible typosquatted bundled PHP library name"
        category    = "SupplyChain/Typosquat"
        severity    = "medium"
        confidence  = "low"

    strings:
        $lib1 = "phmialer" nocase
        $lib2 = "monologg" nocase
        $lib3 = "sympfony" nocase
        $lib4 = "guzzel" nocase
        $lib5 = "reqeust" nocase

    condition:
        filesize < 5MB and any of ($lib*)
}

rule sup_activation_hook_runs_exec
{
    meta:
        description = "register_activation_hook handler contains exec/system or writes files"
        category    = "SupplyChain/Activation"
        severity    = "medium"
        confidence  = "medium"

    strings:
        $activate = "register_activation_hook(" nocase
        $exec1    = /\bexec\s*\(/
        $exec2    = /\bshell_exec\s*\(/
        $exec3    = /\bsystem\s*\(/
        $write    = /file_put_contents\s*\(/

    condition:
        filesize < 10MB and $activate and ( any of ($exec*) or $write )
}

rule sup_include_remote_url
{
    meta:
        description = "include/require called on http(s):// URL literal"
        category    = "SupplyChain/RFI"
        severity    = "critical"
        confidence  = "high"

    strings:
        $rfi = /(include|require)(_once)?\s*\(\s*['"]https?:\/\//i

    condition:
        filesize < 10MB and $rfi
}
