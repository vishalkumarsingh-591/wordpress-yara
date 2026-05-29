/* =========================================================
   WordPress OWASP-aligned rules (compact set)
   Per-file prefix: wpo_
   ========================================================= */

rule wpo_csrf_missing_nonce_for_state_change
{
    meta:
        description = "State-changing function called with superglobal as an argument, with no nonce verifier in file"
        category    = "CSRF"
        severity    = "high"
        confidence  = "medium"

    strings:
        /* Sink must RECEIVE the superglobal as an argument (not merely co-exist in the file). */
        $sink_with_input = /(update_option|delete_option|wp_update_post|wp_delete_post|wp_insert_post|update_user_meta|delete_user_meta|wp_set_password|wp_create_user|wp_insert_user|wp_update_user|wp_delete_user|unlink|mkdir|file_put_contents)\s*\([^)]{0,300}\$_(POST|GET|REQUEST|COOKIE)/ nocase

        $nonce1 = "check_admin_referer"
        $nonce2 = "check_ajax_referer"
        $nonce3 = "wp_verify_nonce"

    condition:
        filesize < 10MB and $sink_with_input and not any of ($nonce*)
}

rule wpo_sqli_select_with_superglobal
{
    meta:
        description = "SELECT statement string interpolation that includes $_GET/$_POST"
        category    = "SQLi"
        severity    = "high"
        confidence  = "medium"

    strings:
        $sel1 = /["']SELECT[^"']{0,300}\$_(GET|POST|REQUEST)/ nocase
        $sel2 = /["']SELECT[^"']{0,300}\$\w+[^"']{0,300}["']/ nocase
        $prep = "->prepare("

    condition:
        filesize < 10MB and ( $sel1 or $sel2 ) and not $prep
}

rule wpo_xss_reflected_echo
{
    meta:
        description = "Echo of $_GET/$_POST/$_REQUEST with no esc_* call in file"
        category    = "XSS"
        severity    = "high"
        confidence  = "medium"

    strings:
        $echo  = /echo\s+[^;]{0,200}\$_(GET|POST|REQUEST)\s*\[/ nocase
        $safe1 = "esc_html"
        $safe2 = "esc_attr"
        $safe3 = "esc_url"
        $safe4 = "wp_kses"
        $safe5 = "sanitize_text_field"

    condition:
        filesize < 10MB and $echo and not any of ($safe*)
}

rule wpo_arbitrary_file_delete_from_input
{
    meta:
        description = "unlink() called on $_GET/$_POST/$_REQUEST without sanitize_file_name / realpath check"
        category    = "FileDeletion"
        severity    = "high"
        confidence  = "high"

    strings:
        $unlink = /unlink\s*\([^)]{0,200}\$_(GET|POST|REQUEST)/ nocase
        $safe1  = "sanitize_file_name"
        $safe2  = "realpath("

    condition:
        filesize < 10MB and $unlink and not $safe1 and not $safe2
}

rule wpo_file_upload_no_type_validation
{
    meta:
        description = "move_uploaded_file on $_FILES without wp_check_filetype / mime check / sanitize_file_name"
        category    = "FileUpload"
        severity    = "high"
        confidence  = "medium"

    strings:
        $upload = /move_uploaded_file\s*\([^)]{0,200}\$_FILES/ nocase
        $safe1  = "wp_check_filetype"
        $safe2  = "finfo_file"
        $safe3  = "wp_handle_upload"
        $safe4  = "sanitize_file_name"

    condition:
        filesize < 10MB and $upload and not any of ($safe*)
}

rule wpo_rfi_lfi_superglobal_include
{
    meta:
        description = "include/require with $_GET/$_POST/$_REQUEST/$_COOKIE"
        category    = "LFI/RFI"
        severity    = "critical"
        confidence  = "high"

    strings:
        $inc = /(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase

    condition:
        filesize < 10MB and $inc
}

rule wpo_privileged_option_update_no_cap_check
{
    meta:
        description = "update_option/site_option/user_meta called with superglobal input, no current_user_can"
        category    = "AccessControl"
        severity    = "high"
        confidence  = "medium"

    strings:
        $update = /update_(option|site_option|user_meta)\s*\([^)]{0,200}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $cap    = "current_user_can"

    condition:
        filesize < 10MB and $update and not $cap
}

rule wpo_require_relative_no_abspath
{
    meta:
        description = "PHP file uses require/include on a relative path string without plugin_dir_path/ABSPATH/__DIR__ helpers"
        category    = "FilePath"
        severity    = "medium"
        confidence  = "low"

    strings:
        $php_open = "<?php"
        /* require/include "relative.php" — first char of literal is NOT / or \, and ends in .php */
        $req_rel  = /(require|include)(_once)?\s*\(?\s*['"][^\/\\][^'"]{0,200}\.php['"]\s*\)?/ nocase
        $safe1    = "plugin_dir_path"
        $safe2    = "get_template_directory"
        $safe3    = "get_stylesheet_directory"
        $safe4    = "ABSPATH"
        $safe5    = "__DIR__"
        $safe6    = "dirname("

    condition:
        filesize < 5MB and $php_open and $req_rel and not any of ($safe*)
}

rule wpo_php_file_without_abspath_guard
{
    meta:
        description = "PHP file that executes top-level (non-class) code touching request input, with no ABSPATH/WPINC guard. Pure class/interface/trait library files are excluded."
        category    = "DirectAccess"
        severity    = "low"
        confidence  = "low"

    strings:
        $php_open  = "<?php"

        /* Top-level (column 0) executable statements — not inside a class method (which would be indented) */
        $top_super  = /(\r?\n|^)\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[/
        $top_echo   = /(\r?\n|^)echo\s/
        $top_if     = /(\r?\n|^)if\s*\(\s*isset\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/
        $top_action = /(\r?\n|^)(do_action|apply_filters|add_action|add_filter)\s*\(/

        /* File is a class/interface/trait definition — not a request-handling entry point */
        $is_class      = /(\r?\n|^)\s*(abstract\s+class|final\s+class|class|interface|trait)\s+\w+/
        $is_namespace  = /(\r?\n|^)\s*namespace\s+[\w\\]+/

        /* Guards */
        $abspath1 = "ABSPATH"
        $abspath2 = "WPINC"
        $abspath3 = /defined\s*\(\s*['"]ABSPATH['"]\s*\)/ nocase
        $abspath4 = /defined\s*\(\s*['"]WPINC['"]\s*\)/ nocase

    condition:
        filesize < 5MB and $php_open and
        ( $top_super or $top_echo or $top_if or $top_action ) and
        not $is_class and not $is_namespace and
        not any of ($abspath*)
}

rule wpo_unserialize_on_superglobal
{
    meta:
        description = "unserialize() called on $_GET/$_POST/$_REQUEST or base64-decoded input"
        category    = "Deserialization"
        severity    = "critical"
        confidence  = "high"

    strings:
        $u1 = /unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $u2 = /unserialize\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase

    condition:
        filesize < 10MB and any of ($u*)
}
