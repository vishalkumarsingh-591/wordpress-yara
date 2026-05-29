/* =========================================================
   OWASP-aligned WordPress / PHP rules
   Per-file prefix: owasp_
   (Refactored: drops near-duplicates with wordpress-advance/owasp,
    keeps the high-value OWASP-mapped checks unique to this file.)
   ========================================================= */

rule owasp_a01_broken_access_control_admin_action_no_cap
{
    meta:
        description = "Admin-level wp_* / update_* call with $_POST/$_GET and no current_user_can"
        category    = "A01-AccessControl"
        severity    = "high"
        confidence  = "medium"

    strings:
        $action = /(wp_insert_user|wp_update_user|wp_delete_user|update_user_meta|delete_user_meta|wp_set_password)\s*\(/ nocase
        $input  = /\$_(GET|POST|REQUEST)\s*\[/
        $cap    = "current_user_can"

    condition:
        filesize < 10MB and $action and $input and not $cap
}

rule owasp_a02_crypto_failures_weak_hash
{
    meta:
        description = "MD5/SHA1 used to hash a 'password' / 'token' / 'secret' variable"
        category    = "A02-Crypto"
        severity    = "medium"
        confidence  = "medium"

    strings:
        $md5    = /\bmd5\s*\(\s*\$(password|pass|pwd|token|secret)\b/ nocase
        $sha1   = /\bsha1\s*\(\s*\$(password|pass|pwd|token|secret)\b/ nocase

    condition:
        filesize < 10MB and ( $md5 or $sha1 )
}

rule owasp_a03_injection_sql_concat_query
{
    meta:
        description = "$wpdb->query / get_results / mysqli_query string concatenation with a variable"
        category    = "A03-SQLi"
        severity    = "high"
        confidence  = "medium"

    strings:
        $q1   = /\$wpdb->(query|get_results|get_row|get_var|get_col)\s*\(\s*['"][^'"]*\.\s*\$\w+/ nocase
        $q2   = /\$wpdb->(query|get_results|get_row|get_var|get_col)\s*\(\s*['"][^'"]*\$\w+[^'"]*['"]\s*\)/ nocase
        $q3   = /mysqli_query\s*\([^)]*['"][^'"]*\$\w+/ nocase
        $prep = "->prepare("

    condition:
        filesize < 10MB and ( $q1 or $q2 or $q3 ) and not $prep
}

rule owasp_a03_injection_command_with_user_input
{
    meta:
        description = "system/exec/shell_exec containing $_GET/$_POST without escapeshellarg/escapeshellcmd"
        category    = "A03-CmdInjection"
        severity    = "critical"
        confidence  = "high"

    strings:
        $exec   = /\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\([^)]{0,200}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $safe1  = "escapeshellarg"
        $safe2  = "escapeshellcmd"

    condition:
        filesize < 10MB and $exec and not $safe1 and not $safe2
}

rule owasp_a03_injection_xss_echo
{
    meta:
        description = "echo of $_GET/$_POST without esc_* / sanitize_text_field / wp_kses"
        category    = "A03-XSS"
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

rule owasp_a04_insecure_design_missing_rate_limit_on_login
{
    meta:
        description = "Custom authenticate/login function with no throttle/captcha/limit keyword present"
        category    = "A04-InsecureDesign"
        severity    = "medium"
        confidence  = "low"

    strings:
        $auth   = /function\s+\w*(authenticate|login|signon)\w*\s*\(/ nocase
        $hook   = /add_filter\s*\(\s*['"]authenticate['"]/ nocase
        $limit1 = /(throttle|rate_limit|limit_login|login_attempts)/ nocase
        $limit2 = /(recaptcha|captcha|hcaptcha)/ nocase
        $limit3 = /(get_transient|set_transient)\s*\(/ nocase

    condition:
        filesize < 10MB and ( $auth or $hook ) and not any of ($limit*)
}

rule owasp_a05_security_misconfig_debug_enabled
{
    meta:
        description = "WP_DEBUG / WP_DEBUG_DISPLAY defined as true"
        category    = "A05-Misconfig"
        severity    = "low"
        confidence  = "high"

    strings:
        $d1 = /define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*true\s*\)/ nocase
        $d2 = /define\s*\(\s*['"]WP_DEBUG_DISPLAY['"]\s*,\s*true\s*\)/ nocase
        $d3 = /define\s*\(\s*['"]SAVEQUERIES['"]\s*,\s*true\s*\)/ nocase

    condition:
        filesize < 5MB and any of ($d*)
}

rule owasp_a06_vulnerable_components_eol_dependency
{
    meta:
        description = "composer.json/package.json present — review with SCA; flagged for visibility only"
        category    = "A06-Components"
        severity    = "info"
        confidence  = "high"

    strings:
        $comp  = /"require"\s*:/
        $pkg   = /"dependencies"\s*:/

    condition:
        filesize < 5MB and ( $comp or $pkg )
}

rule owasp_a07_identification_auth_failure_user_lookup_input
{
    meta:
        description = "User identifier read from $_POST/$_GET feeds wp_set_auth_cookie or wp_set_current_user without cap/nonce/logged-in check"
        category    = "A07-AuthFailure"
        severity    = "critical"
        confidence  = "high"

    strings:
        $input   = /\$_(POST|GET|REQUEST)\s*\[\s*['"](id|user_id|userid|email|mail|login|username|user_login)['"]\s*\]/ nocase
        $lookup  = /get_user_by\s*\(\s*['"](id|email|login)['"]\s*,/ nocase
        $set1    = /wp_set_current_user\s*\(/
        $set2    = /wp_set_auth_cookie\s*\(/
        $cap     = "current_user_can"
        $nonce   = "wp_verify_nonce"
        $logged  = "is_user_logged_in"

    condition:
        filesize < 10MB and $input and $lookup and ( $set1 or $set2 ) and
        not $cap and not $nonce and not $logged
}

rule owasp_a08_data_integrity_unserialize_user_input
{
    meta:
        description = "unserialize() on user input — deserialization / object injection"
        category    = "A08-DataIntegrity"
        severity    = "critical"
        confidence  = "high"

    strings:
        $u1 = /unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $u2 = /unserialize\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase

    condition:
        filesize < 10MB and any of ($u*)
}

rule owasp_a09_logging_token_leaked_to_log
{
    meta:
        description = "error_log / var_dump / print_r / console.log called with access/id/refresh token variable"
        category    = "A09-Logging"
        severity    = "high"
        confidence  = "medium"

    strings:
        $log_php = /(error_log|var_dump|print_r|var_export)\s*\(\s*\$(access_token|id_token|refresh_token|jwt|api_key|client_secret)\b/ nocase
        $log_js  = /console\.(log|debug|info)\s*\(\s*\w*(access_token|id_token|refresh_token|jwt|api_key|client_secret)\b/ nocase
        $log_echo = /echo\s+\$(access_token|id_token|refresh_token|jwt|client_secret)\b/ nocase

    condition:
        filesize < 10MB and ( $log_php or $log_js or $log_echo )
}

rule owasp_a10_ssrf_remote_fetch_with_input
{
    meta:
        description = "wp_remote_*/file_get_contents/curl_init given $_GET/$_POST without URL validation"
        category    = "A10-SSRF"
        severity    = "high"
        confidence  = "medium"

    strings:
        $r1   = /wp_remote_(get|post|request)\s*\([^)]{0,200}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $r2   = /file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $r3   = /curl_init\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $safe = /(wp_http_validate_url|FILTER_VALIDATE_URL)/

    condition:
        filesize < 10MB and any of ($r*) and not $safe
}
