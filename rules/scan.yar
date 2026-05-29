/* =========================================================
   General WordPress vulnerability scan rules
   Per-file prefix: scan_
   ========================================================= */

rule scan_csrf_state_change_post_no_nonce
{
    meta:
        description = "$_POST used in update_option/delete_option without nonce or capability check"
        category    = "CSRF"
        severity    = "high"
        confidence  = "medium"

    strings:
        $input   = /\$_POST\s*\[/
        $action1 = /update_option\s*\(/
        $action2 = /delete_option\s*\(/
        $nonce1  = "check_admin_referer"
        $nonce2  = "check_ajax_referer"
        $nonce3  = "wp_verify_nonce"
        $auth    = "current_user_can"

    condition:
        filesize < 10MB and $input and ( $action1 or $action2 ) and
        not any of ($nonce*) and not $auth
}

rule scan_xss_echo_superglobal
{
    meta:
        description = "echo of $_GET/$_POST without esc_* / wp_kses / sanitize_text_field anywhere"
        category    = "XSS"
        severity    = "high"
        confidence  = "medium"

    strings:
        $echo_super = /echo\s+[^;]{0,200}\$_(GET|POST|REQUEST)\s*\[/ nocase
        $print_super = /print\s+[^;]{0,200}\$_(GET|POST|REQUEST)\s*\[/ nocase
        $safe1 = "esc_html"
        $safe2 = "esc_attr"
        $safe3 = "esc_url"
        $safe4 = "wp_kses"
        $safe5 = "sanitize_text_field"
        $safe6 = "esc_textarea"

    condition:
        filesize < 10MB and ( $echo_super or $print_super ) and
        not any of ($safe*)
}

rule scan_rce_exec_with_user_input
{
    meta:
        description = "eval/exec/system/shell_exec containing $_GET/$_POST without escapeshellarg"
        category    = "RCE"
        severity    = "critical"
        confidence  = "high"

    strings:
        $call_super = /\b(eval|exec|system|shell_exec|passthru|proc_open|popen)\s*\([^)]{0,200}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $safe       = "escapeshellarg"

    condition:
        filesize < 10MB and $call_super and not $safe
}

rule scan_sqli_wpdb_query_with_input
{
    meta:
        description = "$wpdb->query / DB::select with $_GET/$_POST and no prepare() / esc_sql nearby"
        category    = "SQLi"
        severity    = "high"
        confidence  = "medium"

    strings:
        $wpdb    = /\$wpdb->(query|get_results|get_row|get_var|get_col)\s*\(/
        $laravel = /DB::(select|raw|statement)\s*\(/
        $input   = /\$_(GET|POST|REQUEST)\s*\[/
        $safe1   = "->prepare("
        $safe2   = "esc_sql("
        $safe3   = "DB::table"

    condition:
        filesize < 10MB and ( $wpdb or $laravel ) and $input and
        not $safe1 and not $safe2 and not $safe3
}

rule scan_file_write_with_user_input
{
    meta:
        description = "file_put_contents / fopen with $_POST and no sanitize_file_name"
        category    = "FileWrite"
        severity    = "high"
        confidence  = "medium"

    strings:
        $write_super = /(file_put_contents|fopen)\s*\([^)]{0,200}\$_(POST|REQUEST|FILES)/ nocase
        $safe        = "sanitize_file_name"

    condition:
        filesize < 10MB and $write_super and not $safe
}

rule scan_ssrf_remote_fetch_with_user_input
{
    meta:
        description = "wp_remote_get / file_get_contents called with $_GET/$_POST and no URL validation"
        category    = "SSRF"
        severity    = "high"
        confidence  = "medium"

    strings:
        $req_super = /(wp_remote_(get|post|request)|file_get_contents|curl_init)\s*\([^)]{0,200}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $safe1     = "wp_http_validate_url"
        $safe2     = "FILTER_VALIDATE_URL"

    condition:
        filesize < 10MB and $req_super and not $safe1 and not $safe2
}

rule scan_open_redirect_redirect_uri
{
    meta:
        description = "wp_redirect with $_GET-controlled URL and no wp_safe_redirect / wp_validate_redirect"
        category    = "OpenRedirect"
        severity    = "medium"
        confidence  = "medium"

    strings:
        $redir = /wp_redirect\s*\([^)]{0,200}\$_(GET|POST|REQUEST)/ nocase
        $safe1 = "wp_safe_redirect"
        $safe2 = "wp_validate_redirect"

    condition:
        filesize < 10MB and $redir and not $safe1 and not $safe2
}

rule scan_jwt_secret_hardcoded
{
    meta:
        description = "Hardcoded JWT/OAuth/API secret literal of 16+ chars"
        category    = "Secret"
        severity    = "high"
        confidence  = "medium"

    strings:
        $jwt_secret  = /['"]?JWT_SECRET['"]?\s*[:=,]\s*['"][A-Za-z0-9_\-\.~]{16,}['"]/ nocase
        $api_key     = /['"]?(api_key|apikey)['"]?\s*[:=,]\s*['"][A-Za-z0-9_\-\.~]{20,}['"]/ nocase
        $cli_secret  = /['"]?client_secret['"]?\s*[:=,]\s*['"][A-Za-z0-9_\-\.~]{20,}['"]/ nocase

    condition:
        filesize < 5MB and any of them
}

rule scan_ajax_nopriv_no_capability_check
{
    meta:
        description = "wp_ajax_nopriv_ hook reads $_POST but has no capability/auth check"
        category    = "AJAX/Auth"
        severity    = "high"
        confidence  = "medium"

    strings:
        $ajax  = "wp_ajax_nopriv_" nocase
        $input = /\$_(POST|GET|REQUEST)\s*\[/
        $auth1 = "current_user_can"
        $auth2 = "is_user_logged_in"
        $auth3 = "check_ajax_referer"
        $auth4 = "wp_verify_nonce"

    condition:
        filesize < 10MB and $ajax and $input and
        not any of ($auth*)
}
