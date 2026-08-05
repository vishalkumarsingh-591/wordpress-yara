/* =========================================================
   Advanced WordPress security rules
   Per-file prefix: wpa_
   ========================================================= */

rule wpa_insecure_tls_disabled
{
    meta:
        description = "Insecure TLS verification disabled (sslverify/verify/CURLOPT_SSL_VERIFYPEER false)"
        category    = "TLS"
        severity    = "high"
        confidence  = "high"

    strings:
        $s1 = /['"]sslverify['"]\s*=>\s*false/ nocase
        $s2 = /['"]verify['"]\s*=>\s*false/ nocase
        $s3 = /CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)/ nocase
        $s4 = /CURLOPT_SSL_VERIFYHOST\s*,\s*(0|false)/ nocase

    condition:
        filesize < 10MB and any of ($s*)
}

rule wpa_csrf_state_change_no_nonce
{
    meta:
        description = "State-changing sink uses superglobal in file with no nonce verifier"
        category    = "CSRF"
        severity    = "high"
        confidence  = "low"

    strings:
        $sink = /(update_option|delete_option|wp_update_post|file_put_contents|unlink|mkdir)\s*\(/ nocase
        $input = /\$_(GET|POST|REQUEST)\s*\[/
        $nonce1 = "check_admin_referer"
        $nonce2 = "check_ajax_referer"
        $nonce3 = "wp_verify_nonce"

    condition:
        filesize < 10MB and $sink and $input and not any of ($nonce*)
}

rule wpa_unserialize_user_input
{
    meta:
        description = "unserialize() called on $_GET/$_POST/$_REQUEST (object injection / RCE)"
        category    = "Deserialization"
        severity    = "critical"
        confidence  = "high"

    strings:
        $u1 = /unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $u2 = /unserialize\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase

    condition:
        filesize < 10MB and any of ($u*)
}

rule wpa_command_exec_or_obfuscation
{
    meta:
        description = "system/exec/shell_exec call OR multiple obfuscation primitives — flag for review"
        category    = "RCE/Obfuscation"
        severity    = "high"
        confidence  = "medium"

    strings:
        $exec     = /\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/ nocase
        $obfus1   = /base64_decode\s*\(/ nocase
        $obfus2   = /gzinflate\s*\(|gzuncompress\s*\(/ nocase
        $obfus3   = /str_rot13\s*\(/ nocase

    condition:
        filesize < 10MB and ( $exec or 2 of ($obfus*) )
}

rule wpa_static_secret_in_array_or_define
{
    meta:
        description = "Hardcoded hex secret / client_secret / oauth_secret literal"
        category    = "Secret"
        severity    = "high"
        confidence  = "medium"

    strings:
        $hex   = /['"]?(enc|encrypt|key|secret)['"]?\s*(=>|:)\s*['"][a-f0-9]{16,}['"]/ nocase
        $named = /['"]?(CLIENT_SECRET|OAUTH_SECRET|CLIENT_KEY)['"]?\s*(=>|:)\s*['"][A-Za-z0-9_\-\.~]{12,}['"]/ nocase

    condition:
        filesize < 10MB and ( $hex or $named )
}

rule wpa_oauth_state_read_but_not_validated
{
    meta:
        description = "Reads 'state' from request but no hash_equals/strcmp/=== comparison present"
        category    = "OAuth/CSRF"
        severity    = "high"
        confidence  = "low"

    strings:
        $state_read   = /\$_(GET|REQUEST|POST)\s*\[\s*['"]state['"]\s*\]/ nocase
        $cmp_eq       = /===\s*\$state\b/
        $cmp_strcmp   = /strcmp\s*\(\s*\$state\b/
        $cmp_hashe    = /hash_equals\s*\(/
        $cmp_session  = /\$_SESSION\s*\[\s*['"]state['"]\s*\]/

    condition:
        filesize < 10MB and $state_read and
        not $cmp_eq and not $cmp_strcmp and not $cmp_hashe and not $cmp_session
}

rule wpa_file_upload_no_validation
{
    meta:
        description = "move_uploaded_file on $_FILES without wp_check_filetype / sanitize_file_name / finfo_file"
        category    = "FileUpload"
        severity    = "high"
        confidence  = "medium"

    strings:
        $upload = /move_uploaded_file\s*\([^)]{0,200}\$_FILES/ nocase
        $safe1  = "wp_check_filetype"
        $safe2  = "sanitize_file_name"
        $safe3  = "finfo_file"
        $safe4  = "wp_handle_upload"

    condition:
        filesize < 10MB and $upload and not any of ($safe*)
}

rule wpa_rfi_lfi_includes_from_input
{
    meta:
        description = "include/require with superglobal — RFI/LFI"
        category    = "LFI/RFI"
        severity    = "critical"
        confidence  = "high"

    strings:
        $inc = /(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase

    condition:
        filesize < 10MB and $inc
}

rule wpa_open_redirect_wp_redirect_super
{
    meta:
        description = "wp_redirect on $_GET/$_POST/$_REQUEST without wp_safe_redirect / wp_validate_redirect"
        category    = "OpenRedirect"
        severity    = "high"
        confidence  = "high"

    strings:
        $redir  = /wp_redirect\s*\([^)]{0,200}\$_(GET|POST|REQUEST)/ nocase
        $safe1  = "wp_safe_redirect"
        $safe2  = "wp_validate_redirect"

    condition:
        filesize < 10MB and $redir and not $safe1 and not $safe2
}

rule wpa_insecure_cookie_token_flags
{
    meta:
        description = "setcookie with token name but missing Secure/HttpOnly/SameSite flags"
        category    = "Cookie"
        severity    = "medium"
        confidence  = "medium"

    strings:
        $setcookie = /setcookie\s*\(\s*['"](access|id|oauth|jwt|token|session)[^'"]*['"]/ nocase
        $secure    = /['"]?secure['"]?\s*=>\s*true/ nocase
        $httponly  = /['"]?httponly['"]?\s*=>\s*true/ nocase
        $samesite  = /['"]?samesite['"]?\s*=>/ nocase

    condition:
        filesize < 10MB and $setcookie and not ( $secure and $httponly and $samesite )
}

rule wpa_privileged_call_with_input_no_capability
{
    meta:
        description = "update_*/delete_* call with superglobal input and no current_user_can in file"
        category    = "AccessControl"
        severity    = "high"
        confidence  = "medium"

    strings:
        $u1 = /update_(option|site_option|user_meta|post_meta)\s*\([^)]{0,200}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $u2 = /delete_(option|user_meta|post_meta)\s*\([^)]{0,200}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $u3 = /wp_(insert|update|delete)_(user|post)\s*\([^)]{0,200}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $cap = "current_user_can"

    condition:
        filesize < 10MB and any of ($u*) and not $cap
}

rule wpa_rest_debug_route_exposed
{
    meta:
        description = "register_rest_route registering a route named debug/test/dev/diag/probe"
        category    = "Exposure"
        severity    = "medium"
        confidence  = "medium"

    strings:
        $register = /register_rest_route\s*\(\s*['"][^'"]+['"]\s*,\s*['"]\/?(debug|test|dev|probe|diag)/ nocase

    condition:
        filesize < 10MB and $register
}

rule wpa_eval_or_obfuscation_heavy
{
    meta:
        description = "Direct eval/assert call OR two obfuscation primitives (heuristic)"
        category    = "Malware"
        severity    = "high"
        confidence  = "medium"

    strings:
        $eval = /\beval\s*\(/
        $ass  = /\bassert\s*\(/
        $b64  = /base64_decode\s*\(/
        $gzi  = /gzinflate\s*\(|gzuncompress\s*\(/
        $rot  = /str_rot13\s*\(/

    condition:
        filesize < 10MB and ( $eval or $ass or 2 of ($b64, $gzi, $rot) )
}

rule wpa_jwt_idtoken_manual_parse_no_verify
{
    meta:
        description = "Function get_resource_owner_from_id_token (or similar) manually splits/base64-decodes JWT without openssl_verify / JWT lib verify"
        category    = "OIDC/SigVerify"
        severity    = "high"
        confidence  = "medium"

    strings:
        $fn1            = /function\s+get_resource_owner_from_id_token\s*\(/ nocase
        $fn2            = /function\s+\w*(parse|decode)\w*id_token\w*\s*\(/ nocase
        $explode_jwt    = /explode\s*\(\s*['"]\.['"]\s*,\s*\$id_token/ nocase
        $explode_alt    = /list\s*\(\s*\$header\s*,\s*\$payload\s*,\s*\$signature\s*\)\s*=\s*explode\s*\(/ nocase
        $base64_payload = /base64_decode\s*\(\s*\$(payload|header)\b/ nocase
        $verify_ossl    = /openssl_verify\s*\(/ nocase
        $verify_lib     = /(JWT::decode|Firebase\\JWT\\JWT::decode|jwt[._]decode)/ nocase

    condition:
        filesize < 5MB and
        ( ($fn1 or $fn2) and ( $explode_jwt or $explode_alt or $base64_payload ) )
        and not $verify_ossl and not $verify_lib
}

rule wpa_sqli_select_with_superglobal
{
    meta:
        description = "SELECT query string containing $_GET/$_POST without ->prepare()"
        category    = "SQLi"
        severity    = "high"
        confidence  = "medium"

    strings:
        $sel  = /["']SELECT[^"']{0,300}\$_(GET|POST|REQUEST)/ nocase
        $prep = "->prepare("

    condition:
        filesize < 10MB and $sel and not $prep
}

rule wpa_ssrf_remote_fetch_user_url
{
    meta:
        description = "wp_remote_*/file_get_contents/curl_init given $_GET/$_POST/$_REQUEST/$_COOKIE"
        category    = "SSRF"
        severity    = "high"
        confidence  = "medium"

    strings:
        $r1 = /wp_remote_(get|post|request)\s*\([^)]{0,200}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $r2 = /file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $r3 = /curl_init\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $safe = /(wp_http_validate_url|FILTER_VALIDATE_URL)/

    condition:
        filesize < 10MB and any of ($r*) and not $safe
}

rule wpa_insecure_http_geoapi
{
    meta:
        description = "file_get_contents or wp_remote_* called with literal http:// (no TLS)"
        category    = "TLS"
        severity    = "medium"
        confidence  = "high"

    strings:
        $h1 = /file_get_contents\s*\(\s*['"]http:\/\//i
        $h2 = /wp_remote_(get|post|request)\s*\([^)]{0,200}['"]http:\/\//i

    condition:
        filesize < 10MB and ( $h1 or $h2 )
}

rule wpa_xss_unescaped_echo
{
    meta:
        description = "echo of $_GET/$_POST/$_REQUEST with no esc_* / sanitize_text_field / wp_kses"
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

rule wpa_weak_random_for_password_or_token
{
    meta:
        description = "mt_rand/rand/uniqid used near 'password'/'token' identifier (weak randomness)"
        category    = "WeakRandom"
        severity    = "medium"
        confidence  = "low"

    strings:
        $weak    = /\b(mt_rand|rand|uniqid)\s*\(/ nocase
        $context = /(password|token|secret|nonce)/ nocase
        $safe    = /(random_bytes|random_int|openssl_random_pseudo_bytes|wp_generate_password)/ nocase

    condition:
        filesize < 5MB and $weak and $context and not $safe
}

rule wpa_path_traversal_dotdot_with_input
{
    meta:
        description = "fopen/include/require with literal '..' segment and superglobal input"
        category    = "PathTraversal"
        severity    = "high"
        confidence  = "medium"

    strings:
        $trav = /(fopen|include|require)(_once)?\s*\([^)]{0,300}\.\.[\/\\][^)]{0,200}\$_(GET|POST|REQUEST|COOKIE)/ nocase

    condition:
        filesize < 10MB and $trav
}

rule wpa_arbitrary_file_delete
{
    meta:
        description = "unlink() with $_GET/$_POST/$_REQUEST and no realpath/sanitize_file_name"
        category    = "FileDeletion"
        severity    = "high"
        confidence  = "high"

    strings:
        $u1 = /unlink\s*\([^)]{0,200}\$_(GET|POST|REQUEST)/ nocase
        $safe1 = "sanitize_file_name"
        $safe2 = "realpath("

    condition:
        filesize < 10MB and $u1 and not $safe1 and not $safe2
}

rule wpa_auth_bypass_user_lookup_from_input
{
    meta:
        description = "User lookup by id/email/login from $_POST/$_GET feeds wp_set_auth_cookie / wp_set_current_user without cap/nonce/is_user_logged_in"
        category    = "AuthBypass"
        severity    = "critical"
        confidence  = "high"

    strings:
        $input_id    = /\$_(POST|GET|REQUEST)\s*\[\s*['"](id|user_id|userid)['"]\s*\]/ nocase
        $input_email = /\$_(POST|GET|REQUEST)\s*\[\s*['"](email|mail|user_email)['"]\s*\]/ nocase
        $input_login = /\$_(POST|GET|REQUEST)\s*\[\s*['"](login|username|user_login)['"]\s*\]/ nocase
        $lookup      = /get_user_by\s*\(\s*['"](id|email|login)['"]\s*,/ nocase
        $set_user    = /wp_set_current_user\s*\(/
        $set_cookie  = /wp_set_auth_cookie\s*\(/
        $cap_check   = "current_user_can"
        $nonce       = "wp_verify_nonce"
        $logged_in   = "is_user_logged_in"

    condition:
        filesize < 10MB and
        ( $input_id or $input_email or $input_login ) and
        $lookup and ( $set_user or $set_cookie ) and
        not $cap_check and not $nonce and not $logged_in
}

rule wpa_plaintext_password_in_db_write
{
    meta:
        description = "INSERT/UPDATE writes a $password variable without password_hash / wp_hash_password / password_verify in file"
        category    = "PasswordStorage"
        severity    = "high"
        confidence  = "medium"

    strings:
        $pwd_var    = /\$(password|pass|pwd)\s*=/ nocase
        $db_insert1 = /INSERT\s+INTO\s+[^'"]{0,80}password/ nocase
        $db_insert2 = /UPDATE\s+[^'"]{0,80}SET\s+[^'"]{0,80}password/ nocase
        $wpdb_write = /\$wpdb->(insert|update)\s*\(/
        $cmp_eq     = /\$password\s*===/
        $hash_safe1 = "password_hash"
        $hash_safe2 = "wp_hash_password"
        $hash_safe3 = "password_verify"

    condition:
        filesize < 10MB and $pwd_var and
        ( $db_insert1 or $db_insert2 or $wpdb_write or $cmp_eq ) and
        not any of ($hash_safe*)
}

rule wpa_header_location_user_input_open_redirect
{
    meta:
        description = "header('Location: ...') containing $_GET/$_POST/$_REQUEST"
        category    = "OpenRedirect"
        severity    = "high"
        confidence  = "high"

    strings:
        $hdr  = /header\s*\(\s*['"]Location\s*:[^'"]{0,300}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $safe = /(wp_safe_redirect|wp_validate_redirect|esc_url_raw\s*\()/

    condition:
        filesize < 10MB and $hdr and not $safe
}

rule wpa_hardcoded_third_party_token
{
    meta:
        description = "Hardcoded high-entropy third-party secret (AWS / Google / GitHub / Stripe / Slack / Bearer / PEM private key)"
        category    = "Secret"
        severity    = "critical"
        confidence  = "high"

    strings:
        /* AWS access key ID */
        $aws_id      = /\bAKIA[0-9A-Z]{16}\b/
        /* AWS secret access key – assigned to a variable / array key named ...secret_access_key / aws_secret */
        $aws_secret  = /['"]?(aws_secret|secret_access_key|AWS_SECRET_ACCESS_KEY)['"]?\s*(=>|:|=)\s*['"][A-Za-z0-9\/+=]{40}['"]/ nocase
        /* Google API key */
        $google_key  = /\bAIza[0-9A-Za-z\-_]{35}\b/
        /* GitHub personal access tokens */
        $gh_pat      = /\bgh[pousr]_[A-Za-z0-9]{36,}\b/
        /* Stripe live / restricted secret keys */
        $stripe      = /\b(sk|rk)_live_[0-9a-zA-Z]{24,}\b/
        /* Slack bot / user tokens */
        $slack       = /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/
        /* Generic Bearer token literal embedded in source */
        $bearer      = /['"]Authorization['"]\s*(=>|:)\s*['"]Bearer\s+[A-Za-z0-9._\-]{20,}['"]/ nocase
        /* PEM-encoded RSA / EC / OpenSSH private key block */
        $pem         = /-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PRIVATE)\s*(PRIVATE)?\s+KEY-----/
        /* JWT secret / signing key string assignment with 24+ char value */
        $jwt_secret  = /['"]?(JWT_SECRET|jwt_secret|signing_key|signingKey)['"]?\s*(=>|:|=)\s*['"][A-Za-z0-9_\-\.~+\/]{24,}['"]/ nocase
        /* Generic *_TOKEN / *_API_KEY constant with 20+ char value */
        $generic     = /\b(API_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|API_KEY|SECRET_KEY|PRIVATE_KEY)['"]?\s*[,:=]+\s*['"][A-Za-z0-9_\-\.~+\/]{20,}['"]/

    condition:
        filesize < 5MB and any of them
}

rule wpa_weak_crypto_primitive
{
    meta:
        description = "Use of weak crypto: MD5/SHA1 for password/token, DES/RC4 ciphers, ECB mode, hardcoded IV, base64 mistaken for encryption"
        category    = "WeakCrypto"
        severity    = "high"
        confidence  = "medium"

    strings:
        /* MD5 / SHA1 hashing a password / token / secret variable */
        $md5_pwd   = /\bmd5\s*\(\s*\$(password|pass|pwd|token|secret|api_key|client_secret)\b/ nocase
        $sha1_pwd  = /\bsha1\s*\(\s*\$(password|pass|pwd|token|secret|api_key|client_secret)\b/ nocase

        /* OpenSSL called with broken ciphers */
        $weak_cipher_des = /openssl_(encrypt|decrypt)\s*\(\s*[^,]+,\s*['"]des(-(ede|ede3))?['"]/ nocase
        $weak_cipher_rc4 = /openssl_(encrypt|decrypt)\s*\(\s*[^,]+,\s*['"]rc4['"]/ nocase
        $ecb_mode        = /['"](aes-(128|192|256)-ecb|des-ecb|bf-ecb)['"]/ nocase

        /* Mcrypt — removed in PHP 7.2 and never secure by default */
        $mcrypt          = /\bmcrypt_(encrypt|decrypt|create_iv|module_open)\s*\(/ nocase

        /* IV hardcoded as a literal next to openssl_encrypt — should be random */
        $hardcoded_iv    = /openssl_encrypt\s*\([^)]*,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*['"][^'"]{8,32}['"]/ nocase
        /* IV built from str_repeat / zero bytes / "0000..." */
        $zero_iv         = /\$iv\s*=\s*(str_repeat\s*\(\s*['"][\\\\x0]+['"]|['"]0{8,}['"])/ nocase

        /* base64 round-trip presented as "encryption" — same variable encoded then "decoded" with same key */
        $base64_encrypt  = /function\s+\w*encrypt\w*\s*\([^)]*\)\s*\{[^}]{0,200}\bbase64_encode\s*\(/ nocase

        /* Negative: presence of a sound primitive in the file */
        $safe_password   = /\b(password_hash|password_verify|wp_hash_password|sodium_crypto|hash_hmac)\s*\(/ nocase

    condition:
        filesize < 5MB and
        (
            $md5_pwd or $sha1_pwd or
            $weak_cipher_des or $weak_cipher_rc4 or $ecb_mode or
            $mcrypt or $hardcoded_iv or $zero_iv or $base64_encrypt
        )
        and not $safe_password
}

rule wpa_meta_refresh_with_input
{
    meta:
        description = "Meta-refresh tag built with $_GET/$_POST in URL"
        category    = "OpenRedirect"
        severity    = "medium"
        confidence  = "medium"

    strings:
        $meta = /<meta\s+http-equiv\s*=\s*['"]refresh['"][^>]*content\s*=\s*['"][^'"]{0,200}url\s*=\s*[^'"]*\$_(GET|POST|REQUEST)/ nocase

    condition:
        filesize < 10MB and $meta
}

rule OAuth_ProfileCompletion_EmailSelection
{
    meta:
        description = "Possible account selection from attacker-controlled email"

    strings:
        $post = "email_field"
        $user1 = "get_user_by("
        $user2 = "email_exists("
        $auth1 = "wp_set_auth_cookie("
        $auth2 = "wp_signon("
        $auth3 = "wp_set_current_user("

    condition:
        $post and
        1 of ($user*) and
        1 of ($auth*)
}

rule WeakOTPHash
{
    strings:
        $sha = "sha512"
        $otp = "otp"
        $cust = "customer_key"

    condition:
        all of them
}

rule SmallOTPRange
{
    strings:
        $rand1 = "wp_rand(1000,99999)"
        $rand2 = "wp_rand(1000, 99999)"
        $rand3 = "rand(1000,99999)"

    condition:
        any of them
}
