/* =========================================================
   OAuth / OIDC vulnerability detection
   Per-file prefix: oidc_
   ========================================================= */

rule oidc_authorize_url_missing_state
{
    meta:
        description = "Authorize URL built with response_type=code but no 'state' parameter anywhere"
        category    = "OAuth/CSRF"
        severity    = "high"
        confidence  = "medium"

    strings:
        $auth_url   = /authorize\?[^'"]{0,300}response_type=code[^'"]{0,300}client_id=/ nocase
        $build_url1 = /add_query_arg\s*\([^)]{0,500}response_type[^)]{0,500}client_id/ nocase
        $build_url2 = /http_build_query\s*\([^)]{0,500}response_type[^)]{0,500}client_id/ nocase
        $state      = "state=" nocase
        $state_arr  = /['"]state['"]\s*=>/ nocase

    condition:
        filesize < 5MB and
        ( $auth_url or $build_url1 or $build_url2 ) and
        not $state and not $state_arr
}

rule oidc_callback_no_state_read
{
    meta:
        description = "OAuth callback handler reads 'code' but never reads 'state' from request/session"
        category    = "OAuth/CSRF"
        severity    = "high"
        confidence  = "low"

    strings:
        $exchange    = /grant_type\s*=\s*['"]?authorization_code/ nocase
        $code_read   = /\$_(GET|POST|REQUEST)\s*\[\s*['"]code['"]\s*\]/ nocase
        $state_read  = /\$_(GET|POST|REQUEST|SESSION|COOKIE)\s*\[\s*['"]state['"]\s*\]/ nocase
        $state_trans = /get_transient\s*\(\s*[^)]*state/ nocase

    condition:
        filesize < 5MB and ( $exchange or $code_read ) and
        not $state_read and not $state_trans
}

rule oidc_login_user_lookup_by_email_only
{
    meta:
        description = "OAuth/OIDC handler logs user in by email lookup with no UID/sub matching"
        category    = "OAuth/AuthBypass"
        severity    = "high"
        confidence  = "medium"

    strings:
        $tok      = /\$(access_token|id_token|userinfo)\b/ nocase
        $by_email = /get_user_by\s*\(\s*['"]email['"]\s*,/ nocase
        $login    = /(wp_set_auth_cookie|wp_signon|wp_set_current_user)\s*\(/ nocase
        $by_sub   = /get_user_by\s*\(\s*['"](id|login)['"]\s*,/ nocase
        $meta_sub = /get_user_meta\s*\([^)]*['"](oauth_sub|oidc_sub|external_id)['"]/ nocase

    condition:
        filesize < 10MB and $tok and $by_email and $login and
        not $by_sub and not $meta_sub
}

rule oidc_token_value_leaked_to_log_or_url
{
    meta:
        description = "Token variable concatenated into URL/log/redirect"
        category    = "OAuth/Leakage"
        severity    = "high"
        confidence  = "medium"

    strings:
        $tok_qs    = /[?&](access_token|id_token|refresh_token)=\$/ nocase
        $sink_log  = /(error_log|var_dump|print_r|var_export)\s*\(\s*\$(access_token|id_token|refresh_token)/ nocase
        $sink_echo = /echo\s+\$(access_token|id_token|refresh_token)\b/ nocase

    condition:
        filesize < 5MB and ( $tok_qs or $sink_log or $sink_echo )
}

rule oidc_authorize_request_missing_pkce
{
    meta:
        description = "Authorize URL with response_type=code but no code_challenge (PKCE)"
        category    = "OAuth/PKCE"
        severity    = "medium"
        confidence  = "low"

    strings:
        $auth_url      = /authorize\?[^'"]{0,300}response_type=code/ nocase
        $challenge     = "code_challenge=" nocase
        $challenge_arr = /['"]code_challenge['"]\s*=>/ nocase

    condition:
        filesize < 5MB and $auth_url and not $challenge and not $challenge_arr
}

rule oidc_redirect_uri_from_user_input
{
    meta:
        description = "redirect_uri OAuth parameter set directly from $_GET/$_POST/$_REQUEST"
        category    = "OAuth/OpenRedirect"
        severity    = "high"
        confidence  = "high"

    strings:
        $r1 = /['"]redirect_uri['"]\s*(=>|:)\s*\$_(GET|POST|REQUEST)/ nocase
        $r2 = /redirect_uri\s*=\s*\$_(GET|POST|REQUEST)\s*\[/ nocase

    condition:
        filesize < 5MB and any of ($r*)
}

rule oidc_client_secret_hardcoded
{
    meta:
        description = "OAuth client_secret hardcoded as a literal in source"
        category    = "OAuth/Secret"
        severity    = "high"
        confidence  = "medium"

    strings:
        $secret_assign = /['"]client_secret['"]\s*(=>|:)\s*['"][A-Za-z0-9_\-\.~]{20,}['"]/ nocase
        $secret_var    = /\$client_secret\s*=\s*['"][A-Za-z0-9_\-\.~]{20,}['"]/ nocase

    condition:
        filesize < 5MB and ( $secret_assign or $secret_var )
}

rule oidc_implicit_flow_response_type_token
{
    meta:
        description = "OAuth implicit flow (response_type=token) — deprecated"
        category    = "OAuth/Flow"
        severity    = "medium"
        confidence  = "high"

    strings:
        $impl = /response_type=(token|id_token\s+token|token\s+id_token)/ nocase

    condition:
        filesize < 5MB and $impl
}

rule oidc_id_token_no_signature_verification
{
    meta:
        description = "ID token split & base64-decoded manually without openssl_verify / JWT lib verify"
        category    = "OIDC/SigVerify"
        severity    = "critical"
        confidence  = "medium"

    strings:
        $explode_jwt = /explode\s*\(\s*['"]\.['"]\s*,\s*\$(id_token|jwt|token)\b/ nocase
        $b64_decode  = /base64_decode\s*\(\s*\$(parts|header|payload|segments)/ nocase
        $verify_ossl = /openssl_verify\s*\(/ nocase
        $verify_lib  = /(JWT::decode|Firebase\\JWT\\JWT::decode|jwt[._]decode)/ nocase
        $verify_jwks = /(jwks|JwkSet|getPublicKey)/ nocase

    condition:
        filesize < 5MB and ( $explode_jwt or $b64_decode ) and
        not $verify_ossl and not $verify_lib and not $verify_jwks
}

rule oidc_token_endpoint_over_http
{
    meta:
        description = "OAuth/OIDC token / userinfo / introspect endpoint URL using plain HTTP"
        category    = "OAuth/Transport"
        severity    = "critical"
        confidence  = "high"

    strings:
        $http_tok = /http:\/\/[^\s'"<>]+\/(token|userinfo|introspect)/ nocase

    condition:
        filesize < 5MB and $http_tok
}
