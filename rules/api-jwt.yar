/* =========================================================
   API / JWT vulnerability detection
   Per-file prefix: api_
   ========================================================= */

rule api_jwt_alg_none
{
    meta:
        description = "JWT 'alg:none' literal present near a JWT decode/verify call"
        category    = "API_JWT"
        severity    = "high"
        confidence  = "high"

    strings:
        $alg1 = "\"alg\":\"none\"" nocase
        $alg2 = "'alg' => 'none'" nocase
        $alg3 = /alg\s*[:=>]+\s*['"]none['"]/ nocase
        $jwt  = /(jwt[._]decode|jwt[._]verify|JWT::decode|jsonwebtoken|firebase\\jwt)/ nocase

    condition:
        filesize < 10MB and $jwt and any of ($alg*)
}

rule api_jwt_decode_with_verify_disabled
{
    meta:
        description = "JWT decoded with verification explicitly disabled"
        category    = "API_JWT"
        severity    = "high"
        confidence  = "high"

    strings:
        $decode   = /(JWT::decode|jwt[._]decode|jsonwebtoken\.verify)/ nocase
        $disable1 = /['"]verify['"]\s*=>\s*false/ nocase
        $disable2 = /verify\s*:\s*false/ nocase
        $disable3 = /['"]verify_signature['"]\s*=>\s*false/ nocase

    condition:
        filesize < 10MB and $decode and any of ($disable*)
}

rule api_rest_route_missing_permission_callback
{
    meta:
        description = "register_rest_route used without permission_callback / capability check"
        category    = "API_AUTH"
        severity    = "high"
        confidence  = "medium"

    strings:
        $route     = "register_rest_route(" nocase
        $perm_cb   = "permission_callback" nocase
        $is_logged = "is_user_logged_in" nocase
        $cap       = "current_user_can" nocase

    condition:
        filesize < 10MB and $route and
        not $perm_cb and not $is_logged and not $cap
}

rule api_trust_spoofable_forwarded_ip_header
{
    meta:
        description = "Reads a spoofable forwarded-IP header and uses it in a comparison"
        category    = "Microservices"
        severity    = "medium"
        confidence  = "medium"

    strings:
        $hdr1 = /\$_SERVER\s*\[\s*['"]HTTP_X_FORWARDED_FOR['"]\s*\]/ nocase
        $hdr2 = /\$_SERVER\s*\[\s*['"]HTTP_X_REAL_IP['"]\s*\]/ nocase
        $hdr3 = /\$_SERVER\s*\[\s*['"]HTTP_CLIENT_IP['"]\s*\]/ nocase
        $hdr4 = /req(uest)?\.headers\s*\[\s*['"]x-forwarded-for['"]\s*\]/ nocase
        $cmp  = /(==|===|if\s*\()/
        $validate = /FILTER_VALIDATE_IP|inet_pton|inet_aton/ nocase

    condition:
        filesize < 10MB and any of ($hdr*) and $cmp and not $validate
}
