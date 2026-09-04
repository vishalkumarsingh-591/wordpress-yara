/* =========================================================
   SAML vulnerability detection
   Per-file prefix: saml_
   ========================================================= */

rule saml_explicit_signature_validation_disabled
{
    meta:
        description = "Code explicitly disables SAML signature validation"
        category    = "SAML/SigBypass"
        severity    = "critical"
        confidence  = "high"

    strings:
        $d1 = "skipSignatureValidation" nocase
        $d2 = "disableSignatureValidation" nocase
        $d3 = /validateSignature\s*[:=]\s*false/ nocase
        $d4 = /wantAssertionsSigned\s*[:=>]+\s*false/ nocase
        $d5 = /wantMessagesSigned\s*[:=>]+\s*false/ nocase
        $d6 = "allowUnsignedAssertions" nocase
        $d7 = /requireSignedAssertions\s*[:=]\s*false/ nocase

    condition:
        filesize < 5MB and any of ($d*)
}

rule saml_xml_signature_wrapping_indexed_access
{
    meta:
        description = "SAML XML parsing pulls Assertion/Signature by tag-name index — classic XSW pattern"
        category    = "SAML/XSW"
        severity    = "critical"
        confidence  = "medium"

    strings:
        $xml1 = /getElementsByTagName\s*\(\s*['"](ns\d*:)?Assertion['"]\s*\)/ nocase
        $xml2 = /getElementsByTagName\s*\(\s*['"](ns\d*:)?Signature['"]\s*\)/ nocase
        $bad1 = /assertions?\s*\[\s*0\s*\]/ nocase
        $bad2 = /signature\s*\[\s*0\s*\]/ nocase
        $bad3 = /selectSingleNode\s*\(\s*['"]\/\/Assertion['"]\s*\)/ nocase
        $bad4 = /->item\s*\(\s*0\s*\)/

    condition:
        filesize < 5MB and ( $xml1 or $xml2 ) and any of ($bad*)
}

rule saml_audience_validation_disabled
{
    meta:
        description = "SAML AudienceRestriction validation explicitly disabled"
        category    = "SAML/Audience"
        severity    = "high"
        confidence  = "high"

    strings:
        $d1 = "skipAudienceValidation" nocase
        $d2 = /validateAudience\s*[:=]\s*false/ nocase
        $d3 = "disableAudienceCheck" nocase
        $d4 = /strict\s*[:=]\s*false/ nocase

    condition:
        filesize < 5MB and any of ($d*)
}

rule saml_issuer_validation_disabled
{
    meta:
        description = "SAML Issuer validation explicitly disabled"
        category    = "SAML/Issuer"
        severity    = "high"
        confidence  = "high"

    strings:
        $d1 = "skipIssuerValidation" nocase
        $d2 = /validateIssuer\s*[:=]\s*false/ nocase
        $d3 = "disableIssuerCheck" nocase

    condition:
        filesize < 5MB and any of ($d*)
}

rule saml_response_parsed_without_verify_call
{
    meta:
        description = "SAMLResponse base64-decoded from request without any verifySignature/XMLSecurityDSig call"
        category    = "SAML/SigVerify"
        severity    = "high"
        confidence  = "low"

    strings:
        $samlresp = "SAMLResponse" nocase
        $parse    = /base64_decode\s*\(\s*\$_(POST|GET|REQUEST)\s*\[\s*['"]SAMLResponse['"]\s*\]/ nocase
        $verify1  = /(verifySignature|validateSignature|checkSignature|XMLSecurityDSig|->verify\s*\()/ nocase
        $verify2  = /xmlsec(_verify|tool)/ nocase

    condition:
        filesize < 5MB and $samlresp and $parse and
        not $verify1 and not $verify2
}

rule saml_certificate_validation_disabled
{
    meta:
        description = "Certificate verification disabled in SAML/HTTPS setup"
        category    = "SAML/CertValidation"
        severity    = "high"
        confidence  = "high"

    strings:
        $c1 = /validateCertificate\s*[:=]\s*false/ nocase
        $c2 = "disableCertificateValidation" nocase
        $c3 = "trustAllCertificates" nocase
        $c4 = /setTrustAll\s*\(\s*true/ nocase
        $c5 = /CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)/ nocase

    condition:
        filesize < 5MB and any of ($c*)
}

rule saml_relaystate_unvalidated_redirect
{
    meta:
        description = "RelayState read from request and used directly in redirect without wp_safe_redirect/allowlist"
        category    = "SAML/OpenRedirect"
        severity    = "medium"
        confidence  = "medium"

    strings:
        $read1 = /\$_(GET|POST|REQUEST)\s*\[\s*['"]RelayState['"]\s*\]/ nocase
        $read2 = /request\.getParameter\s*\(\s*['"]RelayState['"]/ nocase
        $redir = /(wp_redirect|header\s*\(\s*['"]Location:|sendRedirect|res\.redirect)/ nocase
        $safe  = /(wp_safe_redirect|wp_validate_redirect|allowed_redirect_hosts)/ nocase

    condition:
        filesize < 5MB and ( $read1 or $read2 ) and $redir and not $safe
}

rule WP_SAML_Certificate_Poisoning
{
    meta:
        description = "Detects potential SAML certificate poisoning before signature verification"
        author = "OpenAI"
        severity = "high"

    strings:
        $opt1 = "mo_saml_required_certificate"
        $opt2 = "saml_x509_certificate"

        $update1 = "update_option("
        $update2 = "add_option("
        $update3 = "update_site_option("

        $cert1 = "getX509Certificate("
        $cert2 = "getCertificate("
        $cert3 = "X509Certificate"
        $cert4 = "retrieveCertificate"

    condition:
        any of ($opt*) and
        1 of ($update*) and
        1 of ($cert*)
}

rule WP_Admin_Action_Without_Nonce
{
    meta:
        description = "Potential admin action protected only by capability check"

    strings:
        $cap1 = "current_user_can("
        $cap2 = "manage_options"

        $req1 = "$_REQUEST"
        $req2 = "$_GET"
        $req3 = "$_POST"

        $token = "mo_saml_mint_test_token"

    condition:
        $cap1 and
        $cap2 and
        $token and
        1 of ($req*)
}

rule PHP_Tautology_Redundant_Condition
{
    meta:
        description = "Detects a tautological/redundant PHP condition"
        author = "Security Assessment"
        severity = "Low"
        category = "Tautology"

    strings:
        $condition =
            /['"]username['"]\s*===\s*\$[A-Za-z_][A-Za-z0-9_]*\s*&&\s*username_exists\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\)\s*\)\s*\|\|\s*username_exists\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\)/

    condition:
        $condition
}