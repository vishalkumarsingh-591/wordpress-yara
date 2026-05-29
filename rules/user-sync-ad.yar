/* =========================================================
   Active Directory / LDAP / SCIM user-sync rules
   Per-file prefix: ad_
   ========================================================= */

rule ad_ldap_filter_built_with_variable
{
    meta:
        description = "LDAP filter constructed with a PHP variable for uid/cn/mail/userPrincipalName"
        category    = "AD/LDAPi"
        severity    = "high"
        confidence  = "medium"

    strings:
        $ldap   = /\bldap_(search|bind|list|read|modify)\s*\(/ nocase
        $filter = /\(\s*(uid|cn|mail|sAMAccountName|userPrincipalName)\s*=\s*['"]?\$\w+/ nocase
        $escape = /ldap_escape\s*\(/ nocase

    condition:
        filesize < 5MB and $ldap and $filter and not $escape
}

rule ad_ldap_filter_from_request_input
{
    meta:
        description = "LDAP filter or ldap_search built directly from $_GET/$_POST/$_REQUEST"
        category    = "AD/LDAPi"
        severity    = "high"
        confidence  = "high"

    strings:
        $f1 = /\(\s*(uid|cn|mail|sAMAccountName)\s*=\s*\$_(GET|POST|REQUEST)/ nocase
        $f2 = /ldap_search\s*\([^)]*\$_(GET|POST|REQUEST)/ nocase
        $escape = /ldap_escape\s*\(/ nocase

    condition:
        filesize < 5MB and any of ($f*) and not $escape
}

rule ad_admin_role_assigned_from_group_attribute
{
    meta:
        description = "Group/memberOf attribute mapped to administrator role assignment"
        category    = "AD/PrivEsc"
        severity    = "critical"
        confidence  = "medium"

    strings:
        $group   = /(memberOf|groupMembership)/ nocase
        $admin   = /['"](administrator|admin_role|ROLE_ADMIN)['"]/ nocase
        $assign  = /(set_role|add_role|wp_update_user|wp_insert_user|assign_role)\s*\(/ nocase

    condition:
        filesize < 5MB and $group and $admin and $assign
}

rule ad_user_created_from_request_email_or_username
{
    meta:
        description = "User created with email/username taken from $_POST/$_GET/$_REQUEST without sanitize_*"
        category    = "AD/UserSync"
        severity    = "high"
        confidence  = "medium"

    strings:
        $source   = /\$_(POST|GET|REQUEST)\s*\[\s*['"](email|mail|username|user_login)['"]\s*\]/ nocase
        $create   = /\b(wp_create_user|wp_insert_user|add_user)\s*\(/ nocase
        $sanitize = /\b(sanitize_email|sanitize_user|is_email)\s*\(/ nocase

    condition:
        filesize < 5MB and $source and $create and not $sanitize
}

rule ad_password_from_ldap_stored_in_db
{
    meta:
        description = "Password value pulled from LDAP write path stored via update_user_meta / INSERT"
        category    = "AD/PasswordExposure"
        severity    = "critical"
        confidence  = "medium"

    strings:
        $ldap   = /\bldap_(search|bind|get_entries|first_entry|read)\s*\(/ nocase
        $pwd    = /\$(password|pwd|userPassword|pwdLastSet)\b/ nocase
        $store1 = /update_user_meta\s*\(/ nocase
        $store2 = /INSERT\s+INTO/ nocase
        $hash   = /(password_hash|wp_hash_password)\s*\(/ nocase

    condition:
        filesize < 5MB and $ldap and $pwd and ( $store1 or $store2 ) and not $hash
}

rule ad_ldap_uri_plaintext_no_starttls
{
    meta:
        description = "ldap:// URI used without ldap_start_tls or ldaps:// alternative"
        category    = "AD/Transport"
        severity    = "high"
        confidence  = "medium"

    strings:
        $ldap_uri    = /ldap:\/\//
        $ldaps_uri   = /ldaps:\/\//
        $start_tls   = /ldap_start_tls\s*\(/ nocase

    condition:
        filesize < 2MB and $ldap_uri and not $ldaps_uri and not $start_tls
}

rule ad_scim_endpoint_input_to_user_creation
{
    meta:
        description = "SCIM endpoint feeds $_POST/php://input directly into wp_create_user / wp_insert_user"
        category    = "SCIM/UserSync"
        severity    = "high"
        confidence  = "medium"

    strings:
        $scim   = /['"]\/scim(\/v2)?\/Users['"]/ nocase
        $input1 = /\$_(POST|REQUEST)\s*\[/
        $input2 = /php:\/\/input/
        $create = /\b(wp_create_user|wp_insert_user|add_user)\s*\(/ nocase
        $auth   = /(current_user_can|is_user_logged_in|Authorization|Bearer )/ nocase

    condition:
        filesize < 5MB and $scim and ( $input1 or $input2 ) and $create and not $auth
}

rule ad_group_to_role_no_allowlist_check
{
    meta:
        description = "memberOf used to set/add role without any 'allowed_groups'-style allowlist"
        category    = "AD/PrivEsc"
        severity    = "high"
        confidence  = "low"

    strings:
        $group    = /(memberOf|groups)/ nocase
        $assign   = /(set_role|add_role|assign_role)\s*\(/ nocase
        $allowlist = /(allowed_groups|group_allowlist|whitelist|valid_groups)/ nocase

    condition:
        filesize < 5MB and $group and $assign and not $allowlist
}
