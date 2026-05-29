/* =========================================================
   WordPress malware / shell / backdoor threats
   Per-file prefix: wpt_
   ========================================================= */

rule wpt_eval_base64_pattern
{
    meta:
        description = "Classic eval(base64_decode(...)) malware pattern"
        category    = "Malware"
        severity    = "critical"
        confidence  = "high"

    strings:
        $a = "eval(base64_decode(" nocase
        $b = /eval\s*\(\s*base64_decode\s*\(/ nocase

    condition:
        filesize < 10MB and ( $a or $b )
}

rule wpt_eval_assert_on_superglobal
{
    meta:
        description = "eval/assert called with value taken straight from $_POST/$_GET/$_REQUEST"
        category    = "Backdoor"
        severity    = "critical"
        confidence  = "high"

    strings:
        $b1 = /\beval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
        $b2 = /\bassert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase

    condition:
        filesize < 10MB and any of ($b*)
}

rule wpt_theme_creates_hidden_admin_user
{
    meta:
        description = "Theme/plugin creates user with administrator role and adds to blog — backdoor"
        category    = "Backdoor"
        severity    = "critical"
        confidence  = "high"

    strings:
        $a = "wp_create_user(" nocase
        $b = "user_pass" nocase
        $c = "add_user_to_blog(" nocase
        $d = /['"]administrator['"]/

    condition:
        filesize < 10MB and all of them
}

rule wpt_wp_config_db_credentials_present
{
    meta:
        description = "wp-config.php with DB_NAME, DB_USER, DB_PASSWORD, DB_HOST literals — flag if committed to VCS"
        category    = "Config/Secret"
        severity    = "medium"
        confidence  = "high"

    strings:
        $name = /define\s*\(\s*['"]DB_NAME['"]\s*,\s*['"][^'"]+['"]\s*\)/
        $user = /define\s*\(\s*['"]DB_USER['"]\s*,\s*['"][^'"]+['"]\s*\)/
        $pass = /define\s*\(\s*['"]DB_PASSWORD['"]\s*,\s*['"][^'"]+['"]\s*\)/
        $host = /define\s*\(\s*['"]DB_HOST['"]\s*,\s*['"][^'"]+['"]\s*\)/

    condition:
        filesize < 2MB and all of them
}

rule wpt_mysql_query_with_php_variable
{
    meta:
        description = "mysql_query / mysqli_query containing a PHP variable interpolation — likely concat SQL"
        category    = "SQLi"
        severity    = "high"
        confidence  = "medium"

    strings:
        $mysql_var  = /mysql_query\s*\([^)]*\$\w+/ nocase
        $mysqli_var = /mysqli_query\s*\([^)]*\$\w+/ nocase

    condition:
        filesize < 10MB and ( $mysql_var or $mysqli_var )
}

rule wpt_wpdb_unprepared_concat_variable
{
    meta:
        description = "$wpdb->query / get_results passed a string literal that contains a PHP variable (no prepare)"
        category    = "SQLi"
        severity    = "high"
        confidence  = "medium"

    strings:
        $q1 = /\$wpdb->query\s*\(\s*['"][^'"]*\$\w+[^'"]*['"]\s*\)/
        $q2 = /\$wpdb->get_results\s*\(\s*['"][^'"]*\$\w+[^'"]*['"]\s*\)/
        $q3 = /\$wpdb->get_row\s*\(\s*['"][^'"]*\$\w+[^'"]*['"]\s*\)/

    condition:
        filesize < 10MB and any of ($q*)
}

rule wpt_php_lfi_via_superglobal
{
    meta:
        description = "include/require taking $_GET/$_POST/$_REQUEST directly"
        category    = "LFI/RFI"
        severity    = "critical"
        confidence  = "high"

    strings:
        $i1 = /\binclude(_once)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $i2 = /\brequire(_once)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase

    condition:
        filesize < 10MB and any of ($i*)
}

rule wpt_js_eval_with_dynamic_arg
{
    meta:
        description = "JavaScript eval() called with a variable / dynamic argument (not a string literal)"
        category    = "JS/Eval"
        severity    = "high"
        confidence  = "low"

    strings:
        $eval_var = /\beval\s*\(\s*[A-Za-z_]\w*/

    condition:
        filesize < 5MB and $eval_var
}
