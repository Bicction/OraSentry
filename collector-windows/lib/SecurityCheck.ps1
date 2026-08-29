Set-StrictMode -Version 2.0

function Export-WindowsAcl {
    param([string]$Path, [string]$OutputFile)
    if (-not (Test-Path -LiteralPath $Path)) { throw "路径不存在: $Path" }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $rows = foreach ($access in $acl.Access) {
        ,@($Path, $acl.Owner, $access.IdentityReference, $access.FileSystemRights, $access.AccessControlType, $access.IsInherited)
    }
    Write-PipeTable $OutputFile @("PATH","OWNER","IDENTITY","RIGHTS","TYPE","INHERITED") $rows
}

function Collect-WindowsSecurity {
    param([Parameter(Mandatory=$true)]$Context, [Parameter(Mandatory=$true)][hashtable]$Config)
    $secDir = Join-Path $Context.RawDir "security"
    New-Item -ItemType Directory -Force -Path $secDir | Out-Null
    Write-CollectorLog -Context $Context -Message "开始采集 Oracle 与 Windows 安全数据"

    $queries = [ordered]@{
        "password_policy.txt" = "SELECT profile, resource_name, resource_type, limit FROM dba_profiles WHERE resource_name IN ('PASSWORD_LIFE_TIME','PASSWORD_REUSE_TIME','PASSWORD_REUSE_MAX','PASSWORD_LOCK_TIME','PASSWORD_GRACE_TIME','PASSWORD_VERIFY_FUNCTION','FAILED_LOGIN_ATTEMPTS') ORDER BY profile, resource_name;"
        "profiles.txt" = "SELECT DISTINCT profile FROM dba_profiles ORDER BY profile;"
        "db_users.txt" = "SELECT username, account_status, expiry_date, lock_date, default_tablespace, profile, created, CAST(NULL AS VARCHAR2(64)) last_login, CAST(NULL AS VARCHAR2(30)) authentication_type, CAST(NULL AS VARCHAR2(30)) password_versions, CAST('N' AS VARCHAR2(1)) oracle_maintained, CAST('NO' AS VARCHAR2(3)) common FROM dba_users ORDER BY username;"
        "dba_role_users.txt" = "SELECT grantee, granted_role FROM dba_role_privs WHERE granted_role='DBA' ORDER BY grantee;"
        "sys_privs.txt" = "WITH business_users AS (SELECT username FROM dba_users WHERE username NOT IN ('SYS','SYSTEM','DBSNMP','APPQOSSYS','MDSYS','OUTLN','SYSMAN','XDB')), principals AS (SELECT username principal FROM business_users UNION SELECT granted_role FROM dba_role_privs WHERE grantee IN (SELECT username FROM business_users) AND granted_role NOT IN ('CONNECT','RESOURCE','DBA')) SELECT DISTINCT p.grantee,p.privilege,p.admin_option FROM dba_sys_privs p JOIN principals x ON x.principal=p.grantee ORDER BY p.grantee,p.privilege;"
        "audit_settings.txt" = "SELECT name, value FROM v`$parameter WHERE name LIKE '%audit%';"
        "traditional_audit_options.txt" = "SELECT user_name, proxy_name, audit_option, success, failure FROM dba_stmt_audit_opts ORDER BY user_name, audit_option;"
        "public_risky_grants.txt" = "SELECT owner, table_name, privilege, grantable FROM dba_tab_privs WHERE grantee='PUBLIC' AND privilege IN ('EXECUTE','READ','WRITE') AND table_name IN ('UTL_FILE','UTL_HTTP','UTL_TCP','UTL_SMTP','DBMS_SCHEDULER','DBMS_JOB','DBMS_LOB','DBMS_SQL','DBMS_RANDOM') ORDER BY owner,table_name,privilege;"
        "security_parameters.txt" = "SELECT name, value, isdefault FROM v`$parameter WHERE name IN ('remote_login_passwordfile','remote_os_authent','os_authent_prefix','sec_case_sensitive_logon','sql92_security','_allow_insert_with_update_check') ORDER BY name;"
    }
    foreach ($entry in $queries.GetEnumerator()) { Invoke-RegisteredSql $Context $secDir $entry.Key $entry.Value }

    if ([int](([regex]::Match((Invoke-OraScalar $Context "SELECT version FROM v`$instance;"), '^\d+')).Value) -ge 12) {
        Invoke-RegisteredSql $Context $secDir "unified_audit_policies.txt" "SELECT * FROM audit_unified_enabled_policies;" -Optional
    } else {
        Skip-SqlCollection $Context $secDir "unified_audit_policies.txt" "POLICY_NAME" "当前版本不支持统一审计视图"
    }

    Invoke-CollectionAction $Context "oracle_home_acl.txt" {
        Export-WindowsAcl $Context.OracleHome (Join-Path $secDir "oracle_home_acl.txt")
    }
    Invoke-CollectionAction $Context "oracle_bin_acl.txt" {
        Export-WindowsAcl (Join-Path $Context.OracleHome "bin\oracle.exe") (Join-Path $secDir "oracle_bin_acl.txt")
    }
    Invoke-CollectionAction $Context "oracle_network_acl.txt" {
        Export-WindowsAcl (Join-Path $Context.OracleHome "network\admin") (Join-Path $secDir "oracle_network_acl.txt")
    }
    Invoke-CollectionAction $Context "oracle_password_file_acl.txt" {
        $passwordFile = Join-Path $Context.OracleHome ("database\PWD{0}.ora" -f $Context.OracleSid)
        Export-WindowsAcl $passwordFile (Join-Path $secDir "oracle_password_file_acl.txt")
    } -Optional

    Invoke-CollectionAction $Context "listener_status.txt" {
        $lsnrctl = Join-Path $Context.OracleHome "bin\lsnrctl.exe"
        if (-not (Test-Path -LiteralPath $lsnrctl)) { throw "lsnrctl.exe不存在" }
        $output = & $lsnrctl status 2>&1 | Out-String
        Write-CollectorText (Join-Path $secDir "listener_status.txt") $output
        if ($LASTEXITCODE -ne 0) { throw "lsnrctl status失败(rc=$LASTEXITCODE)" }
    }
    Invoke-CollectionAction $Context "listener_services.txt" {
        $lsnrctl = Join-Path $Context.OracleHome "bin\lsnrctl.exe"
        $output = & $lsnrctl services 2>&1 | Out-String
        Write-CollectorText (Join-Path $secDir "listener_services.txt") $output
        if ($LASTEXITCODE -ne 0) { throw "lsnrctl services失败(rc=$LASTEXITCODE)" }
    } -Optional

    foreach ($name in @("listener.ora","sqlnet.ora","tnsnames.ora")) {
        $targetName = $name.Replace('.', '_') + ".txt"
        $action = {
            $source = Join-Path $Context.OracleHome ("network\admin\$name")
            if (-not (Test-Path -LiteralPath $source)) { throw "$name 不存在" }
            Write-CollectorText (Join-Path $secDir $targetName) ([System.IO.File]::ReadAllText($source))
        }.GetNewClosure()
        Invoke-CollectionAction -Context $Context -Item $targetName -Action $action -Optional
    }

    Write-CollectorLog -Context $Context -Message "Oracle 与 Windows 安全数据采集完成"
}
