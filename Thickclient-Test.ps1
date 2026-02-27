```
# ================================
# Thick Client VAPT Automation Script (Safe & Extended)
# ================================

$BasePath = (Get-Location).Path
$OutDir   = Join-Path $BasePath "VAPT_TEST"

# Create output folder
if (!(Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

Write-Host "Running safe VAPT checks..." -ForegroundColor Cyan

# ================================
# 1. Generate DLL/EXE List
# ================================
$dllList = Join-Path $OutDir "dll_list.txt"
Get-ChildItem -Recurse -Include *.dll, *.exe -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName |
    Out-File $dllList

Write-Host "Generated dll_list.txt" -ForegroundColor Green

# ================================
# 2. Signature Validation
# ================================
$SignatureReport = Join-Path $OutDir "SignatureReport.csv"
$files   = Get-Content $dllList
$results = @()

foreach ($file in $files) {
    if (Test-Path $file) {
        $sig = Get-AuthenticodeSignature -FilePath $file

        $results += [PSCustomObject]@{
            FileName  = (Split-Path $file -Leaf)
            FullPath  = $file
            Status    = $sig.Status
            Signer    = $sig.SignerCertificate.Subject
            Issuer    = $sig.SignerCertificate.Issuer
            NotBefore = $sig.SignerCertificate.NotBefore
            NotAfter  = $sig.SignerCertificate.NotAfter
        }
    }
    else {
        $results += [PSCustomObject]@{
            FileName  = (Split-Path $file -Leaf)
            FullPath  = $file
            Status    = "FileNotFound"
            Signer    = ""
            Issuer    = ""
            NotBefore = ""
            NotAfter  = ""
        }
    }
}

$results | Export-Csv $SignatureReport -NoTypeInformation
Write-Host "SignatureReport.csv created" -ForegroundColor Green

# ================================
# 3. Extract ALL Strings from Binaries (Raw)
# ================================
$StringsDir = Join-Path $OutDir "AllStrings"
if (!(Test-Path $StringsDir)) {
    New-Item -ItemType Directory -Path $StringsDir | Out-Null
}

Write-Host "Extracting strings from binaries..." -ForegroundColor Cyan

foreach ($file in $files) {
    if (Test-Path $file) {
        $outFile = Join-Path $StringsDir ("{0}.txt" -f ((Split-Path $file -Leaf) -replace '[^\w\.-]', '_'))
        try {
            strings.exe $file 2>$null | Out-File $outFile
        } catch {
            # If strings.exe not available, skip silently
        }
    }
}

Write-Host "String extraction complete." -ForegroundColor Green

# ================================
# 3b. Extract ONLY Interesting Strings (Filtered)
# ================================
$InterestingOut = Join-Path $OutDir "InterestingStrings.txt"

$patterns = @(
    "password",
    "passwd",
    "token",
    "secret",
    "key",
    "auth",
    "bearer",
    "api",
    "jdbc",
    "sql",
    "select ",
    "insert ",
    "update ",
    "delete ",
    "http://",
    "https://",
    "ftp://",
    "\\\\",              # UNC paths
    "C:\\",              # Windows paths
    "HKEY_",             # Registry keys
    "@",                 # Email addresses
    "\.config",
    "\.xml",
    "\.json",
    "\.ini",
    "\.dll",
    "\.exe"
)

Write-Host "Filtering interesting strings..." -ForegroundColor Cyan

$AllStrings = Get-ChildItem $StringsDir -Filter *.txt | ForEach-Object {
    Get-Content $_.FullName
}

$Interesting = foreach ($line in $AllStrings) {
    foreach ($pattern in $patterns) {
        if ($line -match $pattern) {
            $line
            break
        }
    }
}

$Interesting | Sort-Object -Unique | Out-File $InterestingOut

Write-Host "InterestingStrings.txt created with filtered results" -ForegroundColor Green

# ================================
# 4. Folder Permission Analysis
# ================================
$FolderACL = Join-Path $OutDir "FolderPermissions.txt"
Get-Acl $BasePath | Format-List | Out-File $FolderACL

Write-Host "Folder permission analysis complete" -ForegroundColor Green

# ================================
# 5. Automatic Registry Discovery (Auto Scan)
# ================================
$RegOut  = Join-Path $OutDir "RegistryPermissions.txt"
$AppName = Read-Host "Enter application name to search in registry (or press Enter to skip)"

if ($AppName -ne "") {

    Write-Host "Searching registry for keys matching: $AppName ..." -ForegroundColor Cyan

    $RegMatches = @()
    $RegPaths   = @(
        "HKLM:\Software",
        "HKLM:\Software\WOW6432Node",
        "HKCU:\Software"
    )

    foreach ($path in $RegPaths) {
        $RegMatches += Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*$AppName*" }
    }

    if ($RegMatches.Count -eq 0) {
        Write-Host "No registry keys found for '$AppName'." -ForegroundColor Yellow
    }
    else {
        Write-Host "Found $($RegMatches.Count) matching registry keys. Checking permissions..." -ForegroundColor Green

        $WeakReg = @()

        foreach ($key in $RegMatches) {
            try {
                $acl = Get-Acl $key.PsPath
                foreach ($ace in $acl.Access) {
                    if ($ace.FileSystemRights -match "Write" -and $ace.IdentityReference -match "Users|Everyone|Authenticated Users") {
                        $WeakReg += "[MEDIUM] Weak registry permission: $($key.Name)  -->  $($ace.IdentityReference)"
                        break
                    }
                }
            }
            catch {}
        }

        if ($WeakReg.Count -gt 0) {
            $WeakReg | Out-File $RegOut
            Write-Host "Weak registry permissions detected." -ForegroundColor Yellow
        } else {
            "No weak registry permissions detected." | Out-File $RegOut
            Write-Host "No weak registry permissions detected." -ForegroundColor Green
        }
    }
}
else {
    Write-Host "Registry search skipped." -ForegroundColor Yellow
}

# ================================
# 6. Weak Crypto Pattern Scan
# ================================
$CryptoOut = Join-Path $OutDir "WeakCrypto.txt"
Select-String -Path *.dll, *.exe -Pattern "MD5|SHA1|DES|RC4" -ErrorAction SilentlyContinue |
    Out-File $CryptoOut

Write-Host "Weak crypto scan complete" -ForegroundColor Green

# ================================
# 7. Config File Sensitive Data Scan
# ================================
$ConfigOut = Join-Path $OutDir "ConfigSensitiveData.txt"
Select-String -Path *.config -Pattern "password|key|token|secret" -ErrorAction SilentlyContinue |
    Out-File $ConfigOut

Write-Host "Config sensitive data scan complete" -ForegroundColor Green

# ================================
# 8. Log File Sensitive Data Scan
# ================================
$LogOut = Join-Path $OutDir "LogSensitiveData.txt"
if (Test-Path ".\Logs") {
    Select-String -Path ".\Logs\*" -Pattern "password|token|error|exception" -ErrorAction SilentlyContinue |
        Out-File $LogOut
}

Write-Host "Log scan complete" -ForegroundColor Green

# ================================
# 9. DLL Load Enumeration (Enhanced & Fixed)
# ================================

Write-Host "`nListing all running processes..." -ForegroundColor Cyan

$ProcessList = Get-Process | Sort-Object ProcessName

for ($i = 0; $i -lt $ProcessList.Count; $i++) {
    Write-Host "[$i] $($ProcessList[$i].ProcessName)  (PID: $($ProcessList[$i].Id))"
}

$choice = Read-Host "Enter the number OR PID of the process (or press Enter to skip)"
$choice = $choice.Trim()

if ($choice -eq "") {
    Write-Host "DLL enumeration skipped (no input)." -ForegroundColor Yellow
    $SelectedProc1 = $null
    return
}

function Resolve-ProcessSelection {
    param(
        [string]$InputValue,
        $List
    )

    # If numeric input
    if ($InputValue -match '^\d+$') {

        # If input is an index
        if ([int]$InputValue -lt $List.Count) {
            return $List[[int]$InputValue]
        }

        # Otherwise treat as PID
        try {
            return Get-Process -Id $InputValue -ErrorAction Stop
        }
        catch {
            Write-Host "Invalid or protected process. Cannot enumerate DLLs for PID $InputValue." -ForegroundColor Yellow
            return $null
        }
    }

    Write-Host "Invalid input. DLL enumeration skipped." -ForegroundColor Yellow
    return $null
}

$SelectedProc1 = Resolve-ProcessSelection -InputValue $choice -List $ProcessList

if (-not $SelectedProc1) {
    Write-Host "DLL enumeration skipped." -ForegroundColor Yellow
    return
}

Write-Host "Selected: $($SelectedProc1.ProcessName) (PID: $($SelectedProc1.Id))" -ForegroundColor Cyan

# Optional second process
$choice2 = Read-Host "Enter second PID to analyze or press Enter to continue"
$choice2 = $choice2.Trim()

$SelectedProc2 = $null
if ($choice2 -ne "") {
    $SelectedProc2 = Resolve-ProcessSelection -InputValue $choice2 -List $ProcessList
}

$DLLReport = Join-Path $OutDir "LoadedDLLs.txt"

# Enumerate DLLs for first process
try {
    $SelectedProc1.Modules | Select ModuleName, FileName | Out-File $DLLReport
    Write-Host "DLLs for first process saved." -ForegroundColor Green
}
catch {
    Write-Host "Access denied or protected process. Cannot enumerate DLLs for PID $($SelectedProc1.Id)." -ForegroundColor Yellow
}

# Enumerate DLLs for second process
if ($SelectedProc2) {
    try {
        $SelectedProc2.Modules | Select ModuleName, FileName | Out-File $DLLReport -Append
        Write-Host "DLLs for second process saved." -ForegroundColor Green
    }
    catch {
        Write-Host "Access denied or protected process. Cannot enumerate DLLs for PID $($SelectedProc2.Id)." -ForegroundColor Yellow
    }
}

# ================================
# 10. Writable Subdirectories Check
# ================================
$WritableDirsOut  = Join-Path $OutDir "WritableSubdirectories.txt"
$WritableFindings = @()

Get-ChildItem -Path $BasePath -Recurse -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $acl = Get-Acl $_.FullName
    foreach ($ace in $acl.Access) {
        if ($ace.FileSystemRights -match "Write" -and $ace.IdentityReference -match "Users|Everyone|Authenticated Users") {
            $WritableFindings += "Writable by $($ace.IdentityReference): $($_.FullName)"
            break
        }
    }
}

if ($WritableFindings.Count -gt 0) {
    $WritableFindings | Out-File $WritableDirsOut
    Write-Host "Writable subdirectories found (potential DLL hijack risk)." -ForegroundColor Yellow
} else {
    "No writable subdirectories for non-admin users detected." | Out-File $WritableDirsOut
    Write-Host "No writable subdirectories detected." -ForegroundColor Green
}

# ================================
# 11. Extended Config Secret Scan
# ================================
$ConfigExtendedOut = Join-Path $OutDir "ConfigExtendedSensitiveData.txt"

$ConfigFiles = Get-ChildItem -Recurse -Include *.config, *.xml, *.json, *.ini, *.properties, *.yml, *.yaml -ErrorAction SilentlyContinue

if ($ConfigFiles) {
    $ExtPatterns = "password","passwd","token","secret","key","auth","connectionstring","user id","uid","pwd"
    $matches     = @()

    foreach ($file in $ConfigFiles) {
        foreach ($pattern in $ExtPatterns) {
            $res = Select-String -Path $file.FullName -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
            if ($res) { $matches += $res }
        }
    }

    if ($matches.Count -gt 0) {
        $matches | Out-File $ConfigExtendedOut
        Write-Host "Extended config sensitive data found." -ForegroundColor Yellow
    } else {
        "No obvious secrets found in extended config files." | Out-File $ConfigExtendedOut
        Write-Host "No sensitive data in extended config files." -ForegroundColor Green
    }
} else {
    "No extended config files found." | Out-File $ConfigExtendedOut
}

# ================================
# 12. Insecure Protocol Usage Scan
# ================================
$InsecureProtoOut = Join-Path $OutDir "InsecureProtocols.txt"

$ProtoPatterns = "http://","ftp://","telnet://","ldap://"
$ProtoTargets  = Get-ChildItem -Recurse -Include *.dll, *.exe, *.config, *.xml, *.json, *.ini -ErrorAction SilentlyContinue

$ProtoHits = @()

foreach ($file in $ProtoTargets) {
    foreach ($pattern in $ProtoPatterns) {
        $res = Select-String -Path $file.FullName -Pattern $pattern -ErrorAction SilentlyContinue
        if ($res) { $ProtoHits += $res }
    }
}

if ($ProtoHits.Count -gt 0) {
    $ProtoHits | Out-File $InsecureProtoOut
    Write-Host "Insecure protocol references found." -ForegroundColor Yellow
} else {
    "No insecure protocol references detected." | Out-File $InsecureProtoOut
    Write-Host "No insecure protocol usage detected." -ForegroundColor Green
}

# ================================
# 13. Embedded Private Key Detection
# ================================
$PrivateKeyOut = Join-Path $OutDir "EmbeddedPrivateKeys.txt"

$KeyPatterns = "-----BEGIN PRIVATE KEY-----","-----BEGIN RSA PRIVATE KEY-----","-----BEGIN EC PRIVATE KEY-----"
$TextFiles   = Get-ChildItem -Recurse -Include *.pem, *.key, *.crt, *.cer, *.pfx, *.p12, *.config, *.xml, *.json, *.txt -ErrorAction SilentlyContinue

$KeyHits = @()

foreach ($file in $TextFiles) {
    foreach ($pattern in $KeyPatterns) {
        $res = Select-String -Path $file.FullName -Pattern $pattern -ErrorAction SilentlyContinue
        if ($res) { $KeyHits += $res }
    }
}

if ($KeyHits.Count -gt 0) {
    $KeyHits | Out-File $PrivateKeyOut
    Write-Host "Embedded private key material detected." -ForegroundColor Yellow
} else {
    "No embedded private key material detected." | Out-File $PrivateKeyOut
    Write-Host "No private keys detected in files." -ForegroundColor Green
}

# ================================
# 14. Connection String Detection
# ================================
$ConnStrOut = Join-Path $OutDir "ConnectionStrings.txt"

$ConnPatterns = "Server=","Data Source=","User ID=","Password=","Uid=","Pwd=","Integrated Security="
$ConnFiles    = Get-ChildItem -Recurse -Include *.config, *.xml, *.json, *.ini, *.properties, *.txt -ErrorAction SilentlyContinue

$ConnHits = @()

foreach ($file in $ConnFiles) {
    foreach ($pattern in $ConnPatterns) {
        $res = Select-String -Path $file.FullName -Pattern $pattern -ErrorAction SilentlyContinue
        if ($res) { $ConnHits += $res }
    }
}

if ($ConnHits.Count -gt 0) {
    $ConnHits | Out-File $ConnStrOut
    Write-Host "Connection strings detected." -ForegroundColor Yellow
} else {
    "No obvious connection strings detected." | Out-File $ConnStrOut
    Write-Host "No connection strings detected." -ForegroundColor Green
}

# ================================
# 15. Debug / Verbose Mode Detection
# ================================
$DebugOut = Join-Path $OutDir "DebugSettings.txt"

$DebugPatterns = "debug=true","trace=true","verbose=true","loglevel=debug","loglevel=trace"
$DebugFiles    = Get-ChildItem -Recurse -Include *.config, *.xml, *.json, *.ini, *.properties -ErrorAction SilentlyContinue

$DebugHits = @()

foreach ($file in $DebugFiles) {
    foreach ($pattern in $DebugPatterns) {
        $res = Select-String -Path $file.FullName -Pattern $pattern -ErrorAction SilentlyContinue
        if ($res) { $DebugHits += $res }
    }
}

if ($DebugHits.Count -gt 0) {
    $DebugHits | Out-File $DebugOut
    Write-Host "Debug/verbose settings detected (check if enabled in production)." -ForegroundColor Yellow
} else {
    "No obvious debug/verbose flags detected." | Out-File $DebugOut
    Write-Host "No debug flags detected." -ForegroundColor Green
}

# ================================
# 16. Temp/AppData Usage Scan (Safe & Fixed)
# ================================
$TempUsageOut = Join-Path $OutDir "TempUsage.txt"

$TempPatterns = @(
    "%TEMP%",
    "C:\\Temp",
    "AppData\\Local\\Temp",
    "AppData\\Roaming",
    "%APPDATA%",
    "%LOCALAPPDATA%"
)

$TempTargets = Get-ChildItem -Recurse -Include *.dll, *.exe, *.config, *.xml, *.json, *.ini, *.txt -ErrorAction SilentlyContinue

$TempHits = @()

foreach ($file in $TempTargets) {
    foreach ($pattern in $TempPatterns) {
        $res = Select-String -Path $file.FullName -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
        if ($res) { $TempHits += $res }
    }
}

if ($TempHits.Count -gt 0) {
    $TempHits | Out-File $TempUsageOut
    Write-Host "Temp/AppData usage references detected (review for sensitive data handling)." -ForegroundColor Yellow
} else {
    "No explicit Temp/AppData usage patterns detected." | Out-File $TempUsageOut
    Write-Host "No Temp/AppData usage patterns detected." -ForegroundColor Green
}

# ================================
# 17. Unquoted Service Path Detection
# ================================
$ServiceOut      = Join-Path $OutDir "UnquotedServicePaths.txt"
$ServiceFindings = @()

$services = Get-WmiObject win32_service

foreach ($svc in $services) {
    $path = $svc.PathName
    if ($path -and $path -match " " -and $path -notmatch '^".*"$') {
        $ServiceFindings += "[HIGH] Unquoted service path: $($svc.Name)  -->  $path"
    }
}

if ($ServiceFindings.Count -gt 0) {
    $ServiceFindings | Out-File $ServiceOut
    Write-Host "Unquoted service paths detected." -ForegroundColor Yellow
} else {
    "No unquoted service paths detected." | Out-File $ServiceOut
    Write-Host "No unquoted service paths detected." -ForegroundColor Green
}

# ================================
# 18. Weak File Permissions on Executables
# ================================
$WeakExePermOut  = Join-Path $OutDir "WeakExecutablePermissions.txt"
$WeakExeFindings = @()

$ExeTargets = Get-ChildItem -Recurse -Include *.exe, *.dll -ErrorAction SilentlyContinue

foreach ($file in $ExeTargets) {
    try {
        $acl = Get-Acl $file.FullName
        foreach ($ace in $acl.Access) {
            if ($ace.FileSystemRights -match "Write" -and $ace.IdentityReference -match "Users|Everyone|Authenticated Users") {
                $WeakExeFindings += "[HIGH] Writable executable: $($file.FullName) by $($ace.IdentityReference)"
                break
            }
        }
    } catch {}
}

if ($WeakExeFindings.Count -gt 0) {
    $WeakExeFindings | Out-File $WeakExePermOut
    Write-Host "Weak permissions on executables detected." -ForegroundColor Yellow
} else {
    "No weak permissions on executables detected." | Out-File $WeakExePermOut
    Write-Host "No weak executable permissions detected." -ForegroundColor Green
}

# ================================
# 19. Advanced Hardcoded Credential Patterns
# ================================
$AdvSecretsOut = Join-Path $OutDir "AdvancedSecrets.txt"

$AdvPatterns = @(
    "AKIA[0-9A-Z]{16}",                 # AWS Access Key
    "AIza[0-9A-Za-z\-_]{35}",           # Google API Key
    "EAACEdEose0cBA[0-9A-Za-z]+",       # Facebook token style
    "eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", # JWT
    "Basic [A-Za-z0-9+/=]{10,}",        # Basic auth header
    "secret_key",
    "client_secret",
    "access_token"
)

$AdvHits = @()

foreach ($file in $TextFiles) {
    foreach ($pattern in $AdvPatterns) {
        $res = Select-String -Path $file.FullName -Pattern $pattern -ErrorAction SilentlyContinue
        if ($res) { $AdvHits += $res }
    }
}

if ($AdvHits.Count -gt 0) {
    $AdvHits | Out-File $AdvSecretsOut
    Write-Host "Advanced hardcoded credential patterns detected." -ForegroundColor Yellow
} else {
    "No advanced hardcoded credential patterns detected." | Out-File $AdvSecretsOut
    Write-Host "No advanced hardcoded credentials detected." -ForegroundColor Green
}

# ================================
# 20. Local Database File Discovery & Basic Scan
# ================================
$DbOut      = Join-Path $OutDir "LocalDatabases.txt"
$DbFiles    = Get-ChildItem -Recurse -Include *.db, *.sqlite, *.mdb, *.sdf, *.mdf, *.ldf -ErrorAction SilentlyContinue
$DbFindings = @()

if ($DbFiles) {
    foreach ($file in $DbFiles) {
        $DbFindings += "[INFO] Local database file: $($file.FullName)"
        try {
            $res = Select-String -Path $file.FullName -Pattern "password|token|secret|key|user" -ErrorAction SilentlyContinue
            if ($res) {
                $DbFindings += "[MEDIUM] Potential sensitive data in DB file: $($file.FullName)"
            }
        } catch {}
    }

    $DbFindings | Out-File $DbOut
    Write-Host "Local database files scan complete." -ForegroundColor Yellow
} else {
    "No local database files detected." | Out-File $DbOut
    Write-Host "No local database files detected." -ForegroundColor Green
}

# ================================
# 21. Insecure .NET HTTP Client Usage
# ================================
$HttpBypassOut = Join-Path $OutDir "InsecureHttpBypass.txt"

$HttpBypassPatterns = @(
    "ServerCertificateValidationCallback",
    "ServerCertificateCustomValidationCallback",
    "ValidateServerCertificate",
    "TrustAllCertificates",
    "SslProtocols.None"
)

$CodeFiles = Get-ChildItem -Recurse -Include *.config, *.cs, *.vb, *.xml, *.json -ErrorAction SilentlyContinue
$HttpHits  = @()

foreach ($file in $CodeFiles) {
    foreach ($pattern in $HttpBypassPatterns) {
        $res = Select-String -Path $file.FullName -Pattern $pattern -ErrorAction SilentlyContinue
        if ($res) { $HttpHits += $res }
    }
}

if ($HttpHits.Count -gt 0) {
    $HttpHits | Out-File $HttpBypassOut
    Write-Host "Insecure HTTP/TLS validation patterns detected." -ForegroundColor Yellow
} else {
    "No insecure HTTP/TLS validation patterns detected." | Out-File $HttpBypassOut
    Write-Host "No insecure HTTP/TLS patterns detected." -ForegroundColor Green
}
# ================================
# 23. DLL Injection Exposure Analysis (Safe & Hardened)
# ================================
$DllExposureOut = Join-Path $OutDir "DllInjectionExposure.txt"
$ExposureFindings = @()

# If DLL enumeration never happened, skip safely
if (-not $DLLReport -or -not (Test-Path $DLLReport)) {
    "DLL enumeration not performed; skipping injection exposure analysis." | Out-File $DllExposureOut
    Write-Host "Skipping DLL injection exposure analysis (no DLL report)." -ForegroundColor Yellow
    return
}

$dlls = Get-Content $DLLReport

foreach ($dll in $dlls) {

    # Skip empty, null, or whitespace-only entries
    if ([string]::IsNullOrWhiteSpace($dll)) { continue }

    # Skip entries that do not look like valid paths
    if ($dll -notmatch "^[A-Za-z]:\\") { continue }

    # 1. DLL loaded from user-writable directory
    if ($dll -match "C:\\Users|AppData|Temp") {
        $ExposureFindings += "[HIGH] DLL loaded from user-writable directory: $dll"
    }

    # 2. Unsigned DLLs
    if (Test-Path $dll) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $dll
            if ($sig.Status -ne "Valid") {
                $ExposureFindings += "[MEDIUM] Unsigned or invalid DLL loaded: $dll"
            }
        } catch {}
    }

    # 3. Missing DLLs (LoadLibrary fallback risk)
    if (-not (Test-Path $dll)) {
        $ExposureFindings += "[HIGH] Missing DLL referenced by process (hijack risk): $dll"
        continue
    }

    # 4. Weak ACLs on DLL directory
    try {
        $dir = Split-Path $dll -Parent
        if ($dir -and (Test-Path $dir)) {
            $acl = Get-Acl $dir
            foreach ($ace in $acl.Access) {
                if ($ace.FileSystemRights -match "Write" -and $ace.IdentityReference -match "Users|Everyone|Authenticated Users") {
                    $ExposureFindings += "[HIGH] DLL directory writable by non-admins: $dir"
                    break
                }
            }
        }
    } catch {}
}

# 5. Environment variables affecting DLL search path
$envVars = @("PATH","PATHEXT","SYSTEMROOT","WINDIR")

foreach ($var in $envVars) {
    try {
        $envValue = $env[$var]
        if ($envValue -and ($envValue -match "Users|Temp|AppData")) {
            $ExposureFindings += "[LOW] Environment variable $var contains user-writable path: $envValue"
        }
    } catch {}
}

# Save results
if ($ExposureFindings.Count -gt 0) {
    $ExposureFindings | Out-File $DllExposureOut
    Write-Host "DLL Injection Exposure Analysis complete." -ForegroundColor Yellow
} else {
    "No DLL injection exposure indicators detected." | Out-File $DllExposureOut
    Write-Host "No DLL injection exposure indicators detected." -ForegroundColor Green
}
# ================================
# 24. Vulnerability Summary (Safe & Extended)
# ================================
$Summary  = Join-Path $OutDir "VulnerabilitySummary.txt"
$Findings = @()

Write-Host "`nGenerating vulnerability summary..." -ForegroundColor Cyan

function Safe-HasContent {
    param($path)

    if (Test-Path $path) {
        $content = Get-Content $path -ErrorAction SilentlyContinue
        return ($content.Count -gt 0)
    }
    return $false
}

# 1. Unsigned or invalid signatures
$SigData = Import-Csv $SignatureReport
foreach ($item in $SigData) {
    if ($item.Status -ne "Valid") {
        $Findings += "[HIGH] Invalid or unsigned binary: $($item.FileName) ($($item.Status))"
    }
}

# 2. Weak crypto
if (Safe-HasContent $CryptoOut) {
    $Findings += "[MEDIUM] Weak cryptographic algorithms detected (MD5/SHA1/DES/RC4)"
}

# 3. Sensitive strings
if (Safe-HasContent $InterestingOut) {
    $Findings += "[MEDIUM] Sensitive or interesting strings found in binaries"
}

# 4. Sensitive config data
if (Safe-HasContent $ConfigOut) {
    $Findings += "[MEDIUM] Sensitive data found in configuration files"
}

# 5. Extended config secrets
if (Safe-HasContent $ConfigExtendedOut) {
    $Findings += "[MEDIUM] Secrets or credentials found in extended config files"
}

# 6. Sensitive log data
if (Safe-HasContent $LogOut) {
    $Findings += "[LOW] Sensitive information found in log files"
}

# 7. Writable application directory
$acl = Get-Acl $BasePath
$acl.Access | ForEach-Object {
    if ($_.FileSystemRights -match "Write" -and $_.IdentityReference -match "Users|Everyone|Authenticated Users") {
        $Findings += "[HIGH] Application directory is writable by non-admin users"
    }
}

# 8. Writable subdirectories
if (Safe-HasContent $WritableDirsOut) {
    $Findings += "[HIGH] Writable subdirectories detected (DLL hijacking risk)"
}

# 9. Registry permissions
if (Safe-HasContent $RegOut) {
    $Findings += "[MEDIUM] Registry key permissions may allow tampering"
}

# 10. Insecure protocol usage
if (Safe-HasContent $InsecureProtoOut) {
    $Findings += "[MEDIUM] Insecure protocol references found (HTTP/FTP/Telnet/LDAP)"
}

# 11. Embedded private keys
if (Safe-HasContent $PrivateKeyOut) {
    $Findings += "[HIGH] Embedded private key material detected"
}

# 12. Connection strings
if (Safe-HasContent $ConnStrOut) {
    $Findings += "[MEDIUM] Hardcoded connection strings detected"
}

# 13. Debug/verbose mode
if (Safe-HasContent $DebugOut) {
    $Findings += "[LOW] Debug/verbose logging flags detected (review for production)"
}

# 14. Temp/AppData usage
if (Safe-HasContent $TempUsageOut) {
    $Findings += "[LOW] Temp/AppData usage detected (review for sensitive data exposure)"
}

# 15. DLL load anomalies
if ($DLLReport -and (Test-Path $DLLReport)) {
    $dlls = Get-Content $DLLReport
    foreach ($dll in $dlls) {
        if ($dll -match "C:\\Users|Temp|AppData") {
            $Findings += "[HIGH] DLL loaded from user-writable directory: $dll"
        }
    }
}

# 16. Unquoted service paths
if (Safe-HasContent $ServiceOut) {
    $Findings += "[HIGH] Unquoted service paths detected (privilege escalation risk)"
}

# 17. Weak executable permissions
if (Safe-HasContent $WeakExePermOut) {
    $Findings += "[HIGH] Executables or DLLs writable by non-admin users"
}

# 18. Advanced hardcoded credentials
if (Safe-HasContent $AdvSecretsOut) {
    $Findings += "[MEDIUM] Advanced hardcoded credential patterns detected (API keys, tokens, JWT, etc.)"
}

# 19. Local database files
if (Safe-HasContent $DbOut) {
    $Findings += "[MEDIUM] Local database files detected (review for sensitive data exposure)"
}

# 20. Insecure HTTP/TLS validation
if (Safe-HasContent $HttpBypassOut) {
    $Findings += "[MEDIUM] Insecure HTTP/TLS certificate validation patterns detected"
}
# 21. DLL injection exposure
if (Safe-HasContent $DllExposureOut) {
    $Findings += "[HIGH] DLL injection exposure indicators detected"
}
# Save summary
if ($Findings.Count -eq 0) {
    "No obvious misconfigurations detected." | Out-File $Summary
} else {
    $Findings | Out-File $Summary
}

Write-Host "VulnerabilitySummary.txt created" -ForegroundColor Green
```
