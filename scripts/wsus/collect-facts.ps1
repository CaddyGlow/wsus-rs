<#
.SYNOPSIS
  Collect the machine facts a WSUS applicability evaluator needs and write
  them as a snapshot (facts.json) that wsus-protocol's RecordedFacts loads.

.DESCRIPTION
  Reads queries.json (written by scripts/wsus/applicability-queries.py), answers
  every query on THIS machine with the same facts the Windows Update Agent
  reads, and writes facts.json in the snapshot format documented in
  crates/wsus-protocol/src/applicability/recorded.rs. Read-only: it changes
  nothing on the machine.

  PowerShell 5.1, no external modules. Run it elevated, ideally as SYSTEM (the
  Windows Update Agent is a SYSTEM service; per-user MSI products and the
  profile folders differ for other accounts), in the NATIVE (64-bit)
  PowerShell on a 64-bit OS, for example:

      psexec -s -i powershell.exe -ExecutionPolicy Bypass -File collect-facts.ps1 `
          -Queries C:\work\queries.json -Out C:\work\facts.json

  Answers are never guessed: a query that cannot be answered is written with
  state "unavailable" and a reason, which the evaluator turns into Unknown.

.PARAMETER Queries
  Path of queries.json. Default .\queries.json

.PARAMETER Out
  Path of the snapshot to write. Default .\facts.json

.PARAMETER Limit
  Answer only the first N queries (a smoke test). Default 0 (all).

.PARAMETER AllowWow64
  Continue in a 32-bit process on a 64-bit OS. File facts are then subject to
  file system redirection and are wrong for System32; do not use for a
  differential run.
#>
[CmdletBinding()]
param(
    [string]$Queries = '.\queries.json',
    [string]$Out = '.\facts.json',
    [int]$Limit = 0,
    [switch]$AllowWow64
)

$ErrorActionPreference = 'Stop'

if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and -not $AllowWow64) {
    [Console]::Error.WriteLine('This is a 32-bit PowerShell on a 64-bit OS: file system redirection would change the answers. Run the 64-bit powershell.exe (or pass -AllowWow64).')
    exit 2
}

Add-Type -AssemblyName System.Web.Extensions

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class WuaFacts
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct OSVERSIONINFOEX
    {
        public int dwOSVersionInfoSize;
        public int dwMajorVersion;
        public int dwMinorVersion;
        public int dwBuildNumber;
        public int dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;
        public ushort wServicePackMajor;
        public ushort wServicePackMinor;
        public ushort wSuiteMask;
        public byte wProductType;
        public byte wReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    }

    [DllImport("ntdll.dll")]
    static extern int RtlGetVersion(ref OSVERSIONINFOEX v);

    [DllImport("kernel32.dll")]
    static extern void GetNativeSystemInfo(out SYSTEM_INFO info);

    [DllImport("kernel32.dll")]
    static extern ushort GetSystemDefaultUILanguage();

    [DllImport("user32.dll")]
    static extern int GetSystemMetrics(int index);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    static extern int SHGetFolderPathW(IntPtr hwnd, int csidl, IntPtr token, uint flags, StringBuilder path);

    [DllImport("slc.dll", CharSet = CharSet.Unicode)]
    static extern int SLGetWindowsInformationDWORD(string name, out uint value);

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    public delegate bool UiLangProc([MarshalAs(UnmanagedType.LPWStr)] string lang, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern bool EnumUILanguagesW(UiLangProc proc, uint flags, IntPtr lParam);

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    static extern int MsiEnumProductsExW(string product, string sid, int context, uint index,
        StringBuilder installedProduct, out int installedContext, IntPtr sidOut, IntPtr sidLen);

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    static extern int MsiQueryProductStateW(string product);

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    static extern int MsiGetProductInfoExW(string product, string sid, int context, string prop,
        StringBuilder value, ref int len);

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    static extern int MsiQueryFeatureStateW(string product, string feature);

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    static extern int MsiQueryComponentStateW(string product, string sid, int context, string component, out int state);

    public static OSVERSIONINFOEX GetVersion()
    {
        OSVERSIONINFOEX v = new OSVERSIONINFOEX();
        v.dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEX));
        int st = RtlGetVersion(ref v);
        if (st != 0) { throw new Exception("RtlGetVersion returned " + st); }
        return v;
    }

    public static int NativeArchitecture()
    {
        SYSTEM_INFO si;
        GetNativeSystemInfo(out si);
        return si.wProcessorArchitecture;
    }

    public static int UiLanguageLcid() { return GetSystemDefaultUILanguage(); }

    public static int Metric(int index) { return GetSystemMetrics(index); }

    // Returns null when SHGetFolderPath fails; hr is set either way.
    public static string Folder(int csidl, out int hr)
    {
        StringBuilder sb = new StringBuilder(520);
        hr = SHGetFolderPathW(IntPtr.Zero, csidl, IntPtr.Zero, 0, sb);
        return hr == 0 ? sb.ToString() : null;
    }

    public static int LicenseDword(string name, out uint value)
    {
        return SLGetWindowsInformationDWORD(name, out value);
    }

    public static string[] UiLanguages()
    {
        List<string> list = new List<string>();
        UiLangProc cb = delegate (string lang, IntPtr p) { list.Add(lang); return true; };
        // MUI_LANGUAGE_NAME = 8
        EnumUILanguagesW(cb, 8, IntPtr.Zero);
        GC.KeepAlive(cb);
        return list.ToArray();
    }

    // Installed products of this account's view (machine, user-managed and the
    // caller's own user-unmanaged), product code -> installed context.
    public static Dictionary<string, int> EnumProducts()
    {
        Dictionary<string, int> d = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (uint i = 0; ; i++)
        {
            StringBuilder code = new StringBuilder(39);
            int ctx;
            int rc = MsiEnumProductsExW(null, null, 7, i, code, out ctx, IntPtr.Zero, IntPtr.Zero);
            if (rc == 259) { break; }          // ERROR_NO_MORE_ITEMS
            if (rc != 0) { throw new Exception("MsiEnumProductsEx returned " + rc); }
            d[code.ToString()] = ctx;
        }
        return d;
    }

    public static int ProductState(string product) { return MsiQueryProductStateW(product); }

    public static string ProductInfo(string product, int context, string prop)
    {
        StringBuilder sb = new StringBuilder(512);
        int len = sb.Capacity;
        int rc = MsiGetProductInfoExW(product, null, context, prop, sb, ref len);
        return rc == 0 ? sb.ToString() : null;
    }

    public static int FeatureState(string product, string feature) { return MsiQueryFeatureStateW(product, feature); }

    public static int ComponentState(string product, int context, string component)
    {
        int state;
        int rc = MsiQueryComponentStateW(product, null, context, component, out state);
        return rc == 0 ? state : -1000 - rc;
    }
}
'@

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

function R-Known($value) { return [ordered]@{ state = 'known'; value = $value } }
function R-Unit() { return [ordered]@{ state = 'known' } }
function R-Absent() { return [ordered]@{ state = 'absent' } }
function R-Unavail($why) { return [ordered]@{ state = 'unavailable'; reason = [string]$why } }

$script:Hklm = @{}
if ([Environment]::Is64BitOperatingSystem) {
    $script:Hklm['native'] = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
} else {
    $script:Hklm['native'] = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32)
}
$script:Hklm['wow32'] = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32)

function Open-Sub([string]$view, [string]$sub) {
    $s = $sub.Trim('\')
    return $script:Hklm[$view].OpenSubKey($s)
}

function Get-RegKeyFact([string]$view, [string]$sub) {
    try {
        $k = Open-Sub $view $sub
        if ($null -eq $k) { return R-Absent }
        $k.Close()
        return R-Unit
    } catch { return R-Unavail $_.Exception.Message }
}

function Get-Subkeys([string]$view, [string]$sub) {
    # @{ state = 'known'|'absent'|'unavailable'; names = string[]; reason }
    try {
        $k = Open-Sub $view $sub
        if ($null -eq $k) { return @{ state = 'absent'; names = @() } }
        try { $n = [string[]]$k.GetSubKeyNames() } finally { $k.Close() }
        return @{ state = 'known'; names = $n }
    } catch { return @{ state = 'unavailable'; names = @(); reason = $_.Exception.Message } }
}

function To-Hex([byte[]]$b) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($x in $b) { [void]$sb.Append($x.ToString('x2')) }
    return $sb.ToString()
}

function Read-RegValue([string]$view, [string]$sub, [string]$name) {
    # @{ state; type; data; reason } ; data is the JSON shape of the snapshot value
    try { $k = Open-Sub $view $sub } catch { return @{ state = 'unavailable'; reason = $_.Exception.Message } }
    if ($null -eq $k) { return @{ state = 'absent' } }
    try {
        $found = $false
        foreach ($n in $k.GetValueNames()) {
            if ([string]::Equals($n, $name, [StringComparison]::OrdinalIgnoreCase)) { $found = $true; break }
        }
        if (-not $found) { return @{ state = 'absent' } }
        $kind = $k.GetValueKind($name).ToString()
        $raw = $k.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        switch ($kind) {
            'DWord' {
                $u = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$raw), 0)
                return @{ state = 'known'; value = [ordered]@{ type = 'REG_DWORD'; data = $u } }
            }
            'QWord' {
                $u = [BitConverter]::ToUInt64([BitConverter]::GetBytes([int64]$raw), 0)
                return @{ state = 'known'; value = [ordered]@{ type = 'REG_QWORD'; data = $u.ToString() } }
            }
            'String' { return @{ state = 'known'; value = [ordered]@{ type = 'REG_SZ'; data = [string]$raw } } }
            'ExpandString' { return @{ state = 'known'; value = [ordered]@{ type = 'REG_EXPAND_SZ'; data = [string]$raw } } }
            'MultiString' { return @{ state = 'known'; value = [ordered]@{ type = 'REG_MULTI_SZ'; data = [string[]]$raw } } }
            'Binary' { return @{ state = 'known'; value = [ordered]@{ type = 'REG_BINARY'; data = (To-Hex ([byte[]]$raw)) } } }
            default { return @{ state = 'known'; value = [ordered]@{ type = 'OTHER'; name = 'REG_' + $kind.ToUpperInvariant() } } }
        }
    } catch { return @{ state = 'unavailable'; reason = $_.Exception.Message } }
    finally { $k.Close() }
}

function Get-RegValueFact([string]$view, [string]$sub, [string]$name) {
    $r = Read-RegValue $view $sub $name
    switch ($r.state) {
        'known' { return R-Known $r.value }
        'absent' { return R-Absent }
        default { return R-Unavail $r.reason }
    }
}

function Join-Prepend([string]$base, [string]$path) {
    $j = $base.TrimEnd('\') + '\' + $path.TrimStart('\')
    return ($j -replace '\\{2,}', '\').Replace('/', '\')
}

function Fmt-Time([datetime]$t) {
    return $t.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function Get-FileFact($location, [string]$path) {
    $kind = [string]$location['kind']
    $full = $null
    if ($kind -eq 'csidl') {
        $hr = 0
        $dir = [WuaFacts]::Folder([int]$location['csidl'], [ref]$hr)
        if ($null -eq $dir) { return R-Unavail ('SHGetFolderPath failed, hr=0x{0:x8}' -f $hr) }
        $full = Join-Prepend $dir $path
    } elseif ($kind -eq 'reg_sz') {
        $r = Read-RegValue ([string]$location['view']) ([string]$location['subkey']) ([string]$location['value'])
        if ($r.state -eq 'absent') { return R-Absent }
        if ($r.state -ne 'known') { return R-Unavail $r.reason }
        $t = [string]$r.value['type']
        if ($t -ne 'REG_SZ' -and $t -ne 'REG_EXPAND_SZ') { return R-Unavail ('base registry value is ' + $t) }
        $full = Join-Prepend ([string]$r.value['data']) $path
    } else {
        if ($path.Contains('%')) { return R-Unavail 'environment variable in an absolute path is not expanded' }
        $full = $path.Replace('/', '\')
    }
    try {
        if (-not [IO.File]::Exists($full)) { return R-Absent }
        $fi = New-Object IO.FileInfo($full)
        $v = [ordered]@{ resolved_path = $full; size = [int64]$fi.Length }
        $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($full)
        if ($vi.FileMajorPart -ne 0 -or $vi.FileMinorPart -ne 0 -or $vi.FileBuildPart -ne 0 -or $vi.FilePrivatePart -ne 0 -or -not [string]::IsNullOrEmpty($vi.FileVersion)) {
            $v['version'] = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
        }
        $v['modified'] = Fmt-Time $fi.LastWriteTimeUtc
        $v['created'] = Fmt-Time $fi.CreationTimeUtc
        return R-Known $v
    } catch { return R-Unavail $_.Exception.Message }
}

# MSI -----------------------------------------------------------------------
$script:MsiProducts = $null
function Get-MsiProducts() {
    if ($null -eq $script:MsiProducts) {
        $script:MsiProducts = @{}
        $d = [WuaFacts]::EnumProducts()
        foreach ($k in $d.Keys) {
            $st = [WuaFacts]::ProductState($k)
            # INSTALLSTATE_LOCAL 3, SOURCE 4, DEFAULT 5
            if ($st -ge 3 -and $st -le 5) { $script:MsiProducts[$k.ToUpperInvariant()] = [int]$d[$k] }
        }
    }
    return $script:MsiProducts
}

function Get-MsiProductFact([string]$product) {
    try {
        $p = Get-MsiProducts
        $key = $product.ToUpperInvariant()
        if (-not $p.ContainsKey($key)) { return R-Absent }
        $ctx = [int]$p[$key]
        $ver = [WuaFacts]::ProductInfo($product, $ctx, 'VersionString')
        $lang = [WuaFacts]::ProductInfo($product, $ctx, 'Language')
        $v = [ordered]@{ version = [string]$ver }
        $n = 0
        if ($lang -and [int]::TryParse($lang, [ref]$n)) { $v['language'] = $n }
        return R-Known $v
    } catch { return R-Unavail $_.Exception.Message }
}

function Get-MsiFeatureFact([string]$product, [string]$feature) {
    try {
        if (-not (Get-MsiProducts).ContainsKey($product.ToUpperInvariant())) { return R-Known $false }
        $st = [WuaFacts]::FeatureState($product, $feature)
        return R-Known (($st -ge 3) -and ($st -le 5))
    } catch { return R-Unavail $_.Exception.Message }
}

function Get-MsiComponentFact([string]$product, [string]$component) {
    try {
        $p = Get-MsiProducts
        $key = $product.ToUpperInvariant()
        if (-not $p.ContainsKey($key)) { return R-Known $false }
        $st = [WuaFacts]::ComponentState($product, [int]$p[$key], $component)
        if ($st -le -1000) { return R-Unavail ('MsiQueryComponentState error ' + (-1000 - $st)) }
        return R-Known (($st -ge 3) -and ($st -le 5))
    } catch { return R-Unavail $_.Exception.Message }
}

# ---------------------------------------------------------------------------
# answer one query (a dictionary from queries.json); returns the result
# ---------------------------------------------------------------------------
function Answer([hashtable]$q) {
    $kind = [string]$q['kind']
    switch ($kind) {
        'reg_key' { return Get-RegKeyFact $q['view'] $q['subkey'] }
        'reg_value' { return Get-RegValueFact $q['view'] $q['subkey'] $q['value'] }
        'reg_subkeys' {
            $s = Get-Subkeys $q['view'] $q['subkey']
            if ($s.state -eq 'known') { return R-Known ([string[]]$s.names) }
            if ($s.state -eq 'absent') { return R-Absent }
            return R-Unavail $s.reason
        }
        'file' { return Get-FileFact $q['location'] $q['path'] }
        'system_metric' {
            try { return R-Known ([int][WuaFacts]::Metric([int]$q['index'])) } catch { return R-Unavail $_.Exception.Message }
        }
        'license_dword' {
            try {
                $val = [uint32]0
                $hr = [WuaFacts]::LicenseDword([string]$q['name'], [ref]$val)
                if ($hr -eq 0) { return R-Known ([uint32]$val) }
                if ($hr -eq -1073418222) { return R-Absent }  # 0xC004F012 SL_E_VALUE_NOT_FOUND
                return R-Unavail ('SLGetWindowsInformationDWORD hr=0x{0:x8}' -f $hr)
            } catch { return R-Unavail $_.Exception.Message }
        }
        'wmi_query' {
            try {
                $ns = ([string]$q['namespace']).Replace('/', '\')
                $rows = @(Get-CimInstance -Namespace $ns -Query ([string]$q['query']) -ErrorAction Stop)
                return R-Known ($rows.Count -gt 0)
            } catch { return R-Unavail $_.Exception.Message }
        }
        'msi_product' { return Get-MsiProductFact ([string]$q['product']) }
        'msi_feature' { return Get-MsiFeatureFact ([string]$q['product']) ([string]$q['feature']) }
        'msi_component' { return Get-MsiComponentFact ([string]$q['product']) ([string]$q['component']) }
        'msi_patch' { return R-Unavail 'patch state is not collected by this script' }
        'cbs_package' {
            $sub = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\' + [string]$q['identity']
            $r = Read-RegValue 'native' $sub 'CurrentState'
            if ($r.state -eq 'absent') {
                $kf = Get-RegKeyFact 'native' $sub
                if ($kf.state -eq 'absent') { return R-Absent }
                return R-Unavail 'package key exists without a CurrentState value'
            }
            if ($r.state -ne 'known') { return R-Unavail $r.reason }
            if ([string]$r.value['type'] -ne 'REG_DWORD') { return R-Unavail 'CurrentState is not a REG_DWORD' }
            return R-Known ([uint32]$r.value['data'])
        }
        default { return R-Unavail ('unknown query kind ' + $kind) }
    }
}

# Explicit JSON writer. JavaScriptSerializer throws on PowerShell-wrapped objects (it meets
# PSParameterizedProperty members) and PowerShell's array unrolling makes a helper that returns
# converted copies unreliable, so write the text directly.
function Write-JsonString([Text.StringBuilder]$sb, [string]$v) {
    [void]$sb.Append('"')
    foreach ($ch in $v.ToCharArray()) {
        $c = [int]$ch
        if ($ch -eq '"') { [void]$sb.Append('\"') }
        elseif ($ch -eq '\') { [void]$sb.Append('\\') }
        elseif ($c -eq 8) { [void]$sb.Append('\b') }
        elseif ($c -eq 9) { [void]$sb.Append('\t') }
        elseif ($c -eq 10) { [void]$sb.Append('\n') }
        elseif ($c -eq 12) { [void]$sb.Append('\f') }
        elseif ($c -eq 13) { [void]$sb.Append('\r') }
        elseif ($c -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $c)) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
}

function Write-Json([Text.StringBuilder]$sb, $o) {
    # `.BaseObject` on a collection goes through member enumeration and yields nulls; the
    # intrinsic .PSObject.BaseObject is the correct unwrap.
    if ($null -ne $o -and $null -ne $o.PSObject) { $o = $o.PSObject.BaseObject }
    if ($null -eq $o) { [void]$sb.Append('null'); return }
    if ($o -is [string] -or $o -is [char]) { Write-JsonString $sb ([string]$o); return }
    if ($o -is [bool]) { [void]$sb.Append($(if ($o) { 'true' } else { 'false' })); return }
    if ($o -is [System.Collections.IDictionary]) {
        [void]$sb.Append('{')
        $first = $true
        foreach ($k in $o.Keys) {
            if (-not $first) { [void]$sb.Append(',') }
            $first = $false
            Write-JsonString $sb ([string]$k)
            [void]$sb.Append(':')
            Write-Json $sb $o[$k]
        }
        [void]$sb.Append('}')
        return
    }
    if ($o -is [System.Collections.IEnumerable]) {
        [void]$sb.Append('[')
        $first = $true
        foreach ($i in $o) {
            if (-not $first) { [void]$sb.Append(',') }
            $first = $false
            Write-Json $sb $i
        }
        [void]$sb.Append(']')
        return
    }
    if ($o -is [ValueType]) {
        [void]$sb.Append([string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}', $o))
        return
    }
    Write-JsonString $sb ([string]$o)
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
$ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$ser.MaxJsonLength = [int]::MaxValue
$ser.RecursionLimit = 1000

if (-not (Test-Path -LiteralPath $Queries)) { [Console]::Error.WriteLine("queries file not found: $Queries"); exit 1 }
$doc = $ser.DeserializeObject([IO.File]::ReadAllText($Queries))
if ([string]$doc['schema'] -ne 'wsus-applicability-queries/1') { [Console]::Error.WriteLine('unexpected queries schema: ' + $doc['schema']); exit 1 }
$items = @($doc['queries'])
if ($Limit -gt 0 -and $items.Count -gt $Limit) { $items = $items[0..($Limit - 1)] }

# OS section
$ver = [WuaFacts]::GetVersion()
$arch = [WuaFacts]::NativeArchitecture()
$lcid = [WuaFacts]::UiLanguageLcid()
$langName = (New-Object Globalization.CultureInfo($lcid)).Name
$uiLangs = [WuaFacts]::UiLanguages()
$ubr = $null
$cv = Read-RegValue 'native' 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR'
if ($cv.state -eq 'known') { $ubr = $cv.value['data'] }
$display = $null
$dv = Read-RegValue 'native' 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion'
if ($dv.state -eq 'known') { $display = $dv.value['data'] }

$os = [ordered]@{
    major = [int]$ver.dwMajorVersion
    minor = [int]$ver.dwMinorVersion
    build = [int]$ver.dwBuildNumber
    sp_major = [int]$ver.wServicePackMajor
    sp_minor = [int]$ver.wServicePackMinor
    product_type = [int]$ver.wProductType
    suite_mask = [int]$ver.wSuiteMask
    architecture = [int]$arch
    language = $langName
    # Unverified definition: MUI counts as installed when more than one UI
    # language is installed (EnumUILanguages); the list is kept in machine.
    mui_installed = ($uiLangs.Count -gt 1)
}

$machine = [ordered]@{
    computer = $env:COMPUTERNAME
    user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    os_build = '{0}.{1}.{2}' -f $ver.dwMajorVersion, $ver.dwMinorVersion, $ver.dwBuildNumber
    ubr = $ubr
    display_version = $display
    csd_version = $ver.szCSDVersion
    is_64bit_os = [Environment]::Is64BitOperatingSystem
    is_64bit_process = [Environment]::Is64BitProcess
    powershell = $PSVersionTable.PSVersion.ToString()
    ui_languages = [string[]]$uiLangs
    queries_file = (Resolve-Path -LiteralPath $Queries).Path
    queries_generated = [string]$doc['generated']
}

$facts = New-Object System.Collections.ArrayList
$seen = @{}

function Add-Fact([hashtable]$q, $result) {
    # Echo the query fields (without bookkeeping) and add the result.
    $e = [ordered]@{}
    foreach ($k in $q.Keys) {
        if ($k -ne 'updates' -and $k -ne 'loop_parent') { $e[$k] = $q[$k] }
    }
    $key = $script:ser.Serialize($e).ToLowerInvariant()
    $e['result'] = $result
    if ($script:seen.ContainsKey($key)) { return }
    $script:seen[$key] = $true
    [void]$script:facts.Add($e)
}

$counts = @{ known = 0; absent = 0; unavailable = 0 }
$n = 0
$sw = [Diagnostics.Stopwatch]::StartNew()
foreach ($raw in $items) {
    $q = [hashtable]$raw
    $n++
    if ($q.ContainsKey('loop_parent') -and $q['loop_parent']) {
        # Template: expand over every child of the loop key.
        $s = Get-Subkeys $q['view'] $q['loop_parent']
        foreach ($child in $s.names) {
            $full = ([string]$q['loop_parent']).Trim('\') + '\' + $child + '\' + ([string]$q['subkey']).Trim('\')
            $c = @{}
            foreach ($k in $q.Keys) { if ($k -ne 'loop_parent' -and $k -ne 'updates') { $c[$k] = $q[$k] } }
            $c['subkey'] = $full
            $r = Answer $c
            $counts[[string]$r['state']]++
            Add-Fact $c $r
        }
        continue
    }
    $r = Answer $q
    $counts[[string]$r['state']]++
    Add-Fact $q $r
    if (($n % 1000) -eq 0) { Write-Host ('{0}/{1} queries, {2:n0}s' -f $n, $items.Count, $sw.Elapsed.TotalSeconds) }
}

$snapshot = [ordered]@{
    schema = 'wsus-applicability-facts/1'
    collected_at = [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    machine = $machine
    os = $os
    facts = $facts
}
$sbOut = New-Object Text.StringBuilder
Write-Json $sbOut $snapshot
$json = $sbOut.ToString()
[IO.File]::WriteAllText($Out, $json, (New-Object Text.UTF8Encoding($false)))
Write-Host ('wrote {0}: {1} facts (known {2}, absent {3}, unavailable {4}) in {5:n0}s' -f $Out, $facts.Count, $counts['known'], $counts['absent'], $counts['unavailable'], $sw.Elapsed.TotalSeconds)
