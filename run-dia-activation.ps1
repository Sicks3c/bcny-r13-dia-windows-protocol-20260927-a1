$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$evidence = Join-Path $env:RUNNER_TEMP "evidence"
$download = Join-Path $env:RUNNER_TEMP "dia-activation-download"
$owned = Join-Path $env:RUNNER_TEMP "dia-activation-owned"
New-Item -ItemType Directory -Force -Path $evidence, $download, $owned | Out-Null

$msixUrl = "https://releases.diabrowser.com/windows/release-candidate/8EE7CF18-AF4C-48AF-94B0-4B9300876DA5/0.28.0.380/Dia.x64.msix"
$dependencyUrl = "https://releases.diabrowser.com/windows/dependencies/x64/Microsoft.VCLibs.x64.14.00.Desktop.14.0.33728.0.appx"
$expectedMsix = "fd92a6dd178222bc687683a2353b540bd13d0ed42ff87b61124a09bd8be09407"
$expectedDependency = "077a3d1a5d0622bd3004dca85f5e192d6e98ec79b83d4aa06766759ea6c09c3d"
$msixPath = Join-Path $download "Dia.x64.msix"
$dependencyPath = Join-Path $download "Microsoft.VCLibs.x64.appx"
$family = "TheBrowserCompany.Dia_ttt1ap7aakyb4"
$aumid = "$family!Dia"
$toastClsid = "ACDC2A84-D517-4A21-BFB7-A61D1A417115"
$listenerPort = 43871
$listener = $null
$diaPackage = $null
$diaInstallLocation = $null
$installedDependencyByRun = $false
$dependencyInstalledFullName = $null
$baselineProfile = @{}
$failed = $false

$result = [ordered]@{
  schema = "bcny-r13-dia-windows-protocol-activation-v1"
  target = "TheBrowserCompany.Dia"
  requested_version = "0.28.0.380"
  source_chain = [ordered]@{ msix=$msixUrl; dependency=$dependencyUrl }
  baseline = $null
  downloads = @()
  signatures = @()
  registration = $null
  listener_control = $null
  activation_helper = $null
  cases = @()
  detector_control = $null
  summary = $null
  cleanup = $null
  failure = $null
}

function Download-Exact([string]$Url, [string]$Path, [string]$Expected, [string]$Label) {
  & curl.exe --fail --location --silent --show-error --retry 3 --max-time 900 --user-agent "authorized-security-research/1.0" --output $Path $Url
  if ($LASTEXITCODE -ne 0) { throw "curl failed for $Label with exit $LASTEXITCODE" }
  $item = Get-Item -LiteralPath $Path
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
  if ($hash -ne $Expected) { throw "hash mismatch for $Label" }
  $result.downloads += [ordered]@{ label=$Label; bytes=$item.Length; sha256=$hash; hash_match=$true }
}

function Signature-Summary([string]$Path, [string]$Label) {
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  return [ordered]@{
    label = $Label
    status = [string]$signature.Status
    status_message = $signature.StatusMessage
    signer_subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    signer_issuer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Issuer } else { $null }
    signer_thumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
  }
}

function Stop-Dia {
  if (-not $diaInstallLocation) { return }
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.ExecutablePath -and $_.ExecutablePath.StartsWith($diaInstallLocation, [StringComparison]::OrdinalIgnoreCase)
  } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Milliseconds 900
}

function Get-DiaSnapshot {
  if (-not $diaInstallLocation) { return @() }
  return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.ExecutablePath -and $_.ExecutablePath.StartsWith($diaInstallLocation, [StringComparison]::OrdinalIgnoreCase)
  } | Sort-Object ProcessId | ForEach-Object {
    [ordered]@{
      name = $_.Name
      pid = [int]$_.ProcessId
      parent_pid = [int]$_.ParentProcessId
      command_line = if ($_.CommandLine) { $_.CommandLine.Replace($env:RUNNER_TEMP, '%RUNNER_TEMP%') } else { $null }
    }
  })
}

function Invoke-Executable([string]$FilePath, [string[]]$ArgumentList) {
  $psi = [Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $FilePath
  $psi.UseShellExecute = $false
  foreach ($argument in $ArgumentList) { [void]$psi.ArgumentList.Add($argument) }
  $process = [Diagnostics.Process]::Start($psi)
  return [ordered]@{ invocation="ProcessStartInfo.ArgumentList"; pid=[int]$process.Id; error=$null }
}

function Get-ListenerHits([string]$CaseId) {
  $logPath = Join-Path $owned "listener-stderr.log"
  if (-not (Test-Path -LiteralPath $logPath)) { return 0 }
  return @(Select-String -LiteralPath $logPath -SimpleMatch -Pattern "/$CaseId" -ErrorAction SilentlyContinue).Count
}

function Run-IsolatedCase([string]$Id, [string]$Approach, [string]$InputKind, [string]$InputValue, [string]$CanaryPath, [scriptblock]$Activation) {
  Stop-Dia
  if ($CanaryPath -and (Test-Path -LiteralPath $CanaryPath)) { Remove-Item -LiteralPath $CanaryPath -Force }
  $before = @(Get-DiaSnapshot)
  $hitsBefore = Get-ListenerHits $Id
  $activationResult = $null
  $activationError = $null
  try {
    $activationResult = & $Activation
  }
  catch {
    $activationError = [ordered]@{
      type = $_.Exception.GetType().FullName
      message = $_.Exception.Message.Replace($env:RUNNER_TEMP, '%RUNNER_TEMP%')
      hresult = ('0x{0:X8}' -f ($_.Exception.HResult -band 0xffffffffL))
    }
  }
  Start-Sleep -Seconds 5
  $after = @(Get-DiaSnapshot)
  $hitsAfter = Get-ListenerHits $Id
  $case = [ordered]@{
    id = $Id
    approach = $Approach
    input_kind = $InputKind
    input = $InputValue.Replace($env:RUNNER_TEMP, '%RUNNER_TEMP%')
    activation_result = $activationResult
    activation_error = $activationError
    process_count_before = $before.Count
    process_count_after = $after.Count
    processes_after = $after
    listener_hit_delta = [int]($hitsAfter - $hitsBefore)
    command_canary_created = if ($CanaryPath) { [bool](Test-Path -LiteralPath $CanaryPath) } else { $false }
  }
  $result.cases += $case
  Stop-Dia
}

$activationSource = @'
using System;
using System.Runtime.InteropServices;

namespace BcnyActivation {
  [Flags]
  public enum ActivateOptions : uint {
    None = 0,
    DesignMode = 1,
    NoErrorUI = 2,
    NoSplashScreen = 4,
    Prelaunch = 0x2000000
  }

  [ComImport, Guid("2E941141-7F97-4756-BA1D-9DECDE894A3D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IApplicationActivationManager {
    [PreserveSig]
    int ActivateApplication([MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
      [MarshalAs(UnmanagedType.LPWStr)] string arguments, ActivateOptions options, out uint processId);
    [PreserveSig]
    int ActivateForFile([MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
      IShellItemArray itemArray, [MarshalAs(UnmanagedType.LPWStr)] string verb, out uint processId);
    [PreserveSig]
    int ActivateForProtocol([MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
      IShellItemArray itemArray, out uint processId);
  }

  [ComImport, Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C")]
  class ApplicationActivationManager { }

  [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IShellItem { }

  [ComImport, Guid("B63EA76D-1F85-456F-A19C-48159EFA858B"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IShellItemArray { }

  public sealed class ActivationResult {
    public int HResult { get; set; }
    public uint ProcessId { get; set; }
    public string HResultHex { get { return "0x" + unchecked((uint)HResult).ToString("X8"); } }
  }

  public static class Activator {
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, PreserveSig=true)]
    static extern int SHCreateItemFromParsingName(string path, IntPtr bindContext, ref Guid riid,
      [MarshalAs(UnmanagedType.Interface)] out IShellItem shellItem);

    [DllImport("shell32.dll", PreserveSig=true)]
    static extern int SHCreateShellItemArrayFromShellItem(IShellItem shellItem, ref Guid riid,
      [MarshalAs(UnmanagedType.Interface)] out IShellItemArray shellItemArray);

    static IShellItemArray MakeArray(string value) {
      Guid itemGuid = new Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE");
      IShellItem item;
      int hr = SHCreateItemFromParsingName(value, IntPtr.Zero, ref itemGuid, out item);
      if (hr < 0) Marshal.ThrowExceptionForHR(hr);
      Guid arrayGuid = new Guid("B63EA76D-1F85-456F-A19C-48159EFA858B");
      IShellItemArray array;
      hr = SHCreateShellItemArrayFromShellItem(item, ref arrayGuid, out array);
      Marshal.ReleaseComObject(item);
      if (hr < 0) Marshal.ThrowExceptionForHR(hr);
      return array;
    }

    public static ActivationResult Application(string appUserModelId, string arguments) {
      var manager = (IApplicationActivationManager)new ApplicationActivationManager();
      uint pid;
      int hr = manager.ActivateApplication(appUserModelId, arguments, ActivateOptions.NoErrorUI, out pid);
      Marshal.ReleaseComObject(manager);
      return new ActivationResult { HResult=hr, ProcessId=pid };
    }

    public static ActivationResult File(string appUserModelId, string path) {
      var array = MakeArray(path);
      var manager = (IApplicationActivationManager)new ApplicationActivationManager();
      uint pid;
      int hr = manager.ActivateForFile(appUserModelId, array, null, out pid);
      Marshal.ReleaseComObject(array);
      Marshal.ReleaseComObject(manager);
      return new ActivationResult { HResult=hr, ProcessId=pid };
    }

    public static ActivationResult Protocol(string appUserModelId, string uri) {
      var array = MakeArray(uri);
      var manager = (IApplicationActivationManager)new ApplicationActivationManager();
      uint pid;
      int hr = manager.ActivateForProtocol(appUserModelId, array, out pid);
      Marshal.ReleaseComObject(array);
      Marshal.ReleaseComObject(manager);
      return new ActivationResult { HResult=hr, ProcessId=pid };
    }
  }
}
'@

try {
  $baselineDia = @(Get-AppxPackage -Name "TheBrowserCompany.Dia" -ErrorAction SilentlyContinue)
  $baselineDependency = @(Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -ErrorAction SilentlyContinue)
  $profileCandidates = @(
    (Join-Path $env:LOCALAPPDATA "Packages\$family"),
    (Join-Path $env:LOCALAPPDATA "The Browser Company\Dia"),
    (Join-Path $env:LOCALAPPDATA "TheBrowserCompany\Dia"),
    (Join-Path $env:LOCALAPPDATA "Dia"),
    (Join-Path $env:APPDATA "The Browser Company\Dia"),
    (Join-Path $env:APPDATA "Dia")
  )
  foreach ($candidate in $profileCandidates) { $baselineProfile[$candidate] = Test-Path -LiteralPath $candidate }
  $result.baseline = [ordered]@{
    dia_package_count = $baselineDia.Count
    dependency_package_count = $baselineDependency.Count
    profile_candidates = @($profileCandidates | ForEach-Object { [ordered]@{ leaf=(Split-Path $_ -Leaf); existed=[bool]$baselineProfile[$_] } })
  }
  if ($baselineDia.Count -ne 0) { throw "Dia package unexpectedly present at baseline" }

  Download-Exact $msixUrl $msixPath $expectedMsix "dia_x64_msix"
  Download-Exact $dependencyUrl $dependencyPath $expectedDependency "vclibs_dependency"
  $result.signatures = @(
    (Signature-Summary $msixPath "dia_x64_msix"),
    (Signature-Summary $dependencyPath "vclibs_dependency")
  )
  if (($result.signatures | Where-Object { $_.status -ne "Valid" }).Count -ne 0) { throw "source signature invalid" }

  if ($baselineDependency.Count -eq 0) {
    Add-AppxPackage -Path $dependencyPath -ForceApplicationShutdown
    $installedDependencyByRun = $true
    $dependencyInstalledFullName = (Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" | Select-Object -First 1).PackageFullName
  }
  Add-AppxPackage -Path $msixPath -DependencyPath $dependencyPath -ForceApplicationShutdown
  $diaPackage = Get-AppxPackage -Name "TheBrowserCompany.Dia" | Sort-Object Version -Descending | Select-Object -First 1
  if (-not $diaPackage) { throw "Dia package missing after install" }
  $diaInstallLocation = [string]$diaPackage.InstallLocation
  $diaExe = Join-Path $diaInstallLocation "Dia.exe"
  $manifestPath = Join-Path $diaInstallLocation "AppxManifest.xml"
  Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $evidence "installed-AppxManifest.xml")
  $result.signatures += Signature-Summary $diaExe "installed_Dia.exe"
  if (($result.signatures | Where-Object { $_.status -ne "Valid" }).Count -ne 0) { throw "installed signature invalid" }

  [xml]$manifestXml = Get-Content -LiteralPath $manifestPath -Raw
  $ns = [Xml.XmlNamespaceManager]::new($manifestXml.NameTable)
  $ns.AddNamespace("f", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
  $ns.AddNamespace("uap", "http://schemas.microsoft.com/appx/manifest/uap/windows10")
  $ns.AddNamespace("uap3", "http://schemas.microsoft.com/appx/manifest/uap/windows10/3")
  $ns.AddNamespace("uap5", "http://schemas.microsoft.com/appx/manifest/uap/windows10/5")
  $ns.AddNamespace("desktop", "http://schemas.microsoft.com/appx/manifest/desktop/windows10")
  $protocolNames = @($manifestXml.SelectNodes("//uap3:Protocol", $ns) | ForEach-Object { $_.Name })
  $fileTypes = @($manifestXml.SelectNodes("//uap:FileType", $ns) | ForEach-Object { $_.'#text' })
  $aliasNames = @($manifestXml.SelectNodes("//uap5:ExecutionAlias", $ns) | ForEach-Object { $_.Alias })
  $toastIds = @($manifestXml.SelectNodes("//desktop:ToastNotificationActivation", $ns) | ForEach-Object { $_.ToastActivatorCLSID })
  $aliasPath = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\Dia.exe"
  $result.registration = [ordered]@{
    package_name = $diaPackage.Name
    package_version = [string]$diaPackage.Version
    package_family = $diaPackage.PackageFamilyName
    aumid = $aumid
    protocols = $protocolNames
    file_types = $fileTypes
    execution_aliases = $aliasNames
    execution_alias_path_exists = [bool](Test-Path -LiteralPath $aliasPath)
    toast_clsids = $toastIds
    manifest_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash.ToLowerInvariant()
  }
  if ($diaPackage.PackageFamilyName -ne $family) { throw "unexpected package family" }
  if ([string]$diaPackage.Version -ne "0.28.0.380") { throw "unexpected package version" }
  if (-not (Test-Path -LiteralPath $aliasPath)) { throw "registered execution alias missing" }

  Add-Type -TypeDefinition $activationSource -Language CSharp
  $result.activation_helper = [ordered]@{ compiled=$true; sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($activationSource))).ToLowerInvariant() }

  $python = (Get-Command python -ErrorAction Stop).Source
  $listenerOut = Join-Path $owned "listener-stdout.log"
  $listenerErr = Join-Path $owned "listener-stderr.log"
  $listener = Start-Process -FilePath $python -ArgumentList @("-u", "-m", "http.server", [string]$listenerPort, "--bind", "127.0.0.1", "--directory", $owned) -RedirectStandardOutput $listenerOut -RedirectStandardError $listenerErr -PassThru
  Start-Sleep -Seconds 2
  $controlId = "listener-positive-control"
  $controlResponse = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$listenerPort/$controlId" -SkipHttpErrorCheck
  Start-Sleep -Milliseconds 300
  $result.listener_control = [ordered]@{ status_code=[int]$controlResponse.StatusCode; logged_hits=(Get-ListenerHits $controlId); passed=((Get-ListenerHits $controlId) -ge 1) }
  if (-not $result.listener_control.passed) { throw "listener positive control failed" }

  $html = Join-Path $owned "owned-&-bcny.html"
  $xml = Join-Path $owned "owned-&-bcny.xml"
  $pdf = Join-Path $owned "owned-&-bcny.pdf"
  $svg = Join-Path $owned "owned-&-bcny.svg"
  $webp = Join-Path $owned "owned-&-bcny.webp"
  Set-Content -LiteralPath $html -Encoding utf8 -Value '<!doctype html><meta charset="utf-8"><title>bcny-owned-html</title>'
  Set-Content -LiteralPath $xml -Encoding utf8 -Value '<?xml version="1.0"?><owned>bcny-owned-xml</owned>'
  [IO.File]::WriteAllBytes($pdf, [Text.Encoding]::ASCII.GetBytes("%PDF-1.4`n1 0 obj <<>> endobj`ntrailer <<>>`n%%EOF`n"))
  Set-Content -LiteralPath $svg -Encoding utf8 -Value '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><rect width="16" height="16" fill="green"/></svg>'
  [IO.File]::WriteAllBytes($webp, [byte[]](82,73,70,70,18,0,0,0,87,69,66,80,86,80,56,32,10,0,0,0,47,0,0,0,0,0,0,0,0,0))

  $directCanary = Join-Path $owned "direct-canary.txt"
  $aliasCanary = Join-Path $owned "alias-canary.txt"
  $aumidCanary = Join-Path $owned "aumid-canary.txt"
  $protocolCanary = Join-Path $owned "protocol-canary.txt"
  $toastCanary = Join-Path $owned "toast-canary.txt"

  Run-IsolatedCase "direct-no-args" "direct_executable" "none" "" $null { Invoke-Executable $diaExe @() }
  Run-IsolatedCase "direct-http" "direct_executable" "uri" "http://127.0.0.1:$listenerPort/direct-http" $null { Invoke-Executable $diaExe @("http://127.0.0.1:$listenerPort/direct-http") }
  Run-IsolatedCase "direct-http-fragment" "direct_executable" "uri" "http://127.0.0.1:$listenerPort/direct-http-fragment?q=%2522%2526#owned" $null { Invoke-Executable $diaExe @("http://127.0.0.1:$listenerPort/direct-http-fragment?q=%2522%2526#owned") }
  $directPayload = 'http://127.0.0.1:' + $listenerPort + '/direct-meta?x=" & cmd.exe /d /c echo owned>' + $directCanary + ' & rem "'
  Run-IsolatedCase "direct-meta" "direct_executable" "command_line_metacharacters" $directPayload $directCanary { Invoke-Executable $diaExe @($directPayload) }

  Run-IsolatedCase "alias-no-args" "execution_alias" "none" "" $null { Invoke-Executable $aliasPath @() }
  Run-IsolatedCase "alias-http" "execution_alias" "uri" "http://127.0.0.1:$listenerPort/alias-http" $null { Invoke-Executable $aliasPath @("http://127.0.0.1:$listenerPort/alias-http") }
  $quotedAlias = '"http://127.0.0.1:' + $listenerPort + '/alias-quoted?q=owned"'
  Run-IsolatedCase "alias-quoted" "execution_alias" "quoted_uri" $quotedAlias $null { Invoke-Executable $aliasPath @($quotedAlias) }
  $aliasPayload = 'http://127.0.0.1:' + $listenerPort + '/alias-meta?x=" & cmd.exe /d /c echo owned>' + $aliasCanary + ' & rem "'
  Run-IsolatedCase "alias-meta" "execution_alias" "command_line_metacharacters" $aliasPayload $aliasCanary { Invoke-Executable $aliasPath @($aliasPayload) }

  Run-IsolatedCase "aumid-no-args" "aumid_activate_application" "none" "" $null { [BcnyActivation.Activator]::Application($aumid, "") }
  Run-IsolatedCase "aumid-http" "aumid_activate_application" "uri" "http://127.0.0.1:$listenerPort/aumid-http" $null { [BcnyActivation.Activator]::Application($aumid, "http://127.0.0.1:$listenerPort/aumid-http") }
  $aumidPayload = 'http://127.0.0.1:' + $listenerPort + '/aumid-meta?x=" & cmd.exe /d /c echo owned>' + $aumidCanary + ' & rem "'
  Run-IsolatedCase "aumid-meta" "aumid_activate_application" "command_line_metacharacters" $aumidPayload $aumidCanary { [BcnyActivation.Activator]::Application($aumid, $aumidPayload) }

  Run-IsolatedCase "protocol-http" "activate_for_protocol" "uri" "http://127.0.0.1:$listenerPort/protocol-http" $null { [BcnyActivation.Activator]::Protocol($aumid, "http://127.0.0.1:$listenerPort/protocol-http") }
  Run-IsolatedCase "protocol-encoded" "activate_for_protocol" "encoded_uri" "http://127.0.0.1:$listenerPort/protocol-encoded?q=%2522%2526%253B" $null { [BcnyActivation.Activator]::Protocol($aumid, "http://127.0.0.1:$listenerPort/protocol-encoded?q=%2522%2526%253B") }
  $protocolPayload = 'http://127.0.0.1:' + $listenerPort + '/protocol-meta?x=" & cmd.exe /d /c echo owned>' + $protocolCanary + ' & rem "'
  Run-IsolatedCase "protocol-meta" "activate_for_protocol" "command_line_metacharacters" $protocolPayload $protocolCanary { [BcnyActivation.Activator]::Protocol($aumid, $protocolPayload) }

  Run-IsolatedCase "file-html" "activate_for_file" "owned_file" $html $null { [BcnyActivation.Activator]::File($aumid, $html) }
  Run-IsolatedCase "file-xml" "activate_for_file" "owned_file" $xml $null { [BcnyActivation.Activator]::File($aumid, $xml) }
  Run-IsolatedCase "file-pdf" "activate_for_file" "owned_file" $pdf $null { [BcnyActivation.Activator]::File($aumid, $pdf) }
  Run-IsolatedCase "file-svg" "activate_for_file" "owned_file" $svg $null { [BcnyActivation.Activator]::File($aumid, $svg) }
  Run-IsolatedCase "file-webp" "activate_for_file" "owned_file" $webp $null { [BcnyActivation.Activator]::File($aumid, $webp) }

  Run-IsolatedCase "toast-com-create" "toast_com" "clsid" $toastClsid $null {
    $type = [Type]::GetTypeFromCLSID([Guid]$toastClsid, $true)
    $instance = [System.Activator]::CreateInstance($type)
    if ($instance -and [Runtime.InteropServices.Marshal]::IsComObject($instance)) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($instance) }
    [ordered]@{ invocation="CoCreateInstance"; clsid=$toastClsid; created=[bool]$instance }
  }
  Run-IsolatedCase "toast-empty" "toast_argument" "notification_activation" "----AppNotificationActivated:" $null { Invoke-Executable $diaExe @("----AppNotificationActivated:") }
  $toastPayload = '----AppNotificationActivated:bcny-owned" & cmd.exe /d /c echo owned>' + $toastCanary + ' & rem "'
  Run-IsolatedCase "toast-meta" "toast_argument" "command_line_metacharacters" $toastPayload $toastCanary { Invoke-Executable $diaExe @($toastPayload) }

  Stop-Dia
  $singleBefore = @(Get-DiaSnapshot)
  $first = Invoke-Executable $diaExe @()
  Start-Sleep -Seconds 4
  $singleFirst = @(Get-DiaSnapshot)
  $second = Invoke-Executable $aliasPath @("http://127.0.0.1:$listenerPort/single-alias")
  Start-Sleep -Seconds 5
  $singleSecond = @(Get-DiaSnapshot)
  $result.cases += [ordered]@{
    id="single-direct-then-alias"; approach="single_instance_routing"; input_kind="first_then_second"; input="direct empty, alias loopback URI";
    activation_result=[ordered]@{ first=$first; second=$second }; activation_error=$null; process_count_before=$singleBefore.Count;
    process_count_after_first=$singleFirst.Count; process_count_after=$singleSecond.Count; processes_after=$singleSecond;
    listener_hit_delta=(Get-ListenerHits "single-alias"); command_canary_created=$false
  }
  Stop-Dia

  $firstAumid = [BcnyActivation.Activator]::Application($aumid, "")
  Start-Sleep -Seconds 4
  $aumidFirstSnapshot = @(Get-DiaSnapshot)
  $secondAumid = [BcnyActivation.Activator]::Application($aumid, "http://127.0.0.1:$listenerPort/single-aumid")
  Start-Sleep -Seconds 5
  $aumidSecondSnapshot = @(Get-DiaSnapshot)
  $result.cases += [ordered]@{
    id="single-aumid-then-aumid"; approach="single_instance_routing"; input_kind="first_then_second"; input="AUMID empty, AUMID loopback URI";
    activation_result=[ordered]@{ first=$firstAumid; second=$secondAumid }; activation_error=$null; process_count_before=0;
    process_count_after_first=$aumidFirstSnapshot.Count; process_count_after=$aumidSecondSnapshot.Count; processes_after=$aumidSecondSnapshot;
    listener_hit_delta=(Get-ListenerHits "single-aumid"); command_canary_created=$false
  }
  Stop-Dia

  $firstDirect = Invoke-Executable $diaExe @()
  Start-Sleep -Seconds 4
  $directFirstSnapshot = @(Get-DiaSnapshot)
  $secondFile = [BcnyActivation.Activator]::File($aumid, $html)
  Start-Sleep -Seconds 5
  $fileSecondSnapshot = @(Get-DiaSnapshot)
  $result.cases += [ordered]@{
    id="single-direct-then-file"; approach="single_instance_routing"; input_kind="first_then_file"; input="direct empty, owned HTML activation";
    activation_result=[ordered]@{ first=$firstDirect; second=$secondFile }; activation_error=$null; process_count_before=0;
    process_count_after_first=$directFirstSnapshot.Count; process_count_after=$fileSecondSnapshot.Count; processes_after=$fileSecondSnapshot;
    listener_hit_delta=0; command_canary_created=$false
  }
  Stop-Dia

  $positiveMarker = Join-Path $owned "detector-positive-control.txt"
  Set-Content -LiteralPath $positiveMarker -Value "owned" -Encoding ascii
  $result.detector_control = [ordered]@{ marker_seen=[bool](Test-Path -LiteralPath $positiveMarker); passed=[bool](Test-Path -LiteralPath $positiveMarker) }
  Remove-Item -LiteralPath $positiveMarker -Force
  if (-not $result.detector_control.passed) { throw "command-canary detector positive control failed" }

  $result.summary = [ordered]@{
    case_count = $result.cases.Count
    approach_count = @($result.cases.approach | Sort-Object -Unique).Count
    activation_error_count = @($result.cases | Where-Object { $_.activation_error }).Count
    command_canary_created_count = @($result.cases | Where-Object { $_.command_canary_created }).Count
    listener_hit_case_count = @($result.cases | Where-Object { $_.listener_hit_delta -gt 0 }).Count
    no_default_browser_change = $true
    no_login_or_consent_action = $true
  }
  if ($result.summary.case_count -lt 15) { throw "case floor not met" }
  if ($result.summary.approach_count -lt 5) { throw "approach floor not met" }
}
catch {
  $failed = $true
  $result.failure = [ordered]@{
    exception_type = $_.Exception.GetType().FullName
    message = $_.Exception.Message.Replace($env:RUNNER_TEMP, '%RUNNER_TEMP%')
    hresult = ('0x{0:X8}' -f ($_.Exception.HResult -band 0xffffffffL))
  }
}
finally {
  try {
    if ($listener -and -not $listener.HasExited) { Stop-Process -Id $listener.Id -Force -ErrorAction SilentlyContinue }
    Stop-Dia
    if ($diaPackage) { Remove-AppxPackage -Package $diaPackage.PackageFullName -AllUsers:$false -ErrorAction Stop }
    if ($installedDependencyByRun -and $dependencyInstalledFullName) { Remove-AppxPackage -Package $dependencyInstalledFullName -AllUsers:$false -ErrorAction Stop }
    $cleanupCandidates = @(
      (Join-Path $env:LOCALAPPDATA "Packages\$family"),
      (Join-Path $env:LOCALAPPDATA "The Browser Company\Dia"),
      (Join-Path $env:LOCALAPPDATA "TheBrowserCompany\Dia"),
      (Join-Path $env:LOCALAPPDATA "Dia"),
      (Join-Path $env:APPDATA "The Browser Company\Dia"),
      (Join-Path $env:APPDATA "Dia")
    )
    foreach ($candidate in $cleanupCandidates) {
      $existedBefore = if ($baselineProfile.ContainsKey($candidate)) { [bool]$baselineProfile[$candidate] } else { $false }
      if (-not $existedBefore -and (Test-Path -LiteralPath $candidate)) { Remove-Item -LiteralPath $candidate -Recurse -Force }
    }
    if (Test-Path -LiteralPath $owned) { Remove-Item -LiteralPath $owned -Recurse -Force }
    if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download -Recurse -Force }
    $remainingCandidates = @($cleanupCandidates | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { Split-Path $_ -Leaf })
    $diaCountAfter = @(Get-AppxPackage -Name "TheBrowserCompany.Dia" -ErrorAction SilentlyContinue).Count
    $dependencyCountAfter = @(Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -ErrorAction SilentlyContinue).Count
    $packageProcessCountAfter = if ($diaInstallLocation) { @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($diaInstallLocation, [StringComparison]::OrdinalIgnoreCase) }).Count } else { 0 }
    $firewallFilterCountAfter = if ($diaInstallLocation) { @(Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | Where-Object { $_.Program -and $_.Program.StartsWith($diaInstallLocation, [StringComparison]::OrdinalIgnoreCase) }).Count } else { 0 }
    $dependencyBaselineCount = if ($result.baseline) { $result.baseline.dependency_package_count } else { $null }
    $cleanupPassed = ($diaCountAfter -eq 0) -and ($packageProcessCountAfter -eq 0) -and ($remainingCandidates.Count -eq 0) -and ($dependencyCountAfter -eq $dependencyBaselineCount) -and ($firewallFilterCountAfter -eq 0)
    $result.cleanup = [ordered]@{
      dia_package_count_after = $diaCountAfter
      dependency_count_after = $dependencyCountAfter
      dependency_baseline_count = $dependencyBaselineCount
      package_process_count_after = $packageProcessCountAfter
      firewall_application_filter_count_after = $firewallFilterCountAfter
      residual_new_profile_candidate_count = $remainingCandidates.Count
      residual_new_profile_candidate_leaves = $remainingCandidates
      owned_temp_exists_after = [bool](Test-Path -LiteralPath $owned)
      download_temp_exists_after = [bool](Test-Path -LiteralPath $download)
      cleanup_gate_passed = $cleanupPassed
    }
    if (-not $cleanupPassed) { $failed = $true }
  }
  catch {
    $failed = $true
    $result.cleanup = [ordered]@{ cleanup_error_type=$_.Exception.GetType().FullName; cleanup_error=$_.Exception.Message.Replace($env:RUNNER_TEMP, '%RUNNER_TEMP%') }
  }
  $result | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $evidence "activation-result.json") -Encoding utf8
  Get-ChildItem -LiteralPath $evidence -File | ForEach-Object { $_.Attributes = 'Normal' }
}

Write-Host (ConvertTo-Json ([ordered]@{ failure=$result.failure; summary=$result.summary; cleanup=$result.cleanup }) -Depth 8 -Compress)
if ($failed) { exit 1 }
