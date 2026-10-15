<#
what:   From a Windows PC or laptop, check what this machine can reach on the platform VM 101
        (website + AI API). The Windows twin of "platform-check.sh probe".
owner:  AIC
usage:  powershell -ExecutionPolicy Bypass -File ai-api\deploy\platform-probe.ps1 192.168.40.11
        powershell -ExecutionPolicy Bypass -File ai-api\deploy\platform-probe.ps1 10.109.0.10     (on WireGuard or Wi-Fi)
changes:nothing (TCP connects and two HTTPS GETs)
safe to run again: yes
runbook: runbooks/platform-vm-install.md
#>
param([Parameter(Mandatory = $true)][string]$Address)

$script:pass = 0; $script:warn = 0; $script:fail = 0
function Ok($m)   { $script:pass++; Write-Host "  ok    $m" }
function Warn($m) { $script:warn++; Write-Host "  warn  $m" -ForegroundColor Yellow }
function Bad($m)  { $script:fail++; Write-Host "  FAIL  $m" -ForegroundColor Red }

function Test-Port($h, $p) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $t = $c.ConnectAsync($h, $p)
        return ($t.Wait(4000) -and $c.Connected)
    } catch { return $false } finally { $c.Close() }
}
function Get-Code($url) {
    $c = & curl.exe -sk -o NUL -m 6 -w '%{http_code}' $url 2>$null
    if (-not $c) { return '000' } else { return $c }
}

# The source address Windows would use for this destination (a VPN address when WireGuard carries it)
$me = (Find-NetRoute -RemoteIPAddress $Address -ErrorAction SilentlyContinue | Where-Object IPAddress | Select-Object -First 1).IPAddress
if (-not $me) { $me = 'no route' }
Write-Host "Probing the platform VM at $Address from $env:COMPUTERNAME ($me)"

Write-Host "`nWebsite"
if (Test-Port $Address 443) { Ok "TCP 443 open" } else { Bad "TCP 443 unreachable: check the gateway, wireguard-vm's service rule, and VM 101's firewall" }
$c = Get-Code "https://$Address/healthz/"
switch ($c) { '200' { Ok "https://$Address/healthz/ answers 200" } '000' { Bad "https://$Address/healthz/ gave no answer" } default { Warn "https://$Address/healthz/ answered $c" } }

Write-Host "`nAI API"
if (Test-Port $Address 8443) { Ok "TCP 8443 open" } else { Warn "TCP 8443 unreachable (expected unless you are OBS, an AI team or staff; never from Wi-Fi)" }
$c = Get-Code "https://${Address}:8443/healthz"
switch ($c) { '200' { Ok "https://${Address}:8443/healthz answers 200" } '000' { Warn "AI API gave no answer" } default { Warn "AI API answered $c" } }

Write-Host "`nMust NOT be reachable"
foreach ($p in 8000, 5432, 11434) {
    if (Test-Port $Address $p) { Bad "port $p is reachable from here: it must stay local to VM 101" } else { Ok "port $p closed from here" }
}

Write-Host "`n$script:pass ok, $script:warn warnings, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
