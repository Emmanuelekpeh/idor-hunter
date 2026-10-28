#!/usr/bin/env pwsh
# run-burp-mcp.ps1
# One-command orchestration for: Kilo Code -> Ollama (8b) -> Burp Suite MCP.
#
#   .\run-burp-mcp.ps1            # pre-checks ports, runs the full Node verify, prints next steps
#   .\run-burp-mcp.ps1 -Pull      # also pull the Ollama model if it is missing
#   .\run-burp-mcp.ps1 -Launch    # additionally start Kilo in this project (if the CLI is found)
#   .\run-burp-mcp.ps1 -BurpMcpUrl http://127.0.0.1:9876 -OllamaModel granite4.1:8b

[CmdletBinding()]
param(
    [string]$OllamaUrl   = "http://127.0.0.1:11434",
    [string]$OllamaModel = "granite4.1:8b",
    [string]$BurpMcpUrl  = "http://127.0.0.1:9876",
    [switch]$Pull,
    [switch]$Launch
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
$ou = [uri]$OllamaUrl
$OllamaHost = $ou.Host
$OllamaPort = if ($ou.Port -le 0) { 11434 } else { $ou.Port }
$bu = [uri]$BurpMcpUrl
$BurpHost = $bu.Host
$BurpPort = if ($bu.Port -le 0) { 9876 } else { $bu.Port }

function Write-Banner($t) { Write-Host ""; Write-Host ("=" * 64) -ForegroundColor DarkGray; Write-Host $t -ForegroundColor Cyan; Write-Host ("=" * 64) -ForegroundColor DarkGray }
function Test-TcpPort([string]$hostName, [int]$port) {
    try { $c = New-Object System.Net.Sockets.TcpClient; $c.Connect($hostName, $port); $c.Close(); return $true }
    catch { return $false }
}

Write-Banner "Burp MCP orchestration  (Kilo + Ollama + Burp Suite)"
Write-Host " Ollama : $OllamaUrl  (model: $OllamaModel)"
Write-Host " Burp   : $BurpMcpUrl"

# --- locate the kilo CLI (optional) ---
$kiloCmd = $null
$c = Get-Command kilo -ErrorAction SilentlyContinue
if ($c) { $kiloCmd = $c.Source }
else {
    foreach ($d in @("$env:APPDATA\npm", "$env:LOCALAPPDATA\Programs\kilo\bin", "$env:USERPROFILE\.kilo\bin", "$env:USERPROFILE\scoop\shims")) {
        foreach ($n in @('kilo.cmd', 'kilo.exe', 'kilo')) {
            $p = Join-Path $d $n
            if (Test-Path $p) { $kiloCmd = $p; break }
        }
        if ($kiloCmd) { break }
    }
}

