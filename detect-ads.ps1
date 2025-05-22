<#
.SYNOPSIS
    Comprehensive Alternate Data Stream (ADS) Detection Script
.DESCRIPTION
    Scans specified directories for ADS in NTFS files, lists stream details, extracts readable content,
    calculates file hashes, and exports results to a CSV report. Useful for detecting hidden data or malware.

.DATE
    May 12, 2025
.USAGE
    .\Detect-ADS.ps1 -Path "C:\Path\To\Scan" [-OutputCsv "C:\Reports\ADS_Report.csv"] [-ExtractContent]
    Run with elevated privileges for full access.
.PARAMETERS
    -Path: Directory to scan (default: current directory).
    -OutputCsv: Path to export CSV report (default: .\ADS_Report_<timestamp>.csv).
    -ExtractContent: Attempt to extract and display readable ADS content (may increase runtime).
    -Verbose: Enable detailed output.
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$Path = (Get-Location).Path, # Default to current directory
    [Parameter(Mandatory=$false)]
    [string]$OutputCsv = ".\ADS_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [Parameter(Mandatory=$false)]
    [switch]$ExtractContent,
    [Parameter(Mandatory=$false)]
    [switch]$Verbose
)

# Function to log messages
function Write-Log {
    param ($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
    if ($Verbose) { Write-Verbose $Message }
}

# Function to check if path is valid and accessible
function Test-ValidPath {
    param ($CheckPath)
    if (-not (Test-Path $CheckPath)) {
        Write-Log "ERROR: Path '$CheckPath' does not exist."
        exit 1
    }
    if (-not (Get-Item $CheckPath).PSIsContainer) {
        Write-Log "ERROR: Path '$CheckPath' is not a directory."
        exit 1
    }
}

# Function to get file hash (MD5)
function Get-FileHashMD5 {
    param ($FilePath)
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm MD5 -ErrorAction Stop
        return $hash.Hash
    } catch {
        return "N/A"
    }
}

# Initialize results array
$results = @()
$scannedFiles = 0
$adsCount = 0

# Validate input path
Write-Log "Starting ADS detection scan on: $Path"
Test-ValidPath -CheckPath $Path

# Ensure script runs with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "WARNING: Script is not running with elevated privileges. Some files or streams may be inaccessible."
}

# Scan for ADS
Write-Log "Scanning files recursively in $Path..."
try {
    Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $file = $_
        $scannedFiles++
        if ($scannedFiles % 100 -eq 0) { Write-Log "Scanned $scannedFiles files..." }

        try {
            # Get all streams for the file
            $streams = Get-Item -Path $file.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' }

            foreach ($stream in $streams) {
                $adsCount++
                Write-Log "Found ADS: $($file.FullName):$($stream.Stream)"

                # Initialize result object
                $result = [PSCustomObject]@{
                    FilePath      = $file.FullName
                    FileSize      = $file.Length
                    FileHashMD5   = Get-FileHashMD5 -FilePath $file.FullName
                    StreamName    = $stream.Stream
                    StreamSize    = $stream.Length
                    StreamContent = "N/A"
                    LastModified  = $file.LastWriteTime
                    Created       = $file.CreationTime
                }

                # Extract content if requested
                if ($ExtractContent) {
                    try {
                        $content = Get-Content -Path $file.FullName -Stream $stream.Stream -ErrorAction SilentlyContinue
                        if ($content) {
                            # Truncate content for readability (first 100 characters)
                            $result.StreamContent = ($content | Out-String).Trim().Substring(0, [Math]::Min(100, ($content | Out-String).Length))
                            if (($content | Out-String).Length > 100) { $result.StreamContent += "..." }
                        }
                    } catch {
                        $result.StreamContent = "Unable to read content"
                    }
                }

                $results += $result
            }
        } catch {
            Write-Log "ERROR: Failed to process file '$($file.FullName)': $_"
        }
    }
} catch {
    Write-Log "ERROR: Failed to scan directory '$Path': $_"
    exit 1
}

# Summarize findings
Write-Log "Scan completed."
Write-Log "Files scanned: $scannedFiles"
Write-Log "ADS found: $adsCount"

# Display results
if ($results.Count -gt 0) {
    Write-Log "ADS Details:"
    $results | Format-Table -AutoSize -Property FilePath, StreamName, StreamSize, StreamContent, FileHashMD5
} else {
    Write-Log "No ADS found in the specified directory."
}

# Export to CSV
if ($results.Count -gt 0) {
    try {
        $results | Export-Csv -Path $OutputCsv -NoTypeInformation
        Write-Log "Results exported to: $OutputCsv"
    } catch {
        Write-Log "ERROR: Failed to export CSV to '$OutputCsv': $_"
    }
}

# Optional: Suggest next steps
if ($adsCount -gt 0) {
    Write-Log "RECOMMENDATION: Review ADS content for suspicious scripts or data. Use 'Get-Content -Path <file> -Stream <stream>' for detailed inspection."
    Write-Log "Consider cross-referencing with antivirus or forensic tools (e.g., Sysinternals Streams)."
}