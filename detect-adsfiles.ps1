# Detect-adsfiles.ps1
# This script detects files with alternate data streams (ADS) in a specified folder and its subfolders.

#Replace with the path to the folder you want to search
$folderPath = "C:\labfiles" 

#Get all files in the specified folder and its subfolders
$files = Get-ChildItem $folderPath -Recurse -File

#Loop through each file and check if it has any alternate data streams
foreach ($file in $files) {
    $streams = Get-Item $file.FullName -Stream *

    #If the file has alternate data streams, output the file path and stream names
    if ($streams) {
        Write-Host "File: $($file.FullName)" -ForegroundColor Magenta
        Write-Host "Alternate Data Streams:" -ForegroundColor Cyan

        foreach ($stream in $streams) {
            Write-Host "  $($stream.Stream)" -ForegroundColor Yellow
        }

        
        # Output the contents of the alternate data stream
        Write-Host " "
        Write-Host "Reading contents of the alternate data stream..." -ForegroundColor White           
        write-host "Contents of the alternate data stream:" -ForegroundColor Green  
        $ads=get-content -path $file -Stream $stream.Stream 
        write-host $ads -ForegroundColor Red
        Write-Host " "
    }
}