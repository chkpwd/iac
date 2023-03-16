# shamelessly taken from https://github.com/mwrock/packer-templates

# Defragging allows for trimming the drive in vmfs.
Write-Host "defragging..."
if ($null -ne (Get-Command Optimize-Volume -ErrorAction SilentlyContinue)) {
    Optimize-Volume -DriveLetter C
} else {
    Defrag.exe c: /H
}