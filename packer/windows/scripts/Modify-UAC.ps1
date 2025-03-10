$Path = "HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system"

if (Get-ItemProperty -Path $Path -Name EnableLUA).EnableLUA -ne 0 {
  New-ItemProperty -Path $Path -Name EnableLUA -PropertyType DWord -Value 0 -Force
} else {
  Set-ItemProperty -Path $Path -Name EnableLUA -Value 1
}
