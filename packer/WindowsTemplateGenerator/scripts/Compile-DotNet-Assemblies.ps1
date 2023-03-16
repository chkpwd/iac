Start-Process -FilePath %windir%\microsoft.net\framework\v4.0.30319\ngen.exe -ArgumentList 'update /force /queue'
Start-Process -FilePath %windir%\microsoft.net\framework64\v4.0.30319\ngen.exe -ArgumentList 'update /force /queue'
Start-Process -FilePath %windir%\microsoft.net\framework\v4.0.30319\ngen.exe -ArgumentList 'executequeueditems'
Start-Process -FilePath %windir%\microsoft.net\framework64\v4.0.30319\ngen.exe -ArgumentList 'executequeueditems'