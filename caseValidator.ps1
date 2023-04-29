# '==================================================================================================================================================================
# 'Disclaimer
# 'The sample scripts are not supported under any N-able support program or service.
# 'The sample scripts are provided AS IS without warranty of any kind.
# 'N-able further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
# 'The entire risk arising out of the use or performance of the sample scripts and documentation stays with you.
# 'In no event shall N-able or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever
# '(including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
# 'arising out of the use of or inability to use the sample scripts or documentation.
# '==================================================================================================================================================================

Param (
    [string]$verbose = "Y",
    [string]$caseNumber = ""
)

function setupLogging() {
    $script:logFilePath = "C:\ProgramData\MspPlatform\Tech Tribes\Feature Cleanup Utility\debug.log"
    
    $script:logFolder = Split-Path $logFilePath
    $script:logFile = Split-Path $logFilePath -Leaf

    $logFolderExists = Test-Path $logFolder
    $logFileExists = Test-Path $logFilePath

    If ($logFolderExists -eq $false) {
        New-Item -ItemType "directory" -Path $logFolder | Out-Null
    }
    
    If ($logFileExists -eq $true) {
        Remove-Item $logFilePath -ErrorAction SilentlyContinue
        Start-Sleep 2
        New-Item -ItemType "file" -Path $logFolder -Name $logFile | Out-Null
    } Else {
        New-Item -ItemType "file" -Path $logFolder -Name $logFile | Out-Null
    }
    
    If (($logFolder -match '.+?\\$') -eq $false) {
        $script:logFolder = $logFolder + "\"
    }

    [float]$script:currentVersion = 1.24
    writeToLog I "Started processing the caseValidator script."
    writeToLog I "Running script version: $currentVersion"
}

function validateUserInput() {
# Ensures the provided input from user is valid
    If ($verbose.ToLower() -eq "y") {
        $script:verboseMode = $true
        writeToLog V "You have defined to have the script output the verbose log entries."
    } Else {
        $script:verboseMode = $false
        writeToLog I "Will output logs in regular mode."
    }
    If (($caseNumber.Length -eq "8") -and ($caseNumber -match '\d{8}')) {
        writeToLog I "Provided case number is a valid 8 digit number ($caseNumber)."
    } Else {
        writeToLog F "Case number is invalid ($caseNumber)."
        writeToLog F "Please re-enter the 8 digit case number."
        writeToLog F "Failing script."
        postRuntime
        Exit 1001
    }

    writeToLog V "Input Parameters have been successfully validated."
    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function initialSetup() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    $osVersion = (Get-WmiObject Win32_OperatingSystem).Caption
    # Workaround for WMI timeout or WMI returning no data
    If (($null -eq $osVersion) -or ($OSVersion -like "*OS - Alias not found*")) {
        $osVersion = (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('ProductName')
    }
    writeToLog I "Detected Operating System:`r`n`t$OSVersion"
    
    $osArch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
    writeToLog I "Detected Operating System Aarchitecture: $osArch"

    $psVersion = $PSVersionTable.PSVersion
    writeToLog I "Detected PowerShell Version:`r`n`t$psVersion"

    $dotNetVersion = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where-Object { $_.PSChildName -Match '^(?!S)\p{L}'} | Select-Object PSChildName, version

    foreach ($i in $dotNetVersion) {
        writeToLog I ".NET Version: $($i.PSChildName) = $($i.Version)"
    }

    writeToLog I "Setting TLS to allow version 1.2."
    # Set security protocol to TLS 1.2 to avoid TLS errors
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'Tls12'

    $tlsValue = [Net.ServicePointManager]::SecurityProtocol

    writeToLog V "Confirming TLS Value set:`r`n`t$tlsValue"

    writeToLog I "Checking if device has TLS 1.2 Cipher Suites."
    [System.Collections.ArrayList]$enabled = @()

    $cipherslists = @('TLS_DHE_RSA_WITH_AES_128_GCM_SHA256','TLS_DHE_RSA_WITH_AES_256_GCM_SHA384','TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256','TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
    $ciphersenabledkey = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002\' | Select-Object -ExpandProperty Functions
    
    ForEach ($a in $ciphersenabledkey) {
        If ($cipherslists -eq $a){
            $enabled.Add($a) | Out-Null
        }
    }
    
    If ($enabled.count -ne 0) {
        writeToLog I "Cipher Suite(s) found:"
        Foreach ($i in $enabled) {
            writeToLog I "Detected Cipher: $i"
        }
    } Else {
        writeToLog W "Device is not fully patched, no secure Cipher Suite(s) were found."
    }
    
    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function confirmRunningLatest() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    $encryptedString = "JABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAA9ACAAIgBDADoAXABQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXABNAHMAcABQAGwAYQB0AGYAbwByAG0AXABUAGUAYwBoACAAVAByAGkAYgBlAHMAXABGAGUAYQB0AHUAcgBlACAAQwBsAGUAYQBuAHUAcAAgAFUAdABpAGwAaQB0AHkAXABkAGUAYgB1AGcALgBsAG8AZwAiAAoAJABsAG8AZwBGAG8AbABkAGUAcgAgAD0AIAAiAEMAOgBcAFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAE0AcwBwAFAAbABhAHQAZgBvAHIAbQBcAFQAZQBjAGgAIABUAHIAaQBiAGUAcwBcAEYAZQBhAHQAdQByAGUAIABDAGwAZQBhAG4AdQBwACAAVQB0AGkAbABpAHQAeQBcACIACgAKACQAdgBlAHIAcwBpAG8AbgBVAFIATAAgAD0AIAAiAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8AUgB5AGEAbgBBAHkAdABvAG4ALwBGAGUAYQB0AHUAcgBlAC0AQwBsAGUAYQBuAHUAcAAtAFUAdABpAGwAaQB0AHkALwBtAGEAaQBuAC8ARgBlAGEAdAB1AHIAZQBDAGwAZQBhAG4AdQBwAFUAdABpAGwAaQB0AHkAVgBlAHIAcwBpAG8AbgBpAG4AZwAuAHgAbQBsACIACgAkAHgAbQBsAEwAbwBjAGEAdABpAG8AbgAgAD0AIAAkAGwAbwBnAEYAbwBsAGQAZQByACAAKwAgACIAdgBlAHIAcwBpAG8AbgAuAHgAbQBsACIACgAKAHQAcgB5ACAAewAKACAAIAAgACAAUgBlAG0AbwB2AGUALQBJAHQAZQBtACAAJAB4AG0AbABMAG8AYwBhAHQAaQBvAG4AIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKAH0ACgBjAGEAdABjAGgAIAB7AAoAfQAKAAoAJAB3AGMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAAKAFsATgBlAHQALgBTAGUAcgB2AGkAYwBlAFAAbwBpAG4AdABNAGEAbgBhAGcAZQByAF0AOgA6AFMAZQBjAHUAcgBpAHQAeQBQAHIAbwB0AG8AYwBvAGwAIAA9ACAAWwBOAGUAdAAuAFMAZQBjAHUAcgBpAHQAeQBQAHIAbwB0AG8AYwBvAGwAVAB5AHAAZQBdACcAVABsAHMAMQAyACcACgAKAHQAcgB5ACAAewAKACAAIAAgACAAJAB3AGMALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACQAdgBlAHIAcwBpAG8AbgBVAFIATAAsACQAeABtAGwATABvAGMAYQB0AGkAbwBuACkACgB9AAoAYwBhAHQAYwBoACAAewAKACAAIAAgACAAJABtAHMAZwAgAD0AIAAkAF8ALgBFAHgAYwBlAHAAdABpAG8AbgAKACAAIAAgACAAJABsAGkAbgBlACAAPQAgACQAXwAuAEkAbgB2AG8AYwBhAHQAaQBvAG4ASQBuAGYAbwAuAFMAYwByAGkAcAB0AEwAaQBuAGUATgB1AG0AYgBlAHIACgAgACAAIAAgAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAIgBGAGEAaQBsAGUAZAAgAHQAbwAgAGQAbwB3AG4AbABvAGEAZAAgAEYAZQBhAHQAdQByAGUAQwBsAGUAYQBuAHUAcABVAHQAaQBsAGkAdAB5AFYAZQByAHMAaQBvAG4AaQBuAGcALgB4AG0AbAAsACAAZAB1AGUAIAB0AG8AOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAE0AZQBzAHMAYQBnAGUAKQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFQAaABpAHMAIABvAGMAYwB1AHIAcgBlAGQAIABvAG4AIABsAGkAbgBlACAAbgB1AG0AYgBlAHIAOgAgACQAbABpAG4AZQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAdABhAHQAdQBzADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBTAHQAYQB0AHUAcwApAGAAcgBgAG4AUgBlAHMAcABvAG4AcwBlADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBSAGUAcwBwAG8AbgBzAGUAKQBgAHIAYABuAEkAbgBuAGUAcgAgAEUAeABjAGUAcAB0AGkAbwBuADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBJAG4AbgBlAHIARQB4AGMAZQBwAHQAaQBvAG4AKQBgAHIAYABuAGAAcgBgAG4ASABSAGUAcwB1AGwAdAA6ACAAJAAoACQAbQBzAGcALgBIAFIAZQBzAHUAbAB0ACkAYAByAGAAbgBgAHIAYABuAFQAYQByAGcAZQB0AFMAaQB0AGUAIABhAG4AZAAgAFMAdABhAGMAawBUAHIAYQBjAGUAOgBgAHIAYABuACQAKAAkAG0AcwBnAC4AVABhAHIAZwBlAHQAUwBpAHQAZQApAGAAcgBgAG4AJAAoACQAbQBzAGcALgBTAHQAYQBjAGsAVAByAGEAYwBlACkAYAByAGAAbgAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFAAbABlAGEAcwBlACAAZQBuAHMAdQByAGUAIAB5AG8AdQAnAHIAZQAgAHUAcwBpAG4AZwAgAHQAaABlACAAbABhAHQAZQBzAHQAIAB2AGUAcgBzAGkAbwBuACwAIAB3AGgAaQBjAGgAIABjAGEAbgAgAGIAZQAgAGQAbwB3AG4AbABvAGEAZABlAGQAIABmAHIAbwBtACAAaABlAHIAZQA6AGAAcgBgAG4AYAB0AGgAdAB0AHAAcwA6AC8ALwBzADMALgBhAG0AYQB6AG8AbgBhAHcAcwAuAGMAbwBtAC8AbgBlAHcALQBzAHcAbQBzAHAALQBuAGUAdAAtAHMAdQBwAHAAbwByAHQAZgBpAGwAZQBzAC8AUABlAHIAbQBhAG4AZQBuAHQARgBpAGwAZQBzAC8ARgBlAGEAdAB1AHIAZQBDAGwAZQBhAG4AdQBwAC8AUABNAEUAJQAyADAAQwBsAGUAYQBuAHUAcAAlADIAMABSAGUAcQB1AGUAcwB0AC4AegBpAHAAIgAgAHwAIABPAHUAdAAtAGYAaQBsAGUAIAAkAGwAbwBnAEYAaQBsAGUAUABhAHQAaAAgAC0AQQBwAHAAZQBuAGQAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUACgAKACAAIAAgACAAUgBlAG0AbwB2AGUALQBJAHQAZQBtACAAJAB4AG0AbABMAG8AYwBhAHQAaQBvAG4AIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKAH0A"
    
    Powershell.exe -EncodedCommand $encryptedString

    $script:versionLocation = $logFolder + "version.xml"

    If (!(Test-Path $versionLocation)) {
        writeToLog E "The version.xml failed to download to the device."
        writeToLog E "Please review the following log for more information:`r`n`t$logFilePath"
        writeToLog W "Unable to confirm if the latest version is being ran."
        writeToLog W "Please ensure you're using the latest version, which can be downloaded from here:`r`nhttps://s3.amazonaws.com/new-swmsp-net-supportfiles/PermanentFiles/FeatureCleanup/PME%20Cleanup%20Request.zip"

        $url = "https://raw.githubusercontent.com/RyanAyton/Feature-Cleanup-Utility/main/FeatureCleanupUtilityVersioning.xml"

        try {
            $webRequest = Invoke-WebRequest $url
        }
        catch {
            $msg = $_.Exception
            $line = $_.InvocationInfo.ScriptLineNumber
            writeToLog E "Unable to perform web request to raw.githubusercontent.com, due to:`r`n`t$($msg.Message)"
            writeToLog V "This occurred on line number: $line"
            writeToLog V "Status:`r`n`t$($msg.Status)`r`nResponse:`r`n`t$($msg.Response.StatusCode)`r`n`t$($msg.Response.StatusDescription)`r`nInner Exception:`r`n`t$($msg.InnerException)`r`n`r`nHResult: $($msg.HResult)`r`n`r`nTargetSite and StackTrace:`r`n$($msg.TargetSite)`r`n$($msg.StackTrace)`r`n"
            writeToLog E "Url used: `r`n`t$url"
        }

    } Else {

        try {
            [xml]$xmlContent = Get-Content $versionLocation
        }
        catch {
            $msg = $_.Exception
            $line = $_.InvocationInfo.ScriptLineNumber
            writeToLog E "Unable to read content of version.xml, due to:`r`n`t$($msg.Message)"
            writeToLog V "This occurred on line number: $line"
            writeToLog V "Status:`r`n`t$($msg.Status)`r`nResponse:`r`n`t$($msg.Response)`r`nInner Exception:`r`n`t$($msg.InnerException)`r`n`r`nHResult: $($msg.HResult)`r`n`r`nTargetSite and StackTrace:`r`n$($msg.TargetSite)`r`n$($msg.StackTrace)`r`n"
        
            Remove-Item $versionLocation -Force -ErrorAction SilentlyContinue
        }

        [float]$script:latestPMECleanupVersion = $xmlContent.FeatureCleanupUtility.PME.Version
        writeToLog I "Latest GA version detected: $latestPMECleanupVersion"
    
        If ($currentVersion -lt $latestPMECleanupVersion) {
            writeToLog W "The version of this executing script is not the latest available."
            writeToLog V "Executing Version: $currentVersion. Latest GA Version: $latestPMECleanupVersion"
            writeToLog W "Please ensure you're using the latest version, which can be downloaded from here:`r`nhttps://s3.amazonaws.com/new-swmsp-net-supportfiles/PermanentFiles/FeatureCleanup/PME%20Cleanup%20Request.zip"
        } ElseIf ($currentVersion -gt $latestPMECleanupVersion) {
            writeToLog W "An error occurred validating the latest version."
        } Else {
            writeToLog I "The version of this executing script is the latest available."
        }
    }
    postRuntime

    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function downloadXml() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    $encryptedString = "JABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAA9ACAAIgBDADoAXABQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXABNAHMAcABQAGwAYQB0AGYAbwByAG0AXABUAGUAYwBoACAAVAByAGkAYgBlAHMAXABGAGUAYQB0AHUAcgBlACAAQwBsAGUAYQBuAHUAcAAgAFUAdABpAGwAaQB0AHkAXABkAGUAYgB1AGcALgBsAG8AZwAiAAoAJABsAG8AZwBGAG8AbABkAGUAcgAgAD0AIAAiAEMAOgBcAFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAE0AcwBwAFAAbABhAHQAZgBvAHIAbQBcAFQAZQBjAGgAIABUAHIAaQBiAGUAcwBcAEYAZQBhAHQAdQByAGUAIABDAGwAZQBhAG4AdQBwACAAVQB0AGkAbABpAHQAeQBcACIACgAKACQAcgBlAHMAdQBsAHQAcwBVAFIATAAgAD0AIAAiAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8AUgB5AGEAbgBBAHkAdABvAG4ALwBGAGUAYQB0AHUAcgBlAC0AQwBsAGUAYQBuAHUAcAAtAFUAdABpAGwAaQB0AHkALwBtAGEAaQBuAC8AcgBlAHMAdQBsAHQAcwAuAHgAbQBsACIACgAkAHgAbQBsAEwAbwBjAGEAdABpAG8AbgAgAD0AIAAkAGwAbwBnAEYAbwBsAGQAZQByACAAKwAgACIAcgBlAHMAdQBsAHQAcwAuAHgAbQBsACIACgAKAHQAcgB5ACAAewAKACAAIAAgACAAUgBlAG0AbwB2AGUALQBJAHQAZQBtACAAJAB4AG0AbABMAG8AYwBhAHQAaQBvAG4AIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKAH0ACgBjAGEAdABjAGgAIAB7AAoAfQAKAAoAJAB3AGMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAAKAFsATgBlAHQALgBTAGUAcgB2AGkAYwBlAFAAbwBpAG4AdABNAGEAbgBhAGcAZQByAF0AOgA6AFMAZQBjAHUAcgBpAHQAeQBQAHIAbwB0AG8AYwBvAGwAIAA9ACAAWwBOAGUAdAAuAFMAZQBjAHUAcgBpAHQAeQBQAHIAbwB0AG8AYwBvAGwAVAB5AHAAZQBdACcAVABsAHMAMQAyACcACgAKAHQAcgB5ACAAewAKACAAIAAgACAAJAB3AGMALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACQAcgBlAHMAdQBsAHQAcwBVAFIATAAsACQAeABtAGwATABvAGMAYQB0AGkAbwBuACkACgB9AAoAYwBhAHQAYwBoACAAewAKACAAIAAgACAAJABtAHMAZwAgAD0AIAAkAF8ALgBFAHgAYwBlAHAAdABpAG8AbgAKACAAIAAgACAAJABsAGkAbgBlACAAPQAgACQAXwAuAEkAbgB2AG8AYwBhAHQAaQBvAG4ASQBuAGYAbwAuAFMAYwByAGkAcAB0AEwAaQBuAGUATgB1AG0AYgBlAHIACgAgACAAIAAgAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAIgBGAGEAaQBsAGUAZAAgAHQAbwAgAGQAbwB3AG4AbABvAGEAZAAgAHIAZQBzAHUAbAB0AHMALgB4AG0AbAAsACAAZAB1AGUAIAB0AG8AOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAE0AZQBzAHMAYQBnAGUAKQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFQAaABpAHMAIABvAGMAYwB1AHIAcgBlAGQAIABvAG4AIABsAGkAbgBlACAAbgB1AG0AYgBlAHIAOgAgACQAbABpAG4AZQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAdABhAHQAdQBzADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBTAHQAYQB0AHUAcwApAGAAcgBgAG4AUgBlAHMAcABvAG4AcwBlADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBSAGUAcwBwAG8AbgBzAGUAKQBgAHIAYABuAEkAbgBuAGUAcgAgAEUAeABjAGUAcAB0AGkAbwBuADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBJAG4AbgBlAHIARQB4AGMAZQBwAHQAaQBvAG4AKQBgAHIAYABuAGAAcgBgAG4ASABSAGUAcwB1AGwAdAA6ACAAJAAoACQAbQBzAGcALgBIAFIAZQBzAHUAbAB0ACkAYAByAGAAbgBgAHIAYABuAFQAYQByAGcAZQB0AFMAaQB0AGUAIABhAG4AZAAgAFMAdABhAGMAawBUAHIAYQBjAGUAOgBgAHIAYABuACQAKAAkAG0AcwBnAC4AVABhAHIAZwBlAHQAUwBpAHQAZQApAGAAcgBgAG4AJAAoACQAbQBzAGcALgBTAHQAYQBjAGsAVAByAGEAYwBlACkAYAByAGAAbgAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKAAoAIAAgACAAIABSAGUAbQBvAHYAZQAtAEkAdABlAG0AIAAkAHgAbQBsAEwAbwBjAGEAdABpAG8AbgAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoAfQA="

    Powershell.exe -EncodedCommand $encryptedString

    $script:xmlLocation = $logFolder + "results.xml"

    If (!(Test-Path $xmlLocation)) {
        writeToLog E "Xml does not exist on the device."
        writeToLog E "Please review the following log for more information:`r`n`t$logFilePath"
        writeToLog E "Will attempt to download via SFTP."
        $script:retryXmlDownload = $true
        postRuntime
    } Else {
        writeToLog I "Xml downloaded successfully."
    }

    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function installPSServUModule() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    writeToLog V "Will now attempt to install and import the required ""PSServU"" Powershell Module."
    
    If (!(Get-Command -module PSServU)) {
        writeToLog V "Confirmed that Get-Command returned null for the module."
        writeToLog V "Performing the installation of the ""PSServU"" Powershell Module."

        try {
            Install-Module -Name PSServU -Confirm:$False -Scope AllUsers -Force -ErrorAction Stop
        }
        catch {
            $msg = $_.Exception
            $line = $_.InvocationInfo.ScriptLineNumber
            writeToLog F "Failed to install the PSServU Powershell module, due to:`r`n`t$($msg.Message)"
            writeToLog V "This occurred on line number: $line"
            writeToLog V "Status:`r`n`t$($msg.Status)`r`nResponse:`r`n`t$($msg.Response)`r`nInner Exception:`r`n`t$($msg.InnerException)`r`n`r`nHResult: $($msg.HResult)`r`n`r`nTargetSite and StackTrace:`r`n$($msg.TargetSite)`r`n$($msg.StackTrace)`r`n"
            writeToLog F "Failing script."
            postRuntime
            Exit 1001
        }
    
        $fullModulesPath = ($Env:PSModulePath -split ";")
        writeToLog V "Module Paths:`r`n`t$Env:PSModulePath"

        $fullModulePathTest = $fullModulesPath -contains "C:\Program Files\WindowsPowerShell\Modules"

        If ($fullModulePathTest -eq $true) {
            writeToLog V "Confirmed the following Module Path exists:`r`n`tC:\Program Files\WindowsPowerShell\Modules"
        } Else {
            writeToLog F "The following path does not exist:`r`n`tC:\Program Files\WindowsPowerShell\Modules"
            writeToLog F "Failing script."
            Exit 1001
        }

        $PSServUPath = "C:\Program Files\WindowsPowerShell\Modules\PSServU\"
 
        If (!(Test-Path $PSServUPath)) {
            writeToLog F "PSServU Module does not exist in the PS Module Environemtal path."
            writeToLog F "The module failed to install for all users."
            writeToLog F "Failing script."
            Exit 1001
        } Else {
            writeToLog I "Confirmed the PSServU Module exists in the PS Module Environemtal path."
        }

        writeToLog V "Install complete, now importing the ""PSServU"" Powershell Module."
        
    } Else {
        writeToLog I "Powershell Module is already installed on the device."
    }

    writeToLog V "Moving onto the module import stage."

    try {
        Import-Module -Name PSServU -ErrorAction Stop
    }
    catch {
        $msg = $_.Exception
        $line = $_.InvocationInfo.ScriptLineNumber
        writeToLog F "Failed to import the PSServU Powershell module, due to:`r`n`t$($msg.Message)"
        writeToLog V "This occurred on line number: $line"
        writeToLog V "Status:`r`n`t$($msg.Status)`r`nResponse:`r`n`t$($msg.Response)`r`nInner Exception:`r`n`t$($msg.InnerException)`r`n`r`nHResult: $($msg.HResult)`r`n`r`nTargetSite and StackTrace:`r`n$($msg.TargetSite)`r`n$($msg.StackTrace)`r`n"
        writeToLog F "Failing script."
        postRuntime
        Exit 1001
    }

    If (!(Get-Module -name "PSServU")) {
        writeToLog F "The PSServU Module is not imported."
        writeToLog F "Failing script."
        postRuntime
        Exit 1001
    } Else {
        $moduleVersion = (Get-Module -name "PSServU").Version
        writeToLog V "PSServU Module has successfully been imported on the device, running v$moduleVersion."
    }

    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function downloadSFTPXml() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    writeToLog I "Attempting to download configuration from the SFTP server."

    $encryptedString = "JABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAA9ACAAIgBDADoAXABQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXABNAHMAcABQAGwAYQB0AGYAbwByAG0AXABUAGUAYwBoACAAVAByAGkAYgBlAHMAXABQAE0ARQAgAEMAbABlAGEAbgB1AHAAXABkAGUAYgB1AGcALgBsAG8AZwAiAAoAJABsAG8AZwBGAG8AbABkAGUAcgAgAD0AIAAiAEMAOgBcAFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAE0AcwBwAFAAbABhAHQAZgBvAHIAbQBcAFQAZQBjAGgAIABUAHIAaQBiAGUAcwBcAFAATQBFACAAQwBsAGUAYQBuAHUAcABcACIACgAkAFUAcwBlAHIATgBhAG0AZQAgAD0AIAAiAHQAZQBjAGgAdAByAGkAYgBlAHUAcwBlAHIAIgAKACQAcABhAHMAcwAgAD0AIABDAG8AbgB2AGUAcgB0AFQAbwAtAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAAIgAzAE0AMgAyADcANgB0AGYAIgAgAC0AQQBzAFAAbABhAGkAbgBUAGUAeAB0ACAALQBGAG8AcgBjAGUACgAkAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgAD0AIAAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFAAUwBDAHIAZQBkAGUAbgB0AGkAYQBsACAALQBBAHIAZwB1AG0AZQBuAHQATABpAHMAdAAgACQAVQBzAGUAcgBOAGEAbQBlACwAIAAkAHAAYQBzAHMACgAKAHQAcgB5ACAAewAKACAAIAAgACAAJABzAGMAcgBpAHAAdAA6AHMAZQByAHYAVQBTAGUAcwBzAGkAbwBuACAAPQAgAE4AZQB3AC0AUwBlAHIAdgBVAFMAZQBzAHMAaQBvAG4AIAAtAFUAcgBsACAAIgBoAHQAdABwAHMAOgAvAC8AcwBmAHQAcAAyAC4AbgAtAGEAYgBsAGUALgBjAG8AbQAiACAALQBDAHIAZQBkAGUAbgB0AGkAYQBsACAAJABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAdABvAHAACgB9AAoAYwBhAHQAYwBoACAAewAKACAAIAAgACAAJABtAHMAZwAgAD0AIAAkAF8ALgBFAHgAYwBlAHAAdABpAG8AbgAKACAAIAAgACAAJABsAGkAbgBlACAAPQAgACQAXwAuAEkAbgB2AG8AYwBhAHQAaQBvAG4ASQBuAGYAbwAuAFMAYwByAGkAcAB0AEwAaQBuAGUATgB1AG0AYgBlAHIACgAgACAAIAAgAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAIgBGAGEAaQBsAGUAZAAgAHQAbwAgAHIAZQBhAGMAaAAgAHMAZgB0AHAAIABzAGUAcgB2AGUAcgAsACAAZAB1AGUAIAB0AG8AOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAE0AZQBzAHMAYQBnAGUAKQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFQAaABpAHMAIABvAGMAYwB1AHIAcgBlAGQAIABvAG4AIABsAGkAbgBlACAAbgB1AG0AYgBlAHIAOgAgACQAbABpAG4AZQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAdABhAHQAdQBzADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBTAHQAYQB0AHUAcwApAGAAcgBgAG4AUgBlAHMAcABvAG4AcwBlADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBSAGUAcwBwAG8AbgBzAGUAKQBgAHIAYABuAEkAbgBuAGUAcgAgAEUAeABjAGUAcAB0AGkAbwBuADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBJAG4AbgBlAHIARQB4AGMAZQBwAHQAaQBvAG4AKQBgAHIAYABuAGAAcgBgAG4ASABSAGUAcwB1AGwAdAA6ACAAJAAoACQAbQBzAGcALgBIAFIAZQBzAHUAbAB0ACkAYAByAGAAbgBgAHIAYABuAFQAYQByAGcAZQB0AFMAaQB0AGUAIABhAG4AZAAgAFMAdABhAGMAawBUAHIAYQBjAGUAOgBgAHIAYABuACQAKAAkAG0AcwBnAC4AVABhAHIAZwBlAHQAUwBpAHQAZQApAGAAcgBgAG4AJAAoACQAbQBzAGcALgBTAHQAYQBjAGsAVAByAGEAYwBlACkAYAByAGAAbgAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEYAYQBpAGwAaQBuAGcAIABzAGMAcgBpAHAAdAAuACIAIAB8ACAATwB1AHQALQBmAGkAbABlACAAJABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAAtAEEAcABwAGUAbgBkACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoAIAAgACAAIABFAHgAaQB0ACAAMQAwADAAMQAKAH0ACgAKACQAcgBlAG0AbwB0AGUARgBpAGwAZQAgAD0AIAAiAFAATQBFAEMAbABlAGEAbgB1AHAALwByAGUAcwB1AGwAdABzAC4AeABtAGwAIgAKACQAZABvAHcAbgBsAG8AYQBkAEwAbwBjAGEAdABpAG8AbgAgAD0AIAAkAGwAbwBnAEYAbwBsAGQAZQByAAoACgB0AHIAeQAgAHsACgAgACAAIAAgAEcAZQB0AC0AUwBlAHIAdgBVAEYAaQBsAGUAIAAtAHMAZQBzAHMAaQBvAG4AaQBkACAAJABzAGUAcgB2AFUAUwBlAHMAcwBpAG8AbgAuAFMAZQBzAHMAaQBvAG4ASQBkACAALQBSAGUAbQBvAHQAZQBGAGkAbABlACAAJAByAGUAbQBvAHQAZQBGAGkAbABlACAALQBsAG8AYwBhAGwAUABhAHQAaAAgACQAZABvAHcAbgBsAG8AYQBkAEwAbwBjAGEAdABpAG8AbgAgAC0AbwB2AGUAcgB3AHIAaQB0AGUAIAAtAEUAcgByAG8AcgBWAGEAcgBpAGEAYgBsAGUAIABmAHUAbABsAEUAcgByAG8AcgAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAKAH0ACgBjAGEAdABjAGgAIAB7AAoAIAAgACAAIAAkAG0AcwBnACAAPQAgACQAXwAuAEUAeABjAGUAcAB0AGkAbwBuAAoAIAAgACAAIAAkAGwAaQBuAGUAIAA9ACAAJABfAC4ASQBuAHYAbwBjAGEAdABpAG8AbgBJAG4AZgBvAC4AUwBjAHIAaQBwAHQATABpAG4AZQBOAHUAbQBiAGUAcgAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEYAYQBpAGwAZQBkACAAdABvACAAaQBtAHAAbwByAHQAIAB4AG0AbAAsACAAZAB1AGUAIAB0AG8AOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAE0AZQBzAHMAYQBnAGUAKQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFQAaABpAHMAIABvAGMAYwB1AHIAcgBlAGQAIABvAG4AIABsAGkAbgBlACAAbgB1AG0AYgBlAHIAOgAgACQAbABpAG4AZQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAdABhAHQAdQBzADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBTAHQAYQB0AHUAcwApAGAAcgBgAG4AUgBlAHMAcABvAG4AcwBlADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBSAGUAcwBwAG8AbgBzAGUAKQBgAHIAYABuAEkAbgBuAGUAcgAgAEUAeABjAGUAcAB0AGkAbwBuADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBJAG4AbgBlAHIARQB4AGMAZQBwAHQAaQBvAG4AKQBgAHIAYABuAGAAcgBgAG4ASABSAGUAcwB1AGwAdAA6ACAAJAAoACQAbQBzAGcALgBIAFIAZQBzAHUAbAB0ACkAYAByAGAAbgBgAHIAYABuAFQAYQByAGcAZQB0AFMAaQB0AGUAIABhAG4AZAAgAFMAdABhAGMAawBUAHIAYQBjAGUAOgBgAHIAYABuACQAKAAkAG0AcwBnAC4AVABhAHIAZwBlAHQAUwBpAHQAZQApAGAAcgBgAG4AJAAoACQAbQBzAGcALgBTAHQAYQBjAGsAVAByAGEAYwBlACkAYAByAGAAbgAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEYAYQBpAGwAaQBuAGcAIABzAGMAcgBpAHAAdAAuACIAIAB8ACAATwB1AHQALQBmAGkAbABlACAAJABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAAtAEEAcABwAGUAbgBkACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoAIAAgACAAIABFAHgAaQB0ACAAMQAwADAAMQAKAH0A"

    Powershell.exe -EncodedCommand $encryptedString

    $script:xmlLocation = $logFolder + "results.xml"

    $xmlLocationTest = Test-Path $xmlLocation

    writeToLog V "Testing location of the xml, returns as: $xmlLocationTest"

    If (!(Test-Path $xmlLocation)) {
        writeToLog F "Xml does not exist on the device."
        writeToLog F "Please review the following log for more information:`r`n`t$logFilePath"
        writeToLog F "Failing script."
        postRuntime
        Exit 1001
    }

    writeToLog I "Xml downloaded successfully."

    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function validateCaseNumber() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    try {
        $script:xmlContents = Import-Clixml $xmlLocation -ErrorAction Stop
    }
    catch {
        $msg = $_.Exception
        $line = $_.InvocationInfo.ScriptLineNumber
        writeToLog F "Failed to import xml, due to:`r`n`t$($msg.Message)"
        writeToLog V "This occurred on line number: $line"
        writeToLog V "Status:`r`n`t$($msg.Status)`r`nResponse:`r`n`t$($msg.Response)`r`nInner Exception:`r`n`t$($msg.InnerException)`r`n`r`nHResult: $($msg.HResult)`r`n`r`nTargetSite and StackTrace:`r`n$($msg.TargetSite)`r`n$($msg.StackTrace)`r`n"
        writeToLog F "Failing script."
        postRuntime
        Exit 1001
    }

    $xmlContentCase = ($xmlContents -like "*$caseNumber*")
    $xmlContentLength = $xmlContentCase.length

    writeToLog V "Debug xml contents:`r`n`t $xmlContentCase"
    writeToLog V "Length with case number: $xmlContentLength"

    # Check if case number is present first
    If (($xmlContents -like "*$caseNumber*").length -eq 0) {
        writeToLog W "The provided case number ($caseNumber) is not an approved ticket."
        writeToLog W "Feature Cleanup will not occur."
        
        Remove-Item $xmlLocation -Force -ErrorAction SilentlyContinue
        postRuntime
        Exit 0
    } Else {
        writeToLog I "Provided case number was detected in the xml file."
    }

    $xmlCaseTimestamp = ((($xmlContents -like "*$caseNumber*") -split ";")[-4] -split "=")[1]
    $xmlCaseExpiry = ((((($xmlContents -like "*$caseNumber*") -split ";")[-2] -split "=")[1]) -split "}")[0]
    $expiryState =  (((((($xmlContents -like "*$caseNumber*") -split ";")[-1] -split "=")))[1] -split "}")[0]
    $script:xmlCaseFeature = ((((($xmlContents -like "*$caseNumber*") -split ";")[-3] -split "=")[1]) -split "}")[0]

    writeToLog V "Date the case was added: $xmlCaseTimestamp"
    writeToLog V "Expiry date of the case request: $xmlCaseExpiry"
    writeToLog V "Feature selected to cleanup: $xmlCaseFeature"

    $currentDate = Get-Date

    writeToLog V "Current Date: $currentDate"

    writeToLog V "Expiration State determined as: $expiryState"
    writeToLog I "Cleanup request is approved, the removal of `"$xmlCaseFeature`" will now take place."
    <#
    If ($expiryState -eq "TRUE") {
        writeToLog V "Expiration State determined as: $expiryState"
        writeToLog F "Case record has expired."
        writeToLog F "If you require the cleanup script again for `"$xmlCaseFeature`", please reach out to Technical Support."
        writeToLog F "Failing script."

        Remove-Item $xmlLocation -Force -ErrorAction SilentlyContinue
        postRuntime
        Exit 1001
    } ElseIf ($expiryState -eq "FALSE") {
        writeToLog V "Expiration State determined as: $expiryState"
        writeToLog I "Cleanup request is approved, the removal of `"$xmlCaseFeature`" will now take place."
    } Else {
        writeToLog F "Failed to evaluate expiry status."
        writeToLog F "Expiration State: $expiryState"
        writeToLog F "Failing script."
        postRuntime
        Exit 1001
    }
    #>
    
    postRuntime
    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function downloadScript() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    switch -regex -Wildcard ($xmlCaseFeature) {
        "PME" {
            $featureToCleanup = "PME"
            $script:scriptName = "PMECleanup.ps1"
        }
        "Take Control" {
            $featureToCleanup = "Take Control"
            $script:scriptName = "TakeControlCleanup.ps1"
        }
        "Managed Antivirus - BitDefender" {
            $featureToCleanup = "MAV"
            $script:scriptName = "MAVCleanup.ps1"
        }
        "AV Defender"  {
            $featureToCleanup = "AVD"
            $script:scriptName = "avdCleanup.ps1"
        }
        "EDR"  {
            $featureToCleanup = "EDR"
            $script:scriptName = "EDRCleanup.ps1"
        }
        "N-central Windows Agent"  {
            $featureToCleanup = "NCAgent"
            $script:scriptName = "WindowsAgentCleanup.ps1"
        }
        "N-sight RMM (Advanced Monitoring Agent)"  {
            $featureToCleanup = "N-sightRMM"
            $script:scriptName = "N-sightRMMCleanup.ps1"
        }
        Default {
            $featureToCleanup = $null
        }
    }

    writeToLog I "Feature Selected:`r`n`t$featureToCleanup"

    $encryptedString = "JABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAA9ACAAIgBDADoAXABQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXABNAHMAcABQAGwAYQB0AGYAbwByAG0AXABUAGUAYwBoACAAVAByAGkAYgBlAHMAXABGAGUAYQB0AHUAcgBlACAAQwBsAGUAYQBuAHUAcAAgAFUAdABpAGwAaQB0AHkAXABkAGUAYgB1AGcALgBsAG8AZwAiAAoAJABsAG8AZwBGAG8AbABkAGUAcgAgAD0AIAAiAEMAOgBcAFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAE0AcwBwAFAAbABhAHQAZgBvAHIAbQBcAFQAZQBjAGgAIABUAHIAaQBiAGUAcwBcAEYAZQBhAHQAdQByAGUAIABDAGwAZQBhAG4AdQBwACAAVQB0AGkAbABpAHQAeQBcACIACgAKAHQAcgB5ACAAewAKACAAIAAgACAAJABzAGUAbABlAGMAdABlAGQARgBlAGEAdAB1AHIAZQAgAD0AIAAoAEcAZQB0AC0AQwBvAG4AdABlAG4AdAAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACkAWwAtADEAXQAuAFIAZQBwAGwAYQBjAGUAKAAiAGAAdAAiACwAIAAiACIAKQAKAH0ACgBjAGEAdABjAGgAIAB7AAoAIAAgACAAIAAkAG0AcwBnACAAPQAgACQAXwAuAEUAeABjAGUAcAB0AGkAbwBuAAoAIAAgACAAIAAkAGwAaQBuAGUAIAA9ACAAJABfAC4ASQBuAHYAbwBjAGEAdABpAG8AbgBJAG4AZgBvAC4AUwBjAHIAaQBwAHQATABpAG4AZQBOAHUAbQBiAGUAcgAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEYAYQBpAGwAZQBkACAAdABvACAAcgBlAGEAZAAgAGwAbwBnACAAZgBpAGwAZQAsACAAZAB1AGUAIAB0AG8AOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAE0AZQBzAHMAYQBnAGUAKQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFQAaABpAHMAIABvAGMAYwB1AHIAcgBlAGQAIABvAG4AIABsAGkAbgBlACAAbgB1AG0AYgBlAHIAOgAgACQAbABpAG4AZQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAdABhAHQAdQBzADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBTAHQAYQB0AHUAcwApAGAAcgBgAG4AUgBlAHMAcABvAG4AcwBlADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBSAGUAcwBwAG8AbgBzAGUAKQBgAHIAYABuAEkAbgBuAGUAcgAgAEUAeABjAGUAcAB0AGkAbwBuADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBJAG4AbgBlAHIARQB4AGMAZQBwAHQAaQBvAG4AKQBgAHIAYABuAGAAcgBgAG4ASABSAGUAcwB1AGwAdAA6ACAAJAAoACQAbQBzAGcALgBIAFIAZQBzAHUAbAB0ACkAYAByAGAAbgBgAHIAYABuAFQAYQByAGcAZQB0AFMAaQB0AGUAIABhAG4AZAAgAFMAdABhAGMAawBUAHIAYQBjAGUAOgBgAHIAYABuACQAKAAkAG0AcwBnAC4AVABhAHIAZwBlAHQAUwBpAHQAZQApAGAAcgBgAG4AJAAoACQAbQBzAGcALgBTAHQAYQBjAGsAVAByAGEAYwBlACkAYAByAGAAbgAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKAAoAIAAgACAAIABSAGUAbQBvAHYAZQAtAEkAdABlAG0AIAAkAHMAYwByAGkAcAB0AEwAbwBjAGEAdABpAG8AbgAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoAfQAKAAoAcwB3AGkAdABjAGgAIAAtAHIAZQBnAGUAeAAgAC0AVwBpAGwAZABjAGEAcgBkACAAKAAkAHMAZQBsAGUAYwB0AGUAZABGAGUAYQB0AHUAcgBlACkAIAB7AAoAIAAgACAAIAAiAFAATQBFACIAIAB7AAoAIAAgACAAIAAgACAAIAAgACQAZgBlAGEAdAB1AHIAZQBUAG8AQwBsAGUAYQBuAHUAcAAgAD0AIAAiAFAATQBFACIACgAgACAAIAAgACAAIAAgACAAJABzAGMAcgBpAHAAdABOAGEAbQBlACAAPQAgACIAUABNAEUAQwBsAGUAYQBuAHUAcAAuAHAAcwAxACIACgAgACAAIAAgACAAIAAgACAAJABzAGMAcgBpAHAAdABVAFIATAAgAD0AIAAiAGgAdAB0AHAAcwA6AC8ALwBzADMALgBhAG0AYQB6AG8AbgBhAHcAcwAuAGMAbwBtAC8AbgBlAHcALQBzAHcAbQBzAHAALQBuAGUAdAAtAHMAdQBwAHAAbwByAHQAZgBpAGwAZQBzAC8AUABlAHIAbQBhAG4AZQBuAHQARgBpAGwAZQBzAC8ARgBlAGEAdAB1AHIAZQBDAGwAZQBhAG4AdQBwAC8AQwBsAGUAYQBuAHUAcAAlADIAMABTAGMAcgBpAHAAdABzAC8AUABNAEUAQwBsAGUAYQBuAHUAcAAuAHAAcwAxACIACgAgACAAIAAgAH0ACgAgACAAIAAgACIAVABhAGsAZQAgAEMAbwBuAHQAcgBvAGwAIgAgAHsACgAgACAAIAAgACAAIAAgACAAJABmAGUAYQB0AHUAcgBlAFQAbwBDAGwAZQBhAG4AdQBwACAAPQAgACIAVABhAGsAZQAgAEMAbwBuAHQAcgBvAGwAIgAKACAAIAAgACAAIAAgACAAIAAkAHMAYwByAGkAcAB0AE4AYQBtAGUAIAA9ACAAIgBUAGEAawBlAEMAbwBuAHQAcgBvAGwAQwBsAGUAYQBuAHUAcAAuAHAAcwAxACIACgAgACAAIAAgACAAIAAgACAAJABzAGMAcgBpAHAAdABVAFIATAAgAD0AIAAiAGgAdAB0AHAAcwA6AC8ALwBzADMALgBhAG0AYQB6AG8AbgBhAHcAcwAuAGMAbwBtAC8AbgBlAHcALQBzAHcAbQBzAHAALQBuAGUAdAAtAHMAdQBwAHAAbwByAHQAZgBpAGwAZQBzAC8AUABlAHIAbQBhAG4AZQBuAHQARgBpAGwAZQBzAC8ARgBlAGEAdAB1AHIAZQBDAGwAZQBhAG4AdQBwAC8AQwBsAGUAYQBuAHUAcAAlADIAMABTAGMAcgBpAHAAdABzAC8AVABhAGsAZQBDAG8AbgB0AHIAbwBsAEMAbABlAGEAbgB1AHAALgBwAHMAMQAiAAoAIAAgACAAIAB9AAoAIAAgACAAIAAiAE0AYQBuAGEAZwBlAGQAIABBAG4AdABpAHYAaQByAHUAcwAgAC0AIABCAGkAdABEAGUAZgBlAG4AZABlAHIAIgAgAHsACgAgACAAIAAgACAAIAAgACAAJABmAGUAYQB0AHUAcgBlAFQAbwBDAGwAZQBhAG4AdQBwACAAPQAgACIATQBBAFYAIgAKACAAIAAgACAAIAAgACAAIAAkAHMAYwByAGkAcAB0AE4AYQBtAGUAIAA9ACAAIgBNAEEAVgBDAGwAZQBhAG4AdQBwAC4AcABzADEAIgAKACAAIAAgACAAIAAgACAAIAAkAHMAYwByAGkAcAB0AFUAUgBMACAAPQAgACIAaAB0AHQAcABzADoALwAvAHMAMwAuAGEAbQBhAHoAbwBuAGEAdwBzAC4AYwBvAG0ALwBuAGUAdwAtAHMAdwBtAHMAcAAtAG4AZQB0AC0AcwB1AHAAcABvAHIAdABmAGkAbABlAHMALwBQAGUAcgBtAGEAbgBlAG4AdABGAGkAbABlAHMALwBGAGUAYQB0AHUAcgBlAEMAbABlAGEAbgB1AHAALwBDAGwAZQBhAG4AdQBwACUAMgAwAFMAYwByAGkAcAB0AHMALwBNAEEAVgBDAGwAZQBhAG4AdQBwAC4AcABzADEAIgAKACAAIAAgACAAfQAKACAAIAAgACAAIgBBAFYARAAiACAAIAB7AAoAIAAgACAAIAAgACAAIAAgACQAZgBlAGEAdAB1AHIAZQBUAG8AQwBsAGUAYQBuAHUAcAAgAD0AIAAiAEEAVgBEACIACgAgACAAIAAgACAAIAAgACAAJABzAGMAcgBpAHAAdABOAGEAbQBlACAAPQAgACIAQQBWAEQAQwBsAGUAYQBuAHUAcAAuAHAAcwAxACIACgAgACAAIAAgACAAIAAgACAAJABzAGMAcgBpAHAAdABVAFIATAAgAD0AIAAiAGgAdAB0AHAAcwA6AC8ALwBzADMALgBhAG0AYQB6AG8AbgBhAHcAcwAuAGMAbwBtAC8AbgBlAHcALQBzAHcAbQBzAHAALQBuAGUAdAAtAHMAdQBwAHAAbwByAHQAZgBpAGwAZQBzAC8AUABlAHIAbQBhAG4AZQBuAHQARgBpAGwAZQBzAC8ARgBlAGEAdAB1AHIAZQBDAGwAZQBhAG4AdQBwAC8AQwBsAGUAYQBuAHUAcAAlADIAMABTAGMAcgBpAHAAdABzAC8AYQB2AGQAQwBsAGUAYQBuAHUAcAAuAHAAcwAxACIACgAgACAAIAAgAH0ACgAgACAAIAAgACIARQBEAFIAIgAgACAAewAKACAAIAAgACAAIAAgACAAIAAkAGYAZQBhAHQAdQByAGUAVABvAEMAbABlAGEAbgB1AHAAIAA9ACAAIgBFAEQAUgAiAAoAIAAgACAAIAAgACAAIAAgACQAcwBjAHIAaQBwAHQATgBhAG0AZQAgAD0AIAAiAEUARABSAEMAbABlAGEAbgB1AHAALgBwAHMAMQAiAAoAIAAgACAAIAAgACAAIAAgACQAcwBjAHIAaQBwAHQAVQBSAEwAIAA9ACAAIgBoAHQAdABwAHMAOgAvAC8AcwAzAC4AYQBtAGEAegBvAG4AYQB3AHMALgBjAG8AbQAvAG4AZQB3AC0AcwB3AG0AcwBwAC0AbgBlAHQALQBzAHUAcABwAG8AcgB0AGYAaQBsAGUAcwAvAFAAZQByAG0AYQBuAGUAbgB0AEYAaQBsAGUAcwAvAEYAZQBhAHQAdQByAGUAQwBsAGUAYQBuAHUAcAAvAEMAbABlAGEAbgB1AHAAJQAyADAAUwBjAHIAaQBwAHQAcwAvAEUARABSAEMAbABlAGEAbgB1AHAALgBwAHMAMQAiAAoAIAAgACAAIAB9AAoAIAAgACAAIAAiAE4AQwBBAGcAZQBuAHQAIgAgACAAewAKACAAIAAgACAAIAAgACAAIAAkAGYAZQBhAHQAdQByAGUAVABvAEMAbABlAGEAbgB1AHAAIAA9ACAAIgBOAEMAQQBnAGUAbgB0ACIACgAgACAAIAAgACAAIAAgACAAJABzAGMAcgBpAHAAdABOAGEAbQBlACAAPQAgACIAVwBpAG4AZABvAHcAcwBBAGcAZQBuAHQAQwBsAGUAYQBuAHUAcAAuAHAAcwAxACIACgAgACAAIAAgACAAIAAgACAAJABzAGMAcgBpAHAAdABVAFIATAAgAD0AIAAiAGgAdAB0AHAAcwA6AC8ALwBzADMALgBhAG0AYQB6AG8AbgBhAHcAcwAuAGMAbwBtAC8AbgBlAHcALQBzAHcAbQBzAHAALQBuAGUAdAAtAHMAdQBwAHAAbwByAHQAZgBpAGwAZQBzAC8AUABlAHIAbQBhAG4AZQBuAHQARgBpAGwAZQBzAC8ARgBlAGEAdAB1AHIAZQBDAGwAZQBhAG4AdQBwAC8AQwBsAGUAYQBuAHUAcAAlADIAMABTAGMAcgBpAHAAdABzAC8AVwBpAG4AZABvAHcAcwBBAGcAZQBuAHQAQwBsAGUAYQBuAHUAcAAuAHAAcwAxACIACgAgACAAIAAgAH0ACgAgACAAIAAgACIATgAtAHMAaQBnAGgAdABSAE0ATQAiACAAIAB7AAoAIAAgACAAIAAgACAAIAAgACQAZgBlAGEAdAB1AHIAZQBUAG8AQwBsAGUAYQBuAHUAcAAgAD0AIAAiAE4ALQBzAGkAZwBoAHQAUgBNAE0AIgAKACAAIAAgACAAIAAgACAAIAAkAHMAYwByAGkAcAB0AE4AYQBtAGUAIAA9ACAAIgBOAC0AcwBpAGcAaAB0AFIATQBNAEMAbABlAGEAbgB1AHAALgBwAHMAMQAiAAoAIAAgACAAIAAgACAAIAAgACQAcwBjAHIAaQBwAHQAVQBSAEwAIAA9ACAAIgBoAHQAdABwAHMAOgAvAC8AcwAzAC4AYQBtAGEAegBvAG4AYQB3AHMALgBjAG8AbQAvAG4AZQB3AC0AcwB3AG0AcwBwAC0AbgBlAHQALQBzAHUAcABwAG8AcgB0AGYAaQBsAGUAcwAvAFAAZQByAG0AYQBuAGUAbgB0AEYAaQBsAGUAcwAvAEYAZQBhAHQAdQByAGUAQwBsAGUAYQBuAHUAcAAvAEMAbABlAGEAbgB1AHAAJQAyADAAUwBjAHIAaQBwAHQAcwAvAE4ALQBzAGkAZwBoAHQAUgBNAE0AQwBsAGUAYQBuAHUAcAAuAHAAcwAxACIACgAgACAAIAAgAH0ACgAgACAAIAAgAEQAZQBmAGEAdQBsAHQAIAB7AAoAIAAgACAAIAAgACAAIAAgACQAZgBlAGEAdAB1AHIAZQBUAG8AQwBsAGUAYQBuAHUAcAAgAD0AIAAkAG4AdQBsAGwACgAgACAAIAAgAH0ACgB9AAoACgAkAHMAYwByAGkAcAB0AEwAbwBjAGEAdABpAG8AbgAgAD0AIAAkAGwAbwBnAEYAbwBsAGQAZQByACAAKwAgACQAcwBjAHIAaQBwAHQATgBhAG0AZQAKAAoAdAByAHkAIAB7AAoAIAAgACAAIABSAGUAbQBvAHYAZQAtAEkAdABlAG0AIAAkAHMAYwByAGkAcAB0AEwAbwBjAGEAdABpAG8AbgAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoAfQAKAGMAYQB0AGMAaAAgAHsACgB9AAoACgAkAHcAYwAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AAoACgB0AHIAeQAgAHsACgAgACAAIAAgACQAdwBjAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAkAHMAYwByAGkAcAB0AFUAUgBMACwAJABzAGMAcgBpAHAAdABMAG8AYwBhAHQAaQBvAG4AKQAKAH0ACgBjAGEAdABjAGgAIAB7AAoAIAAgACAAIAAkAG0AcwBnACAAPQAgACQAXwAuAEUAeABjAGUAcAB0AGkAbwBuAAoAIAAgACAAIAAkAGwAaQBuAGUAIAA9ACAAJABfAC4ASQBuAHYAbwBjAGEAdABpAG8AbgBJAG4AZgBvAC4AUwBjAHIAaQBwAHQATABpAG4AZQBOAHUAbQBiAGUAcgAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEYAYQBpAGwAZQBkACAAdABvACAAZABvAHcAbgBsAG8AYQBkACAAYwBsAGUAYQBuAHUAcAAgAHMAYwByAGkAcAB0ACwAIABkAHUAZQAgAHQAbwA6AGAAcgBgAG4AYAB0ACQAKAAkAG0AcwBnAC4ATQBlAHMAcwBhAGcAZQApACIAIAB8ACAATwB1AHQALQBmAGkAbABlACAAJABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAAtAEEAcABwAGUAbgBkACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoAIAAgACAAIABXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACIAVABoAGkAcwAgAG8AYwBjAHUAcgByAGUAZAAgAG8AbgAgAGwAaQBuAGUAIABuAHUAbQBiAGUAcgA6ACAAJABsAGkAbgBlACIAIAB8ACAATwB1AHQALQBmAGkAbABlACAAJABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAAtAEEAcABwAGUAbgBkACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoAIAAgACAAIABXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACIAUwB0AGEAdAB1AHMAOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAFMAdABhAHQAdQBzACkAYAByAGAAbgBSAGUAcwBwAG8AbgBzAGUAOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAFIAZQBzAHAAbwBuAHMAZQApAGAAcgBgAG4ASQBuAG4AZQByACAARQB4AGMAZQBwAHQAaQBvAG4AOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAEkAbgBuAGUAcgBFAHgAYwBlAHAAdABpAG8AbgApAGAAcgBgAG4AYAByAGAAbgBIAFIAZQBzAHUAbAB0ADoAIAAkACgAJABtAHMAZwAuAEgAUgBlAHMAdQBsAHQAKQBgAHIAYABuAGAAcgBgAG4AVABhAHIAZwBlAHQAUwBpAHQAZQAgAGEAbgBkACAAUwB0AGEAYwBrAFQAcgBhAGMAZQA6AGAAcgBgAG4AJAAoACQAbQBzAGcALgBUAGEAcgBnAGUAdABTAGkAdABlACkAYAByAGAAbgAkACgAJABtAHMAZwAuAFMAdABhAGMAawBUAHIAYQBjAGUAKQBgAHIAYABuACIAIAB8ACAATwB1AHQALQBmAGkAbABlACAAJABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAAtAEEAcABwAGUAbgBkACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoACgAgACAAIAAgAFIAZQBtAG8AdgBlAC0ASQB0AGUAbQAgACQAcwBjAHIAaQBwAHQATABvAGMAYQB0AGkAbwBuACAALQBGAG8AcgBjAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUACgB9AA=="

    Powershell.exe -EncodedCommand $encryptedString

    $script:scriptLocation = $logFolder + $scriptName

    If (!(Test-Path $scriptLocation)) {
        writeToLog F "The cleanup utilty for $xmlCaseFeature was not found on the device."
        writeToLog F "Failing script."
        postRuntime
        Exit 1001
    }

    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function triggerCleanup() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    $script:scriptLocation = $logFolder + $scriptName
    Invoke-Expression "& ""$scriptLocation"" -caseNumber $caseNumber"

    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function postRuntime() {
    try {
        Remove-Item $xmlLocation -Force -ErrorAction SilentlyContinue
    }
    catch {
    }
    try {
        Remove-Item $versionLocation -Force -ErrorAction SilentlyContinue
    }
    catch {
    }
    try {
        Remove-Item "$logFolder*.ps1" -Force -ErrorAction SilentlyContinue
    }
    catch {
    }
}

function writeToLog($state, $message) {

    $script:timestamp = "[{0:dd/MM/yy} {0:HH:mm:ss}]" -f (Get-Date)

    switch -regex -Wildcard ($state) {
        "I" {
            $state = "INFO"
            $colour = "Cyan"
        }
        "E" {
            $state = "ERROR"
            $colour = "Red"
        }
        "W" {
            $state = "WARNING"
            $colour = "Yellow"
        }
        "F"  {
            $state = "FAILURE"
            $colour = "Red"
        }
        "C"  {
            $state = "COMPLETE"
            $colour = "Green"
        }
        "V"  {
            If ($verboseMode -eq $true) {
                $state = "VERBOSE"
                $colour = "Magenta"
            } Else {
                return
            }
        }
        ""  {
            $state = "INFO"
        }
        Default {
            $state = "INFO"
        }
    }

    Write-Host "$($timeStamp) - [$state]: $message" -ForegroundColor $colour
    Write-Output "$($timeStamp) - [$state]: $message" | Out-file $logFilePath -Append -ErrorAction SilentlyContinue
}

function main() {
    setupLogging
    validateUserInput
    initialSetup
    confirmRunningLatest
    downloadXml
    validateCaseNumber
    downloadScript
    triggerCleanup
    postRuntime
}
main