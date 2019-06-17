Function Get-ToLower {
    # Best if used with an alias like "gtl" to make it even faster. 
    Param($string)
    $string.tolower()
}

Function Add-LocalAdminMember {
    param(
    $computer,
    $SecurityGroup    
        )
foreach ($i in $computer) {
        $OS = Invoke-command -ScriptBlock {Get-WmiObject -Class Win32_OperatingSystem} -ComputerName $i
        foreach ($Group in $SecurityGroup) {
            if ($OS.Version -match "10.0*") {
                 Invoke-Command -scriptblock {Add-LocalGroupMember -group "Administrators" -Member ($env:USERDOMAIN + "\" + $Using:Group)} -ComputerName $i
            }
            elseif ($OS.Version -match "6.3.*") {
                Invoke-Command -scriptblock {([adsi]"WinNT://./Administrators,group").Add("WinNT://$env:USERDOMAIN/$using:Group,group")} -ComputerName $i
            }
        }
    }
}

Function Remove-LocalAdminMember {
    param(
    $computer,
    $SecurityGroup    
        )

BEGIN {
    $array = @()
}
PROCESS {
    foreach ($i in $computer) {
            $OS = Invoke-command -ScriptBlock {Get-WmiObject -Class Win32_OperatingSystem} -ComputerName $i
            foreach ($Group in $SecurityGroup) {
                TRY { 
                if ($OS.Version -match "10.0*") {
                     Invoke-Command -scriptblock {Remove-LocalGroupMember -group "Administrators" -Member ($env:USERDOMAIN + "\" + $Using:Group)} -ComputerName $i
                     $success = $true
                }
                elseif ($OS.Version -match "6.3.*") {
                    Invoke-Command -scriptblock {([adsi]"WinNT://./Administrators,group").remove("WinNT://$env:USERDOMAIN/$using:Group,group")} -ComputerName $i
                    $success = $true
                }
                } CATCH {
                    $success = $false 
                } 
        
            }
            $hash = @{
                Computer = $i
                Success = $success
            }
            $obj = New-Object -TypeName psobject -ArgumentList $hash
            $array += $obj
        }
}

END {
    $array
}
}

Function Get-TLSSuport {
    param($targets)
BEGIN{ 
    $port = 443
    $protocols = "ssl2","ssl3","tls_1.0","tls_1.1","tls_1.2","tls_1.3"
    $array = @()
} 

PROCESS{
    foreach ($target in $targets) { 
        $obj = New-Object -TypeName PSObject
        $obj | Add-Member -MemberType NoteProperty -Name Target -Value $target
        foreach ($procotol in $protocols) {
            switch ($procotol) {
                "ssl2" {$binVal = 12}
                "ssl3" {$binVal = 48}
                "tls_1.0" {$binVal = 192}
                "tls_1.1" {$binVal = 768}
                "tls_1.2" {$binVal = 3072}
                "tls_1.3" {$binVal = 12288}
            }
            $TcpClient = New-Object Net.Sockets.TcpClient
            $TcpClient.Connect($target, $port)
            $SslStream = New-Object Net.Security.SslStream -ArgumentList @($TcpClient.GetStream(), $true, [System.Net.Security.RemoteCertificateValidationCallback]{ $true })
            $SslStream.ReadTimeout = 3000
            $SslStream.WriteTimeout = 3000
            TRY { 
                $SslStream.AuthenticateAsClient($target,$null,$binVal,$false)
                $status = $true
            } CATCH { 
                $null = $_
                $status = $false
            }
            $obj | Add-Member -MemberType NoteProperty -Name $procotol -Value $status
            $SslStream.Dispose()
            $TcpClient.Dispose()
        }
        $array += $obj
    }
}
END {
    $array
}
}
function Get-SSLCertificate {
param (
    [Parameter(Mandatory=$true)]
    [string]
    $ComputerName,

    [int]
    $Port = 443
)

$Certificate = $null
$TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
try {

    $TcpClient.Connect($ComputerName, $Port)
    $TcpStream = $TcpClient.GetStream()

    $Callback = { param($sender, $cert, $chain, $errors) return $true }

    $SslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($TcpStream, $true, $Callback)
    try {

        $SslStream.AuthenticateAsClient('')
        $Certificate = $SslStream.RemoteCertificate

    } finally {
        $SslStream.Dispose()
    }

} finally {
    $TcpClient.Dispose()
}

if ($Certificate) {
    if ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        $Certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $Certificate
    }

    Write-Output $Certificate
}
}

function Start-PSAdmin {
    param([switch]$noexit)
    Set-Location C:\
    start-process powershell.exe -Credential (Get-Credential)
    if (!($noexit)) {
        exit
    }
}

function Test-RDP {
    param (
    $IP,
    $Port = 3389,
    [int]$count = 3,
    [switch]$quiet,
    [switch]$loop) 
BEGIN{
}
PROCESS{
    $b = $count
    $Success = $false 
    for ($i = 0; $i -lt $b; $i ++) {
        $socket = New-Object System.Net.Sockets.TcpClient
        if ($socket.ConnectAsync($IP,$port).Wait('2000')) {
            $b = $i
            $i++
            $Success = $True
       } else {
        if (!($quiet)) {
            Write-Warning "Failed to Connect to $IP on $Port"
        }
       }
       $socket.Dispose()
       if ($loop) {
        $b = $i + 2
        }
    }

    if ($Success) {
        if (!($quiet)) {
            Write-Host "Succesfully Connected to $IP on $Port" -ForegroundColor Green
        }
    }
            
}
END{
    if ($quiet) { 
        $Success  
    }
}
}

function Resolve-NonYetExistentDnsName {
    #Requires -Version 3.0
    #Requires -Modules DnsClient
    #Shout-out to a friend for writing this. NOT ME! 
    [CmdletBinding()]
    [OutputType([Microsoft.DnsClient.Commands.DnsRecord[]])]
    Param (
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [int]$Timeout = 60,
        [int]$Retries = 5
    )

    $ErrorActionPreference = 'Stop'
    try {
        $Counter = 0
        do {
            try {
                Resolve-DnsName -Name $ComputerName
                break
            }
            catch {
                if ($_.Exception.NativeErrorCode -eq 9003) {
                    Start-Sleep -Seconds $Timeout
                    $Counter++
                }
                else {
                    $PSCmdlet.ThrowTerminatingError($_)
                }
            }
        }
        while ($Counter -lt $Retries)

        if ($Counter -ge $Retries) {
            $Message = 'The DNS name {0} still does not exist after {1} tries' -f $ComputerName, $Retries
            $PSCmdlet.ThrowTerminatingError((New-Object -TypeName 'System.Management.Automation.ErrorRecord' -ArgumentList ((New-Object -TypeName 'System.ComponentModel.Win32Exception' -ArgumentList $Message), 'ERROR_TIMEOUT,Microsoft.DnsClient.Commands.ResolveDnsName', [System.Management.Automation.ErrorCategory]::OperationTimeout, $null)))
        }
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

Function Set-SHAdditionalDisk {
    param(
    [parameter(mandatory=$true)]
        $servername,
        $DriveLetter="D",
        [switch]$SQL) 
    
BEGIN{
    if (!($Global:credentials)) { 
        $Global:credentials = Get-Credential
    }
    Try {
        $ostype = Get-VM $servername -ErrorAction Stop
    } Catch {
        $null = $_ 
    }
    if ($SQL) {
        $allocationUnit = 65536
    } else { 
        $allocationUnit = 4096
    }
}

PROCESS{
    if ($ostype.ExtensionData.Guest.GuestFullName -match '2012') {
        $OldConfirmPreference = $confirmpreference
        Invoke-Command -ComputerName $servername -ScriptBlock {$confirmpreference = 'none'} -Credential $Global:credentials
        Invoke-Command -ComputerName $servername -ScriptBlock {Get-Disk | where {$_.PartitionStyle -eq "RAW"} | Initialize-Disk -PassThru | New-Partition -UseMaximumSize -DriveLetter $using:DriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "New Volume" -AllocationUnitSize $using:allocationUnit -force} -Credential $Global:credentials
        Invoke-Command -ComputerName $servername -ScriptBlock {$confirmpreference = $using:OldConfirmPreference} -Credential $Global:credentials
    } else {
        Invoke-Command -ComputerName $servername -ScriptBlock {Get-Disk | where {$_.PartitionStyle -eq "RAW"} | Initialize-Disk -PassThru | New-Volume -FriendlyName "New Volume" -FileSystem NTFS -AllocationUnitSize $using:allocationUnit -DriveLetter $using:DriveLetter} -Credential $Global:credentials
        }
}

END{}

}


Function Remove-SHCreds {
    TRY { 
        Remove-Variable credentials,IBCreds -Scope global
    } CATCH {
        $null = $_ 
    }       

}

Function Install-SHNet35 { 
    param([parameter(mandatory=$true)]$ServerName,
    [switch]$quiet
    )

BEGIN {
    if (!$Global:credentials) {
        $Global:credentials = Get-credential
    }
    $service = Get-WindowsFeature -Name NET-Framework-Core -ComputerName $servername
    if ($service.InstallState -eq "Installed") {
        if (!($quiet)) {
            Write-Warning ".NET 3.5 Already installed!"
            CONTINUE
        }
    }
    $osVersion = Get-WMIobject -Class Win32_OperatingSystem -ComputerName $ServerName
    if ($osVersion.caption -match "2016") {
        $sourcePath = <# Insert source path for SOURCES (winSXS) #>
    } 
    $destinationPath = "\\$servername\C$\Download\"
}

PROCESS{
    if ($osVersion.caption -match "2016") {
        Write-Progress -Activity "Copying Items"
        Copy-Item -path $sourcePath -Destination $destinationPath -Recurse
        Write-Progress -Activity "Installing .NET 3.5"
        Add-WindowsFeature -Name NET-Framework-Core -IncludeManagementTools -Source C:\Download\sources\sxs\ -ComputerName $ServerName
        Write-Progress -Activity "Removing Items"
        Remove-Item -Path ($destinationPath + "sources\") -Recurse -Force
    } else { 
        Write-Progress -Activity "Installing .NET 3.5"
        Add-WindowsFeature -Name NET-Framework-Core -IncludeManagementTools -ComputerName $ServerName
    }

}

END {
    Write-Progress -Completed -Activity "Completed"
}

}

Function Install-SHSnapDrive {
    param([parameter(mandatory=$true)]$ServerName)
BEGIN {
    $sourcePath = <# Insert Path to Snapdrive location #>
    $destinationPath = "\\$servername\C$\Download\"
    Add-LocalAdminMember -computer $servername -SecurityGroup <# Service Account USERNAME #>
    $svcAcc = Get-Credential -Message "Enter Password for Service Account" -UserName <# USERNAME #> 
    $tpAcc = Get-Credential -Message "Enter Transport Proxy Password" -UserName <# USERNAME #> 
    $ipInfo = Resolve-DnsName -Name $servername -Type A

    $key1 = [byte[]] (1..16)
    $key2 = [byte[]] (1..16)

    $svchash = $svcAcc.password | ConvertFrom-SecureString -Key $key1
    $tphash = $tpAcc.password | ConvertFrom-SecureString -Key $key2
    $svcraw = $svchash | ConvertTo-SecureString -Key $key1
    $tpraw = $tphash | ConvertTo-SecureString -Key $key2
    $svcstr = [System.Runtime.InteropServices.Marshal]::SecureStringtoBSTR($svcraw)
    $tpstr = [System.Runtime.InteropServices.Marshal]::SecureStringtoBSTR($tpraw)
    $svcplain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($svcstr)
    $tpplain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($tpstr)
    $svcUser = $svcAcc.username
    $tpUser = $tpAcc.UserName
}

PROCESS {
    Install-SHNet35 -ServerName $ServerName -quiet
    Write-Progress -Activity "Copying Items"
    Copy-Item -path $sourcePath -Destination $destinationPath -Recurse
    $installScriptBlock = {
        $programPath = "C:\Download\Snapdrive 7.1.5\SnapDrive7.1.5_x64.exe"
        <# Validate Param string, as it is referencing flags that may not be within your installation #> 
        $paramstring = "/s /v`" /qn SILENT_MODE=1 SVCUSERNAME=$using:svcUser SVCUSERPASSWORD=$using:svcplain SVCCONFIRMUSERPASSWORD=$using:svcplain SDW_WEBSRV_TCP_PORT=808 SDW_WEBSRV_HTTP_PORT=4098 TRANSPORT_SETTING_ENABLE=1 TRANSPORT_PRT_SELECTION=3 TRANSPORT_PRT_PORT=443 TRANSPORT_PROTOCOL_LOGON_USERNAME=$using:tpUser TRANSPORT_PROTOCOL_LOGON_PASSWORD=$using:tpplain PREFERRED_STORAGE_SYSTEM_NAME=$using:preferredStorageName PREFERRED_STORAGE_SYSTEM_IP_ADDRESS=$using:preferredStorageIP`""
        $sbParams = [scriptblock]::Create($paramstring)
        Start-Process -FilePath $programPath -ArgumentList $sbParams -Wait
    }
    Write-Progress -Activity "Installing SnapDrive"
    Invoke-Command -ScriptBlock $installScriptBlock -ComputerName $servername
    $configureScriptBlock = {
        Import-Module SnapDrive
        sdcli vsconfig set -IP $using:virtualCenter -user svcnaesx -pwd $using:svcplain
    }
    Write-Progress -Activity "Setting Preferred Management Hosts"
    Invoke-Command -ScriptBlock $configureScriptBlock -ComputerName $servername
       
}

END { 
    Remove-Item -Path "C:\Download\Snapdrive 7.1.5\" -Recurse
    Write-Progress -Activity "Completed" -Completed

}
}


Export-ModuleMember Set-RemoteSharpVM
Export-ModuleMember Test-RDP
Export-ModuleMember Start-PSAdmin
Export-ModuleMember Get-ToLower
Export-ModuleMember Add-LocalAdminMember
Export-ModuleMember Get-SSLCertificate
Export-ModuleMember Get-TLSSuport
Export-ModuleMember Remove-SHCreds
Export-ModuleMember Install-SHNet35
Export-ModuleMember Install-SHSnapDrive
Export-ModuleMember Remove-LocalAdminMember