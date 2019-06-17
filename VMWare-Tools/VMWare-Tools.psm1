function Connect-SHVMWare {
    param(
        [switch]$DMZ,
        [switch]$DMZOnly,
        [switch]$test
        )
BEGIN {
    if (!(Get-Module vmware.vimautomation.core)) {
        Import-Module vmware.vimautomation.core
        }
    if ($DMZ -or $DMZOnly) {
        if (Test-SHVMWareConnection -DMZ) {
            Write-Warning "Already Connected to $($global:DefaultVIServers[0..($($global:DefaultVIServers.count) - 1)])"
            BREAK 
            }
    } else {
            if (Test-SHVMWareConnection) {
            Write-Warning "Already Connected to $($global:DefaultVIServers[0..($($global:DefaultVIServers.count) - 1)])"
            BREAK 
            }
    }

    if ($DMZ) {
        $Servers = <# Insert vCenter FQDNs here #>
    } elseif ($DMZOnly) {
        $Servers = <# Insert vCenter FQDNs here #>
    } else {
        $Servers = <# Insert vCenter FQDNs here #>
    }
}
PROCESS {
    if (!($Global:Credentials)) {
        $Global:Credentials = (Get-Credential -message "Enter Domain Credentials")
    }
    Connect-VIServer -Server $Servers -Credential $Global:Credentials 
}
END{}
}

Function Test-SHVMWareConnection {
#Used to test if there are existing connections to the VMWare servers.
    param([switch]$DMZ)
BEGIN {
    $connectState = $false
}

PROCESS{
    if ($global:DefaultVIServers.IsConnected -and ($global:DefaultVIServers.count -gt 0)) {
        $connectState = $True
        if ($DMZ) { 
            if ($global:DefaultVIServers.count -eq 6) { 
                $connectState = $True
            } else {
                $connectState = $False
            }
        }
    }
    $connectState 
}

END{}
}

Function Get-SVMWRetiredVMs {
BEGIN{
    if (!(Test-SHVMWareConnection)) {
        Connect-SHVMWare
    }
}
PROCESS {
    $retiredVMs = Get-VM -Name *_retired
    Foreach ($i in $retiredVMs) { 
        $poweroff = Get-VIEvent -entity $i | where {$_ -is [VMware.Vim.VmPoweredOffEvent]}
        #Logic for if there are not VIEvents returned
        if ($poweroff) {
            $hash = [ordered]@{
                Name = $i.Name
                Host = $i.VMHost
                DaysOff = (Get-Date).subtract($poweroff[0].CreatedTime).Days
                OffSince = $poweroff[0].CreatedTime
            }
        }else{
            $hash = [ordered]@{
                Name = $i.Name
                Host = $i.VMHost
                DaysOff = [int]999
                OffSince = (get-date).addticks(-((Get-Date).ticks))
            }
        
        }
    New-Object PSObject -Property $hash
    }
}
END{}
}

Function Get-SVMWSimilarVM {
#Used to gather relevant information on a similar VM for when constructing a replacement. 
    param(
    [parameter(mandatory=$true)] $VMName)
BEGIN{
    if (!(Test-SHVMWareConnection)) {
        Connect-SHVMWare
    }
}
PROCESS {
    $info = Get-VM -name $VMName
    $Datastore = Get-Datastore -VM $info
    #Verifies if the datastore that the VM is on is not part of a larger Datastore Cluster or not. 
    if ($Datastore.parentfolder -eq "datastore") {
        $DatastoreInfo = $Datastoreinfo.Name} 
        else {
        $DatastoreInfo = (Get-DatastoreCluster -id $Datastore.ParentFolderID).Name
    }
    $hash = [ordered]@{
        Name = $VMName
        Cluster = $info.VMHost.Parent.Name
        Datastore = $DatastoreInfo
        IP = $info.Guest.IPAddress
    }
    New-Object -TypeName PSOBject -Property $hash
}
END{}
}

Function Get-SVMInfo {
    param(
    [parameter(mandatory=$true)] $VMName,
    [switch]$IPSearch
    )
BEGIN{
    if (!(Test-SHVMWareConnection)) {
        Connect-SHVMWare
    }

    if ($IPSearch) { 
        $VMIPInfo = (Resolve-DnsName $VMName -Server <# Insert DNS Server FQDN Here  #>).IpAddress
    }
}
PROCESS{
    $VMinfo = Get-VM -name $VMName
    $VMMac = $VMinfo | Get-NetworkAdapter

    if ($VMinfo.ExtensionData.Guest.GuestFullName -match 'Windows') {
        if ($IPSearch) { 
            $OSInfo = Invoke-Command -ScriptBlock {(Get-wmiObject Win32_networkAdapterConfiguration| ?{$_.IPEnabled})} -ComputerName $VMIPInfo -Credential $Global:credentials
        } else {
            $OSInfo = Invoke-Command -ScriptBlock {(Get-wmiObject Win32_networkAdapterConfiguration| ?{$_.IPEnabled})} -ComputerName $VMName -Credential $Global:credentials
        }
        $hash = [Ordered]@{
            VMName = $VMName.tolower()
            VMHost = $VMinfo.VMHost
            VMMAC = $VMMac.MacAddress
            VMIP = $OSInfo.IPaddress[0]
            VMGateway = $OSInfo.DefaultIPGateway[0]
        }
    } else { 
        $regexPattern = "(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
        $OSInfo = [regex]::Match($VMinfo.Guest.IPAddress,$regexPattern).value
        $IPInfo = Find-IPPIPInfo -IP $OSInfo
        $hash = [Ordered]@{
            VMName = $VMName.tolower()
            VMHost = $VMinfo.VMHost
            VMMAC = $VMMac.MacAddress
            VMIP = $OSInfo
            VMGateway = $IPInfo.Gateway
        }
    }

    New-Object -TypeName psobject -Property $hash
}

END{}
}

function Get-SVMWActiveProfiles {
    param($vCenter)

$profiles = Get-VMHostprofile -server $vCenter | where {$_.ExtensionData.Entity}
foreach ($i in $profiles) {
    if ($i.ExtensionData.Entity) {
        foreach ($a in $i.ExtensionData.Entity) {
            $hash = @{
                Profile = $i.Name 
                Host = (Get-VMHost -Id ($a.type + "-" + $a.value))
            }
            New-Object -TypeName psobject -Property $hash
        }
    }
}
}

function Get-SVMVDPort {
    param (
    [parameter(mandatory=$true)]$vCenter) 

BEGIN {
    if (!(Test-SHVMWareConnection)) {
        Connect-SHVMWare
    }
    $VDPorts = Get-VDPortgroup -Server $vCenter
}

PROCESS {
    foreach ($port in $VDPorts) {
        $friendlyPipeName = $port.name.split("|")[2]
        $friendlyDashName = $port.name.split("-")[2]
        if ($friendlyPipeName) {
            $hash = @{
                FriendlyName = $friendlyPipeName
                VDPort = $port
                }
        } elseif ($friendlyDashName) {
           $hash = @{
                FriendlyName = $friendlyDashName
                VDPort = $port
                }
        } else { 
            $hash = @{
                FriendlyName = $port.name
                VDPort = $port
                }
        }
        New-Object -TypeName psobject -Property $hash
    }
}

END{}

}

function Get-SVMMatchingPort { 
    param(
        [parameter(mandatory=$true)]$vCenter, 
        [parameter(mandatory=$true)]$IPInfo)

BEGIN{
    if (!(Test-SHVMWareConnection)) {
        Connect-SHVMWare
    }
    $portGroups = Get-SVMVDPort -vCenter $vCenter 
}

PROCESS{
    if ($IPInfo.ACIZone) {
        $matchingPortGroup = $portGroups | where {$IPInfo.ID -match $_.FriendlyName}
    } else {
        $matchingPortGroup = $portGroups | where {$_.FriendlyName -eq $IPInfo.ID}
    }
        $hash = [ordered]@{ 
            IP = $IPInfo.IP
            Netmask = $IPInfo.Netmask
            Gateway = $IPInfo.Gateway
            CIDR = $IPInfo.CIDR
            VDPortGroup = $matchingPortGroup.VDPort
        }
        New-Object -TypeName psobject -Property $hash
}

END{}

}

function Set-SVMRemoteIP {
    param(
        [parameter(mandatory=$true)]$VM,
        [parameter(mandatory=$true)]$IP
    )

BEGIN {
    if (!(Test-SHVMWareConnection)) {
        Connect-SHVMWare
    }
    $foundVM = Get-VM $VM
    $vCenter= $foundVM.uid.split('@')[1].split(':')[0]
    <# Find-IPPInfo refers to another module that was written to function as an "API" to an IPPlan server. #>
    $IPInformation = Find-IPPIPInfo $IP
}

PROCESS {
    $IPSettings = Get-SVMMatchingPort -vCenter $vCenter -IPInfo $IPInformation
    Try{ 
        $scriptBlock = {
            $activeAdapter = Get-NetAdapter | where {$_.status -eq 'Up'}
            $activeAdapter | Get-NetIPAddress | Remove-NetIPAddress -Confirm:$false
            $activeAdapter | Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -Confirm:$false
            $activeAdapter | Set-NetRoute -DestinationPrefix '0.0.0.0/0' -NextHop $using:IPSettings.Gateway
            $activeAdapter | New-NetIPAddress -IPAddress $using:IPSettings.IP -PrefixLength $using:IPSettings.CIDR -DefaultGateway $using:IPSettings.Gateway
            ipconfig /registerdns
        }
        Invoke-Command -ScriptBlock $scriptBlock -ComputerName $VM -InDisconnectedSession -SessionOption (New-PSSessionOption -IdleTimeout 60000 -OutputBufferingMode Drop -MaxConnectionRetryCount 2)
    } catch {-i
            $null = $_
            Write-Warning "Failed to modify host IP"
    }
    TRY {
        $foundVM | Get-NetworkAdapter | Set-NetworkAdapter -NetworkName $IPSettings.VDPortGroup.Name -Confirm:$false -RunAsync
    } catch {
        $null = $_
        Write-Warning "Failed to change Adapter"
    }
            
}

END{
}

}
