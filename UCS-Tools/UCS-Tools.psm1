function Connect-SHUCS {
    param(
        [parameter(mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [ValidateSet(<#Insert UCS FQDNs here#>)]
        $UCSDomain
        )
     
    $multilogin = Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true
    if (!($Global:UCSCreds)) {
        $Global:UCSCreds = Get-Credential
    } 
    Connect-Ucs $UCSDomain -Credential $Global:UCSCreds
}

function Get-SharpUCSProfileReport {
    param(
        [parameter(mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [ValidateSet(<#Insert UCS FQDNs here#>)]
        $UCSDomain
    )

Begin {
    $ucs = Connect-SHUCS $UCSDomain 
}

PROCESS{
    $chassis = Get-UcsChassis -Ucs $ucs
    foreach ($i in $chassis) { 
        $blades = Get-UcsBlade -Chassis $i | where {$_.AssignedToDn}
        Foreach ($a in $blades) { 
            $ServiceProfile = Get-UcsServiceProfile -pnDn $a[0].dn -Ucs $ucs
            $hash = [ordered]@{
                ServiceProfile = $ServiceProfile.Name[0]
                Blade = $a.Rn
                Chassis = $i.rn
            }
            New-object -TypeName PSObject -Property $hash
        }
    }
}

END{
    Disconnect-Ucs
}

}

function Find-SHUCSServiceProfile {
    param(
        [parameter(mandatory=$true)]
        $ServiceProfile,
        [parameter(mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [ValidateSet(<#Insert UCS FQDNs here#>)]
        $UCSDomain
    )

BEGIN {
    $ucs = Connect-ShUCS $UCSDomain 
}

PROCESS {
    $FoundServiceProfile = Get-UCSServiceProfile -name $ServiceProfile -Ucs $ucs
    if ($FoundServiceProfile) {
        $FoundBlade = (Get-UCSBlade -Dn $FoundServiceProfile.pnDn -Ucs $ucs)
        $FoundChassis = $FoundBlade.Dn.split("/")[1]        
        $hash = [ordered]@{
            ServiceProfile = $FoundServiceProfile.name
            Blade = $FoundBlade.Rn
            Chassis = $FoundChassis
            Type = $FoundBlade.Model
        }
        New-Object -TypeName psobject -Property $hash
    }
}
END{
    Disconnect-Ucs
}

}

function Get-SHUCSChassisReport {
    param(
        [parameter(mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [ValidateSet(<#Insert UCS FQDNs here#>)]
        $UCSDomain, 
        $ChassisID
    )
BEGIN {
    $ucs = Connect-SHUCS $UCSDomain 
    if ($ChassisID) { 
        $Chassis = @()
        foreach ($i in $ChassisID) {
        Try {
            $Chassis += Get-UcsChassis -Ucs $ucs -Id $i
        } catch {
            $_  | Out-Null 
            Write-Warning "Unable to gather information for Chassis $i"
            }
        }
    } else {
        $Chassis = Get-UcsChassis -Ucs $ucs
    }
}

PROCESS { 
    foreach ($i in $chassis) { 
        $blades = Get-UCSBlade -Chassis $i
        foreach ($a in $blades) {
            if ($a.AssignedToDn) {
                $ServiceProfile = (Get-UcsServiceProfile -pnDn $a[0].dn -ucs $ucs).Name
                }
            else { 
                $ServiceProfile = "None"
                }
            $hash = [ordered] @{
                Chassis = $i.id
                BladeNumber = $a.SlotId
                ServiceProfile = $ServiceProfile
                Type = $a.Model
            }
        New-Object -TypeName psobject -Property $hash
        }
    }
}

END{
    Disconnect-Ucs    
}

}      

function Get-SHUCSServiceProfileAssociation { 
    param(
        [parameter(mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [ValidateSet(<#Insert UCS FQDNs here#>)]
        $UCSDomain,
        $ChassisID
    )
BEGIN {
    if (!(Test-SHVMWareConnection)) {
        Connect-SHVMWare
    }
    if ($ChassisID) { 
        $ServiceProfiles = Get-SHUCSChassisReport -UCSDomain $UCSDomain -ChassisID $ChassisID
    } else {
        $ServiceProfiles = Get-SHUCSChassisReport -UCSDomain $UCSDomain
    }
}

PROCESS {
    foreach ($i in $ServiceProfiles) {
        if ($i.ServiceProfile -ne "None") {
            $VMhost = <#Information Redacted#>
            $VMHost = Get-VMHost -name $VMhost
            Try {
                $Cluster = $VMhost | Get-Cluster
            } catch {
                $null = $_
                $cluster = "N/A"
            }
            $hash = [ordered]@{
                VMHost = $VMHost.Name
                Cluster = $Cluster.Name
                Chassis = $i.Chassis
                Blade = $i.BladeNumber
            }
            New-Object -TypeName PSObject -Property $hash
        }
    }
}

END{
    Disconnect-Ucs
}
        
}