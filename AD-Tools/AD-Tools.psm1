Function Set-SHUnixUser {
    param(
        [parameter(mandatory=$true)]$ADUser,
        [switch]$Reset,
        [switch]$TSEnable) 

BEGIN {
    TRY {
        $userinfo = Get-ADuser -Identity $ADUser -Properties mssfu30nisdomain,gidnumber,uidnumber,unixHomeDirectory,loginshell -ErrorAction Stop
    } CATCH {
        Write-Warning "Unabled to find $ADUser!"
        BREAK 
    }
    if ($TSEnable ) {
        Set-SHADTSUnixUser -ADUser $userinfo.samaccountname
        BREAK
    }
    if ($Reset) { 
        Reset-SHADUnixUser -ADUser $userinfo.samaccountname
        BREAK
    }
    $validated = $true
    if ($userinfo.mssfu30nisdomain)
        {Write-Warning "mssfu30nisdomain already configured!"; $validated = $false}
    if ($userinfo.gidnumber)
        {Write-Warning "gidnumber already configured!"; $validated = $false}
    if ($userinfo.uidnumber)
        {Write-Warning "uidnumber already configured!"; $validated = $false}
    if ($userinfo.unixHomeDirectory)
        {Write-Warning "unixHomeDirectory already configured!"; $validated = $false}
    if ($userinfo.loginshell)
        {Write-Warning "loginshell already configured!"; $validated = $false}

    if (!($validated)) {
        BREAK
    }
}
PROCESS{
    New-SHADPrimaryGroup -ADUser $userinfo.samaccountname.tolower()
    $SHADPrimaryGroup = Get-SHADPrimaryGroup -ADUser $userinfo.samaccountname.tolower()
    Add-ADGroupMember -Identity $SHADPrimaryGroup.name -Members $userinfo.samaccountname
    Set-SHADUnixUser -ADUser $userinfo.samaccountname.tolower() -GID $SHADPrimaryGroup.GidNumber

}

END{
    Get-ADUser $userinfo.samaccountname -Properties mssfu30nisdomain,gidnumber,uidnumber,unixHomeDirectory,loginshell
}

}

Function Get-SHUnixUser {
    param(
        [parameter(mandatory=$true)]$ADUser)
         
BEGIN {
    TRY {
        $null = Get-ADuser -Identity $ADUser -ErrorAction Stop
    } CATCH {
        Write-Warning "Unabled to find $ADUser!"
        BREAK 
    }
    TRY {
        $userinfo = Get-ADuser -Identity $ADUser -Properties mssfu30nisdomain,gidnumber,uidnumber,unixHomeDirectory,loginshell,msSFU30GidNumber,msSFU30HomeDirectory,msSFU30UidNumber -ErrorAction Stop
    } CATCH {
        Write-Warning "Unabled to load $ADUser!"
        BREAK 
    }
    TRY {
        $primaryGroup = Get-ADGroup -Filter "gidNumber -eq $($userinfo.gidnumber)" -ErrorAction stop
    } CATCH {
        $_ | Out-Null
        $primaryGroup = New-Object -TypeName psobject
        $primaryGroup | Add-Member -MemberType NoteProperty -Name Name -Value $null         
    }
}

PROCESS {
    $validated = $true
    $TSvalidated = $true
    switch ($null) {
        $userinfo.mssfu30nisdomain {$validated = $false}
        $userinfo.gidnumber {$validated = $false}
        $userinfo.uidnumber {$validated = $false}
        $userinfo.unixHomeDirectory {$validated = $false}
        $userinfo.loginshell {$validated = $false}
        }
    switch ($null) {
        $userinfo.msSFU30GidNumber {$TSvalidated = $false}
        $userinfo.msSFU30HomeDirectory {$TSvalidated = $false}
        $userinfo.msSFU30UidNumber {$TSvalidated = $false} 
    }
    $hash = [ordered]@{ 
        Name = $userinfo.Name
        GID = $userinfo.GIDNumber
        UID = $userinfo.UIDNumber
        PrimaryGroup = $primaryGroup.Name
        LoginShell = $userinfo.Loginshell
        HomeDirectory = $userinfo.unixHomeDirectory
        UnixEnabled = $validated
        TSEnabled = $TSvalidated
        }
    New-Object -TypeName PSObject -Property $hash

}

END{}
}

Function New-SHUnixGroup { 
    param(
        [parameter(mandatory=$true)]$ADGroup,
        $path = <#INSERT DEFAULT PATH HERE#>
        )

BEGIN {
    TRY { 
        $null = Get-ADGroup $ADGroup
        Write-Warning "Group Already Exists!"
        $confirm = Read-Host "Unix Enable Existing Group?? [Y/N]"
        if ($confirm -like "y") {  
            Set-SHUnixGroup -ADGroup $ADGroup
        } else {
            BREAK
        }
    } CATCH { 
        $null = $_
    }
}

PROCESS {
    New-ADGroup -Name $ADGroup -Path $path -GroupCategory Security -GroupScope Global
    Set-SHUnixGroup -ADGroup $ADGroup

}

END {}

}

Function Set-SHUnixGroup {
    param(
        [parameter(mandatory=$true)]$ADGroup)

BEGIN {
    $nisDomain = "shcsd"
    TRY {
        $groupQuery = Get-ADGroup $ADGroup -Properties msSFU30Name,msSFU30NisDomain,gidNumber -ErrorAction Stop
    }
    CATCH {
        $null = $_ 
        Write-Warning "Group does not exist!" 
        BREAK  
    }
    $validated = $true
    if ($groupQuery.msSFU30Name) {
        Write-Warning "msSFU30Name already configured!"; $validated = $false
    }
    if ($groupQuery.msSFU30NisDomain) {
        Write-Warning "msSFU30NisDomain already configured!"; $validated = $false
    }
    if ($groupQuery.gidNumber) {
        Write-Warning "gidNumber already configured!"; $validated = $false
    }
    if (!($validated)) {
        BREAK
    }
    
}
PROCESS {
    $GidInfo = Get-SHIDInfo
    $groupQuery.msSFU30Name = $groupQuery.SamAccountName.tolower()
    $groupQuery.msSFU30NisDomain = $nisDomain
    $groupQuery.gidNumber = $GidInfo.MaxGID
    Set-ADGroup -Instance $groupQuery
    sleep 2
}

END{
   Set-SHIDInfo -GID $GidInfo.MaxGID
   Get-ADGroup -Identity $groupQuery.SamAccountName -Properties msSFU30Name,msSFU30NisDomain,gidNumber
}

}

Function New-SHADPrimaryGroup {
    param(
        [parameter(mandatory=$true)]$ADUser)

BEGIN {
    $groupString = "_primary_nix"
    $primaryGroup = $ADUser + $groupString
    $groupPath = <#Insert Default Path Here #>
    $nisDomain = <#NETBIOS NAME#>
    TRY {
        $testgroup = Get-ADGroup $PrimaryGroup -ErrorAction Stop
        Write-Warning "$primaryGroup Already Exists!"
        BREAK
    }
    CATCH {
        $null = $_        
    }
}
PROCESS {
    $GidInfo = Get-SHIDInfo
    New-ADGroup -Name $primaryGroup -Path $groupPath -GroupScope Global -GroupCategory Security
    $groupQuery = Get-ADGroup $primaryGroup -Properties msSFU30MaxUidNumber,msSFU30MaxGidNumber
    $groupQuery.msSFU30Name = $primaryGroup
    $groupQuery.msSFU30NisDomain = $nisDomain
    $groupQuery.gidNumber = $GidInfo.MaxGID
    Set-ADGroup -Instance $groupQuery
    sleep 2
}

END{
   Set-SHIDInfo -GID $GidInfo.MaxGID
}

}

Function Get-SHADPrimaryGroup {
    param(
        [parameter(mandatory=$true)]$ADUser)

BEGIN {
    $groupString = <#Insert Default Group Suffix Here #>
    $primaryGroup = $ADUser + $groupString

}

PROCESS{
    Get-ADGroup $primaryGroup -Properties GidNumber
}

END{}
}

Function Reset-SHADUnixUser { 
    param(
        [parameter(mandatory=$true)]$ADUser) 

BEGIN {
    $unixHash = [ordered]@{
        uidNumber = $null
        msSFU30UidNumber = $null
        gidNumber = $null
        msSFU30GidNumber= $null
        msSFU30Name = $null
        msSFU30NisDomain = $null
        unixHomeDirectory = $null
        msSFU30HomeDirectory = $null
        loginshell = $null
    }
}

PROCESS { 
    Set-ADUser $ADUser -Replace $unixHash
}

END{}
}

Function Set-SHADUnixUser {
    param(
        [parameter(mandatory=$true)]$ADUser,
        [parameter(mandatory=$true)]$GID,
        $nisDomain = <#Insert Domain NETBIOSName#>,
        $loginShell = "/bin/bash"        
        )
BEGIN{
    $homeDirectory = "/home/$($ADUser)"
    } 

PROCESS {
    $uidInfo = Get-SHIDInfo
    $unixHash = [ordered]@{
        uidNumber = $uidInfo.MaxUID
        msSFU30UidNumber = $uidInfo.MaxUID
        gidNumber = $GID
        msSFU30GidNumber= $GID
        msSFU30Name = $ADUser
        msSFU30NisDomain = $nisDomain
        unixHomeDirectory = $homeDirectory
        msSFU30HomeDirectory = $homeDirectory
        loginshell = $loginShell
    }
    Set-ADUser $ADUser -Replace $unixHash

}

END{
    Set-SHIDInfo -UID $uidInfo.MaxUID
}
}

Function Set-SHADTSUnixUser{ 
    param(
        [parameter(mandatory=$true)]$ADUser)

BEGIN{
    $userInfo = Get-SHUnixUser -ADUser $ADUser
    if (($userInfo).TSEnabled) {
        Write-Warning "User is already Technical Services Enabled"
        BREAK
    }
}

PROCESS{
    $unixHash = @{ 
        msSFU30GidNumber = $userInfo.GID
        msSFU30UidNumber = $userInfo.UID
        msSFU30HomeDirectory = $userInfo.HomeDirectory
    }
    Set-ADUser $ADUser -Replace $unixHash
}

END{
    Get-SHUnixUser -ADUser $ADUser
}  
}

Function Get-SHIDInfo {
BEGIN {
    $msInfoBase = <#Base info is located at: "CN=DOMAIN,CN=ypservers,CN=YPSERV30,CN=RpcServices,CN=System,DC=DOMAIN,DC=com" #>
}

PROCESS{
    $object = Get-ADObject $msInfoBase -Properties msSFU30MaxUidNumber,msSFU30MaxGidNumber
    $hash = @{
        MaxUID = $object.msSFU30MaxUidNumber
        MaxGID = $object.msSFU30MaxGidNumber
    }
    New-Object -TypeName psobject -Property $hash 
}
END{}
}

Function Set-SHIDInfo {
    param(
        $UID,
        $GID
    )

BEGIN {
    $msInfoBase = <#Base info is located at: "CN=DOMAIN,CN=ypservers,CN=YPSERV30,CN=RpcServices,CN=System,DC=DOMAIN,DC=com" #>
    $object = Get-ADObject $msInfoBase -Properties msSFU30MaxUidNumber,msSFU30MaxGidNumber
}

PROCESS{
if ($GID) {
    if ($object.msSFU30MaxGidNumber -eq $GID) {
        $newGID = $GID + 1
        $GIDhash = @{
            msSFU30MaxGidNumber = $newGID}
        Set-ADObject $object -Replace $GIDhash
    } else {
        Write-Warning "msSFU30MaxGidNumber ($($object.msSFU30MaxGidNumber)) does not match $GID!"
        BREAK
    }
}
 if ($UID) {
    if ($object.msSFU30MaxUidNumber -eq $UID) {
        $newUID = $UID + 1
        $UIDhash = @{
            msSFU30MaxUidNumber = $newUID}
        Set-ADObject $object -Replace $UIDhash
    } else {
        Write-Warning "msSFU30MaxUidNumber ($($object.msSFU30MaxUidNumber)) does not match $UID!"
        BREAK
    }
}   
    
}

END{}

}

Function Set-SHAzureUPN {
    param(
    [parameter(mandatory=$true)]$SAMAccountName)

BEGIN{
    $users = $SAMAccountName | % {Get-AdUser -identity $_ -Properties EmailAddress}

}

PROCESS {
    foreach ($user in $users) {
        $hash = @{
            UserPrincipalName = $user.EmailAddress
        }
    $user | Set-ADUser -Replace $hash
}

}

END {
    $post = $SAMAccountName | % {Get-AdUser -identity $_ -Properties EmailAddress}
    $post | ft Name,UserPrincipalName -AutoSize
}

}

Export-ModuleMember Set-SHAzureUPN
Export-ModuleMember Set-SHUnixUser
Export-ModuleMember Get-SHUnixUser
Export-ModuleMember Set-SHUnixGroup
Export-ModuleMember New-SHUnixGroup