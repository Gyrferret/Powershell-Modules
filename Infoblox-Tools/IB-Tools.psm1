function Ignore-SelfSignedCerts {
    try {
        Write-Host "Adding TrustAllCertsPolicy type." -ForegroundColor White
        Add-Type -TypeDefinition @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy
    {
    public bool CheckValidationResult(
    ServicePoint srvPoint, X509Certificate certificate,
    WebRequest request, int certificateProblem)
    {
    return true;
    }
    }
"@
    Write-Host "TrustAllCertsPolicy type added." -ForegroundColor White
    }
    catch {
    Write-Host $_ -ForegroundColor "Yellow"
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}
function Get-IBCredentials {
    if (!($Global:IBCreds)) {
        if ($Global:credentials) {
            $Global:IBCreds = [System.Management.Automation.PSCredential]::new($Global:credentials.UserName.tolower().replace("shcsd\",""),$Global:credentials.password)
        } else { 
            $Global:IBCreds = Get-credential
        }
    }
        
}

function New-IBFixedAddress {
    param(
        [parameter(mandatory=$true)]$MAC,
        [parameter(mandatory=$true)]$IP,
        $Hostname = "N/A",
        $CMNumber = "N/A",
        [switch]$Restart
        )
BEGIN{
   Get-IBCredentials
   Ignore-SelfSignedCerts
   if ($MAC -match "-") {
        $MAC = $MAC.Replace("-",":")
    } elseif ($MAC -notmatch "-" -and $MAC -notmatch ":") {
        $MAC = $MAC.insert(2,":").insert(5,":").insert(8,":").insert(11,":").insert(14,":")
    }
    $URL = "https://172.22.8.205/wapi/v1.2/fixedaddress"
}
PROCESS{
    $RequestBody = [ordered]@{
        ipv4addr = $IP
        mac = $MAC.toupper()
        name = $Hostname
        comment = $CMNumber

    }
    TRY { 
        Invoke-RestMethod -Uri $URL -Method POST -Body ($RequestBody | ConvertTo-Json) -ContentType application/json -Credential $Global:IBCreds
    } CATCH {

        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
        Write-Error "[ERROR:Find-Network] $responseBody"
    }
}
END{
    if($Restart) {
        Restart-IBServices
    }    
}
}

function New-IBARecord {
    param(
        [parameter(mandatory=$true)]$Hostname,
        [parameter(mandatory=$true)]$IP,
        [switch]$Restart
        )
BEGIN{
    Get-IBCredentials
    Ignore-SelfSignedCerts
    $fqdn = $Hostname + '.sharp.com'
    $URL = 'https://172.22.8.205/wapi/v2.2/record:host'
}

PROCESS{
    $RequestBody = @{
        ipv4addrs = @( 
            @{ipv4addr = $IP}
        )
        name = $fqdn
    }
    Invoke-WebRequest -Uri $URL -Method Post -Body ($RequestBody | ConvertTo-Json) -ContentType 'application/json' -Credential $Global:IBCreds    
}

END{
    if($Restart) {
        Restart-IBServices
    }    
}
}

function Restart-IBServices {
BEGIN{
    Get-IBCredentials
    Ignore-SelfSignedCerts
}

Process{
    TRY {
        $GridQuery = Invoke-RestMethod https://172.22.8.205/wapi/v2.5/grid -Credential $Global:IBCreds -Method GET
        $RestartURI = "https://172.22.8.205/wapi/v2.5/" + $($GridQuery._REF) + "?_function=restartservices"
        $JSON = @{
            restart_option = "RESTART_IF_NEEDED"
            service_option = "ALL"
            member_order = "SIMULTANEOUSLY"
            }
        $RestartQuery = Invoke-RestMethod $RestartURI -Method Post -Credential $Global:IBCreds -Body ($JSON | ConvertTo-Json) -ContentType application/json
        Write-Host "Successfully Restarted Infoblox Services"-ForegroundColor Green
    } Catch {
    $_
    }
}

END{}

}

function Remove-IBARecord {
    param(
    [parameter(mandatory=$true)]$Hostname)

BEGIN{
    Get-IBCredentials
    Ignore-SelfSignedCerts   
    $fqdn = $Hostname.tolower() + '.sharp.com'
}

Process{
    TRY {
        $request = Invoke-RestMethod -Uri "https://172.22.8.205/wapi/v2.2/record:host?name=$fqdn" -Method GET -Credential $Global:IBCreds 
        $request_ref = $request._ref.Split("/:")[2]
        Invoke-RestMethod -Uri "https://172.22.8.205/wapi/v2.2/record:host/$request_ref" -Method DELETE -Credential $Global:IBCreds 
    } CATCH {
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
        Write-Error "[ERROR:Find-Network] $responseBody"
    }
}
END{}
}

Function Get-IBFixedAddress {
    param(
    [parameter(mandatory=$true,ParameterSetName='MAC')]$MAC,
    [parameter(mandatory=$true,ParameterSetName='IP')]$IP
    )

BEGIN{
    Get-IBCredentials
    Ignore-SelfSignedCerts
    if ($MAC) {
                if ($MAC -match "-") {
        $MAC = $MAC.Replace("-",":")
    } elseif ($MAC -notmatch "-" -and $MAC -notmatch ":") {
            $MAC = $MAC.insert(2,":").insert(5,":").insert(8,":").insert(11,":").insert(14,":")
        }
        $URL = "https://172.22.8.205//wapi/v1.2/fixedaddress?_return_fields%2B=mac&mac="
        $Data = $mac
    } else { 
        $URL = "https://172.22.8.205//wapi/v1.2/ipv4address?status=USED&ip_address="
        $Data = $IP
    }
}

PROCESS{
    $request = Invoke-RestMethod -Uri ($URL + $Data) -Method GET -Credential $Global:IBCreds
    $request
}

END{
}


}

Export-ModuleMember Get-IBFixedAddress
Export-ModuleMember New-IBARecord
Export-ModuleMember Restart-IBServices
Export-ModuleMember New-IBFixedAddress
Export-ModuleMember Get-IBCredentials
Export-ModuleMember Remove-IBARecord
