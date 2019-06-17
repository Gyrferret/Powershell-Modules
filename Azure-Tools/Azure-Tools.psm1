Function Remove-shAzureExchangeSKU {
    param([parameter(mandatory=$true)]$UserPrincipalName)

BEGIN {
    $MSOLUsers = $UserPrincipalName | ForEach-Object { Get-MsolUser -UserPrincipalName $_}
    <# SKUs can be modified to remove whatever SKUs you want#>
    $skus = "efb87545-963c-4e0d-99df-69c6916d9eb0","9aaf7827-d63c-4b61-89c3-182f06f82e5c", "113feb6c-3fe4-4440-bddc-54d774bf0318"
}

PROCESS {
    $array = @()
    foreach ($user in $MSOLUsers) { 
        foreach ($services in $user.licenses) {
            foreach ($service in $Services) {
                foreach ($subsku in $service.ServiceStatus) {
                    if ($skus -contains $subsku.ServicePlan.ServicePlanId.GUID -and $subsku.ProvisioningStatus -eq "Success") {
                        $hash = [ordered]@{ 
                            User = $user.userprincipalname
                            AccountSKU = $service.AccountSkuID
                            ExchangeSKU = $subsku.ServicePlan.ServiceName
                        }
                    $array += New-Object -TypeName psobject -Property $hash
                    $licenseObject = New-MsolLicenseOptions -AccountSkuId $service.AccountSkuID -DisabledPlans $subsku.ServicePlan.ServiceName
                    Set-MsolUserLicense -UserPrincipalName $user.userprincipalname -LicenseOptions $licenseObject
                    }
                }
            
            }
        }
    }
}

END {
    $array 
}

}

Function Add-shAzureExchangeSKU {
    param([parameter(mandatory=$true)]$UserPrincipalName)

BEGIN {
    $MSOLUsers = $UserPrincipalName | ForEach-Object { Get-MsolUser -UserPrincipalName $_}
    $LicenseSkus = <# Enter your company's specific SKUs. Eg (contoso:STANDARDPACK)#>
    $skus = "efb87545-963c-4e0d-99df-69c6916d9eb0","9aaf7827-d63c-4b61-89c3-182f06f82e5c", "113feb6c-3fe4-4440-bddc-54d774bf0318"
    $disabledOptions = "MYANALYTICS_P2","OFFICEMOBILE_SUBSCRIPTION","BPOS_S_TODO_1","FORMS_PLAN_E1","STREAM_O365_E1","Deskless","FLOW_O365_P1","POWERAPPS_O365_P1","PROJECTWORKMANAGEMENT","SWAY","YAMMER_ENTERPRISE","MCOSTANDARD"
}

PROCESS {
    $array = @()
    foreach ($user in $MSOLUsers) {
        if ($user.licenses.count -gt 0 -and ($user.licenses.AccountSkuID | ForEach-Object {$LicenseSkus -contains $_})) {
            foreach ($services in $user.licenses) {
                if ($LicenseSkus -contains $services.AccountSkuId) { 
                    foreach ($service in $Services) {
                        $disableSkus = @()
                        foreach ($subsku in $service.ServiceStatus) {
                            if ($skus -notcontains $subsku.ServicePlan.ServicePlanId.GUID -and $subsku.ProvisioningStatus -ne "Success") {
                                $disableSkus += $subsku.ServicePlan.ServiceName
                            } elseif ($skus -contains $subsku.ServicePlan.ServicePlanId.GUID) { 
                                if ($subsku.ProvisioningStatus -eq "Success") {
                                    $ExchangeStatus = $true 
                                } else { 
                                    $ExchangeStatus = $false
                                }
                                $hash = [ordered]@{ 
                                    User = $user.userprincipalname
                                    AccountSKU = $service.AccountSkuID
                                    ExchangeEnabled = $ExchangeStatus
                                }
                            }
                            $array += New-Object -TypeName psobject -Property $hash
                            }
                        $licenseObject = New-MsolLicenseOptions -AccountSkuId $service.AccountSkuID -DisabledPlans $disableSkus
                        Set-MsolUserLicense -UserPrincipalName $user.userprincipalname -LicenseOptions $licenseObject
                    }
            
                }
               
        }
        } else {
            $licenseObject = New-MsolLicenseOptions -AccountSkuId <#contoso:STANDARDPACK#> -DisabledPlans $disabledOptions
            Set-MsolUserLicense -UserPrincipalName $user.userprincipalname -LicenseOptions $licenseObject -AddLicenses <#contoso:STANDARDPACK#>
        }
    } else {
        $licenseObject = New-MsolLicenseOptions -AccountSkuId <#contoso:STANDARDPACK#> -DisabledPlans $disabledOptions
        Set-MsolUserLicense -UserPrincipalName $user.userprincipalname -LicenseOptions $licenseObject -AddLicenses <#contoso:STANDARDPACK#>
    }

}

END{
    $array
}
}

Function Get-shAzureExchangeSkuStatus {
    param([parameter(mandatory=$true)]$UserPrincipalName)

BEGIN {
    $MSOLUsers = $UserPrincipalName | ForEach-Object { Get-MsolUser -UserPrincipalName $_}
    $skus = "efb87545-963c-4e0d-99df-69c6916d9eb0","9aaf7827-d63c-4b61-89c3-182f06f82e5c", "113feb6c-3fe4-4440-bddc-54d774bf0318"
}
PROCESS {
    $array = @()
    foreach ($user in $MSOLUsers) { 
        if ($user.Licenses) {
            foreach ($services in $user.licenses) {
                foreach ($service in $Services) {
                    foreach ($subsku in $service.ServiceStatus) {
                        if ($skus -contains $subsku.ServicePlan.ServicePlanId.GUID) {
                            $hash = [ordered]@{ 
                                User = $user.userprincipalname
                                AccountSKU = $service.AccountSkuID
                                ExchangeStatus = $subsku.ProvisioningStatus
                            }
                        } else {
                            $hash = [ordered]@{ 
                                User = $user.userprincipalname
                                AccountSKU = $service.AccountSkuID
                                ExchangeStatus = $False
                            }
                        }
                        $array += New-Object -TypeName psobject -Property $hash
                        }
                }
            
            }
        } else {
            $hash = [ordered]@{ 
                User = $user.userprincipalname
                AccountSKU = "None"
                ExchangeStatus = $False
            }
        $array += New-Object -TypeName psobject -Property $hash
    }
    }
}

END{
    $array
}

}

Function Get-SHAzureEXMigrationReadiness {
    param([parameter(mandatory=$true)]$UserPrincipalName)

BEGIN {
    $MSOLUsers = $UserPrincipalName | ForEach-Object { Get-MsolUser -UserPrincipalName $_}
    $LicenseSkus = <# Enter your company's specific SKUs. Eg (contoso:STANDARDPACK)#>
    $skus = "efb87545-963c-4e0d-99df-69c6916d9eb0","9aaf7827-d63c-4b61-89c3-182f06f82e5c", "113feb6c-3fe4-4440-bddc-54d774bf0318"
    $AccountSKU = $false
    $ExchangeSKU = $false
    $array = @()
}

PROCESS {
    foreach ($user in $MSOLUsers) { 
        if ($user.Licenses) {
            foreach ($services in $user.licenses) {
                if ($LicenseSkus -contains $services.AccountSkuId) { 
                    $AccountSKU = $true
                foreach ($service in $Services) {
                    foreach ($subsku in $service.ServiceStatus) {
                        if ($skus -contains $subsku.ServicePlan.ServicePlanId.GUID -and $subsku.ProvisioningStatus -eq "Success") {
                            $ExchangeSKU = $true
                        }
                    }
                }
                }
            }
        }
        $hash = [ordered]@{ 
            UserPrincipalName = $user.UserPrincipalName
            AccountSKU = $AccountSKU
            ExchangeSKU = $ExchangeSKU
        }
        $array += New-Object -TypeName PSObject -Property $hash
    }
}

END {
    $array
}
}

Function Get-SHAzureCSMigrationReadiness {
    param([parameter(mandatory=$true)]$UserPrincipalName)

BEGIN {
    $MSOLUsers = $UserPrincipalName | ForEach-Object { Get-MsolUser -UserPrincipalName $_}
    $LicenseSkus = <# Enter your company's specific SKUs. Eg (contoso:STANDARDPACK)#>
    $csskus = "0feaeb32-d00e-4d66-bd5a-43b5b83db82c"
    $acskus = "3e26ee1f-8a5f-4d52-aee2-b81ce45c8f40"
    $psskus = "4828c8ec-dc2e-4779-b502-87ac9ce28ab7"
    $acName = "MCOMEETADV"
    $psName = "MCOEV"
    $array = @()
}

PROCESS {
    foreach ($user in $MSOLUsers) { 
        $AccountSKU = $false
        $SkypeSKU = $false
        $AVConferenceing = $false
        $phoneSystem = $false
        if ($user.Licenses) {
            foreach ($services in $user.licenses) {
                if ($LicenseSkus -contains $services.AccountSkuId) { 
                    $AccountSKU = $true
                }
                foreach ($service in $Services) {
                    foreach ($subsku in $service.ServiceStatus) {
                        if ($csskus -contains $subsku.ServicePlan.ServicePlanId.GUID -and $subsku.ProvisioningStatus -ne "Disabled") {
                            $SkypeSKU = $true
                        } elseif ($subsku.ServicePlan.ServicePlanId.GUID -eq $acskus) {
                            $AVConferenceing = $true
                        } elseif ($subsku.ServicePlan.ServicePlanId.GUID -eq $psskus) {
                            $phoneSystem = $true
                        }
                            
                    }
                }
                
            }
        }
        $hash = [ordered]@{ 
            UserPrincipalName = $user.UserPrincipalName
            AccountSKU = $AccountSKU
            SkypeSKU = $SkypeSKU
            AVConferencing = $AVConferenceing  
            PhoneSystem = $phoneSystem
        }
        $array += New-Object -TypeName PSObject -Property $hash
    }
}

END {
    $array
}
}

Function Set-SHAzureCSLicenses {
    param([parameter(mandatory=$true)]$UserPrincipalName,
    [switch]$PhoneSystem
    )

BEGIN {
    $licenseUsers = $UserPrincipalName | ForEach-Object { Get-SHAzureCSMigrationReadiness -UserPrincipalName $_}
    $LicenseSkus = <# Enter your company's specific SKUs. Eg (contoso:STANDARDPACK)#>
    $disabledOptions = "MYANALYTICS_P2","OFFICEMOBILE_SUBSCRIPTION","BPOS_S_TODO_1","FORMS_PLAN_E1","STREAM_O365_E1","Deskless","FLOW_O365_P1","POWERAPPS_O365_P1","PROJECTWORKMANAGEMENT","SWAY","YAMMER_ENTERPRISE","EXCHANGE_S_STANDARD"
    $csskus = "0feaeb32-d00e-4d66-bd5a-43b5b83db82c"
    $acName = "sharphealthcare:MCOMEETADV"
    $psName = "sharphealthcare:MCOEV" 
}

PROCESS {
    foreach ($user in $licenseUsers) { 
         if (!($user.AccountSKU)) {
            $licenseObject = New-MsolLicenseOptions -AccountSkuId <#contoso:STANDARDPACK#> -DisabledPlans $disabledOptions
            Set-MsolUserLicense -UserPrincipalName $user.userprincipalname -LicenseOptions $licenseObject -AddLicenses <#contoso:STANDARDPACK#>
         }elseif (!($user.SkypeSKU)) {
            $currentLicenses = ((Get-MSOLUser -UserPrincipalName $user.UserPrincipalName).Licenses | Where-Object {$LicenseSkus -contains $_.AccountSkuID })
            foreach ($service in $currentLicenses) {
                    $disableSkus = @()
                    foreach ($subsku in $service.ServiceStatus) {
                        if ($csskus -notcontains $subsku.ServicePlan.ServicePlanId.GUID -and $subsku.ProvisioningStatus -ne "Success") {
                            $disableSkus += $subsku.ServicePlan.ServiceName
                        }
                    }
                    $licenseObject = New-MsolLicenseOptions -AccountSkuId $service.AccountSkuID -DisabledPlans $disableSkus
                    Set-MsolUserLicense -UserPrincipalName $user.userprincipalname -LicenseOptions $licenseObject
                }
         }
         if (!($user.AVConferencing)) {
            Set-MsolUserLicense -UserPrincipalName $user.userprincipalname -AddLicenses $acName
         }
         if (!($user.PhoneSystem) -and ($phoneSystem)) {
            Set-MsolUserLicense -UserPrincipalName $user.userprincipalname -AddLicenses $psName
         }
    }

}

END {
    $UserPrincipalName | ForEach-Object { Get-SHAzureCSMigrationReadiness -UserPrincipalName $_}
}
}
