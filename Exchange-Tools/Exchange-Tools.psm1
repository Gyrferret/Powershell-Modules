function Start-ExchangeShell {
    . 'C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1'
    Connect-ExchangeServer -auto -ClientApplication:ManagementShell
}
function Get-ExchangeDatabaseSizes {
    param([switch] $list,
    [switch] $report
    )
BEGIN{
}
PROCESS{
    if ($report) { 
        $obj = Get-ExchangeDatabaseSizesfunction
        $obj | Sort Size -Descending | ft -AutoSize 
    } else { 
        Get-ExchangeDatabaseSizesfunction
    }
    
}
END{}
}

function Get-ExchangeDatabaseSizesfunction {
    $Databases = Get-MailboxDatabase | sort Name -Descending | Out-GridView -Title "Select Database" -OutputMode Multiple
    Foreach ($i in $Databases) {
        $Mailboxes = Get-MailboxStatistics -Database $i.name
        for ($a = 0; $a -lt $Mailboxes.count; $a++) {
            $hash = @{
                Name = $Mailboxes[$a].DisplayName 
                Size = $Mailboxes[$a].TotalItemSize
                Items = $Mailboxes[$a].ItemCount
                ServerName = $Mailboxes[$a].ServerName
                Database = $i.name
                }
            New-Object -TypeName psobject -Property $hash
            }
        }
}

function Move-ExchangeMailboxes {
    $MailboxUsers = Get-ExchangeDatabaseSizes | sort Size -Descending | Out-GridView -Title "Select Mailboxes to move" -OutputMode Multiple   
    $DestinationDatabase = Get-MailboxDatabase | sort Name -Descending | Out-GridView -Title "Select Database to Migrate To" -OutputMode Single
    foreach ($c in $MailboxUsers) {
        Get-Mailbox -Identity $c.Name | New-MoveRequest -TargetDatabase $DestinationDatabase.Name
    }
}

function Get-MailboxUserADInfo {
    param($Name) 
    TRY {
            $ADUserName = $b.name
            $UserInfo = Get-ADUser -Filter {Name -eq $ADUserName} -Properties mail
            New-Object -TypeName PSObject -Property @{EmailAddress = $UserInfo.mail} 
        }
    Catch { 
            $_ | Out-Null
            Write-Warning "Failed to Get AD Information for $b.Name"
    }

}

function Get-ExchangeSoftDeletedUsers {
    $Databases = Get-MailboxDatabase | where DatabaseCreated #filters out that pesky database that isn't accessible
    $b = 0
    foreach ($i in $Databases) {
        Write-Progress -Status "Searchign $($i.name)..." -Activity "Checking Databases" -PercentComplete (($b / $Databases.count) * 100)
        $b++
        TRY {
            $Stats = Get-MailboxStatistics -Database $i.name
            $SoftDeleted = $Stats | where DisconnectReason -eq "SoftDeleted"
            for ($a = 0; $a -lt $SoftDeleted.count; $a++) {
                $hash = [ordered]@{ 
                    Name = $SoftDeleted[$a].DisplayName
                    ItemCount = $SoftDeleted[$a].ItemCount
                    Size = $SoftDeleted[$a].TotalItemSize
                    Database = $i.name
                    OrphanedGUID = $SoftDeleted[$a].MailboxGuid
                }
                New-Object -TypeName PSObject -Property $hash
            }
        } Catch {
            $_ | Out-Null
            Write-Warning "Unable to connect to Database $($i.name)"
        }

    }
}

function Get-SoftDeletedUsers {
    $Users = Get-ExchangeSoftDeletedUsers
    foreach ($i in $Users) { 
        $mailbox = Get-Mailbox $i.Name
        $matches = $true
        if ($mailbox.database -eq $i.Database) {
            $Matches = $false
            }
        $hash = [ordered]@{
            Name = $i.Name
            ItemCount = $i.ItemCount
            OrphanedGUID = $i.OrphanedGUID
            CurrentDatabase = $mailbox.Database
            OrphanedDatabase = $i.Database
            Mismatch = $Matches
        }
        New-Object -TypeName PSObject -Property $hash
    }
}

Export-ModuleMember Get-ExchangeDatabaseSizes
Export-ModuleMember Move-ExchangeMailboxes
Export-ModuleMember Start-ExchangeShell
Export-ModuleMember Get-ExchangeSoftDeletedUsers
Export-ModuleMember Get-SoftDeletedUsers