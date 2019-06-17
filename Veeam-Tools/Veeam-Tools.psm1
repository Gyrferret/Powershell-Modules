function Get-VBRsnapinState {
    <#
    .SYNOPSIS
    The Get-VBRsnapinState function is used to verify if the Veeam snapin in loaded, and connects to the Veeam endpoint server

    .DESCRIPTION
    The module is called prior to any Veeam function being run to ensure that the snapin is loaded, and the the endpoint server connection is established. 
    #>
    param ($VBRserver = '[Veeam Server]')
    Try {
        Write-Progress "Attempting to Load Veeam Snap-in"
        Add-PSSnapin VeeamPSSnapIn
    } Catch {
        $_ | Out-Null
        Write-Warning 'Failed Adding Snaping'
        BREAK
    } 
if (!(Get-VBRServerSession)) { # Only connects if a connection isn't already present.
        Try {
            Write-Progress "Attempting to Connect to $VBRserver"
            Connect-VBRServer -Server $VBRserver
        } Catch {
            $_ | Out-Null
            Write-Warning 'Failed Connecting to Endpoint'
            BREAK
            }
    }
}
function Get-FailedVBRJobs {
    <#
    .SYNOPSIS
    This module will return any failed jobs. 

    .DESCRIPTION
    The Get-FailedVBRJobs modules will return any failed jobs. As Endpoint (file) jobs are different than Backup jobs, the -endpoints flag will need to be specified to search those jobs.

    .PARAMETER Endpoints
    Specifies to get Endpoint Backup jobs rather than standard Backup Jobs. 

    .EXAMPLE
    Get-FailedVBRJobs -endpoints
    #>
    param ([switch]$Endpoints)

BEGIN {
    Get-VBRsnapinState
    if ($Endpoints) {
        $jobs = Get-VBREPJob
    } else {
        $jobs = Get-VBRJob
    }
}
PROCESS{
    $a = 0
    if ($Endpoints) { 
        foreach ($i in $jobs) {
            if ($i.LastResult -ne 'Success') {
                $hash = [ordered] @{
                    Job = $i.Name
                    Type = $i.Type
                    Status = $i.LastResult
                }
            New-Object -TypeName PSObject -Property $hash
            
            }

            $a++
            }
    } else {
        foreach ($i in $jobs) {
            Write-Progress "Checking Jobs" -PercentComplete (($a / $jobs.count) * 100)
            $status = (Get-VBRJob -name $i.name).GetLastResult()
            if ($status -ne 'Success') {
                $hash = [ordered] @{
                    Job = $i.Name
                    Type = $i.JobTargetType
                    Status = $status
                }
            New-Object -TypeName PSObject -Property $hash
            
            }

            $a++
            }
    }
}

END{}
} # End Get-FailedVBRJobs function
function Get-VMBackupJobs {
    <#
    .SYNOPSIS
    This module will search through the backup jobs to find if a VM or object is contained in them. 

    .DESCRIPTION
    The Get-VMBackupJobs modules will return any jobs that a VM or object is a part of. There is an optional flag when you want to perform a loose search for the VM or Object

    .PARAMETER VMName
    The name of the VM or Object that you wish to search the backup jobs for. 

    .PARAMETER loose
    Indicates to the module that a loose search for the VMName should be performed.  

    .EXAMPLE
    Get-VMBackupJobs -VMName DC -loose
    This will return all jobs that have a non-strict regex match to the name "DC"

    .EXAMPLE
    Get-VMBackupJobs -loose
    This will return all VMs and the jobs they belong to. VMs may be listed multiple times as they can be a part of multiple jobs. 

    #> 
    param(
    [string]$VMname,
    [switch]$loose   
    ) 
BEGIN{
    Get-VBRsnapinState
    if ($loose) {
        $regex = "($VMname)"
    } else { 
        $regex = "($VMname)$"
    }
}

PROCESS { 
    $jobs = (Get-VBRJob)
    foreach ($i in $jobs) {
        $Objects = $i.getobjectsinjob()
        $matches = $objects.location | Select-String -Pattern $regex
        if ($matches) {
            $lastrun = $i.Findlastbackup()
            $Success = $i.GetLastResult()
            $state = $i.GetLastState()
            foreach ($a in $matches) { #Needed because the name may appear twice in a loose condition within the same job
                $name = $a.ToString().split("\")[-1]
                $hash = @{ 
                    Job = $i.name
                    VMName = $name
                    LastResult = $Success
                    State = $state
                }
                New-Object PSObject -Property $hash
            }
        $matches = $null
        }
    }        
} # End Process
END{}
} # End Function

function Get-VMTapeLibraryNames {
    <#
    .SYNOPSIS
    This module correlates a tape to the friendly name of the Tape Server it is associated with. 

    .DESCRIPTION
    By default, the Get-VMTapeLibraryNames associates the LibraryID of a tape that is not in the vault with the Tape Server that it is associated with. With the flags of -alltapes and -csv, the function will associate tape drives to their servers. The function looks for the CSV header to be "Tape". 

    .EXAMPLE
    Get-VMTapeLibraryNames

    .EXAMPLE
    Get-VMTapeLibraryNames -AllTapes -CSV C:/path/to/file.csv
    Returns the Tape Library that the VMs on the CSV are associated with. The function looks for the CSV header to be "Tape". 
    #>
param(
    [Switch]$AllTapes,
    [String]$Tapes,
    [String]$CSV
)  
BEGIN{
    Get-VBRsnapinState
    If ($CSV) {
        TRY{
            Test-Path $CSV | Out-Null
            $Csvtapes = Import-Csv $CSV
        } Catch {
            $_ | Out-Null
            Write-Warning "Unable to Verify CSV Path"
            BREAK
        }
        $array = @()
        <# Logic is in place due to how tapes that come in have "L4" attached to the end of the name, 
         and the tapes within Veeam are added (usually) without the "L4" at the end.  
        #>
        foreach ($i in $Csvtapes) {
            if ($i.Tape -match 'L4') {
                $i.Tape = $I.Tape.Remove('6','2')
            }
            $array += $i.Tape
        }

    }
} # End BEGIN
PROCESS {
    Write-Progress -Activity "Getting Tape Pools"
    $Library =  Get-VBRTapeLibrary
    Write-Progress -Activity "Getting Tape Drives"
    if ($AllTapes -and $CSV) { #Logic for retrieving tapes and associating them with a CSV. 
        foreach ($b in $library) {
            Write-Progress "Searching Pool $($b.name)"
            $MediaPool = Get-VBRTapeMedium -Library $b.name
            for ($a = 0; $a -lt $MediaPool.count; $a++) {
                if ($array -match $MediaPool[$a].name ) {
                    #$tapes[$a]
                    $hash =[Ordered] @{
                        'Name' = $MediaPool[$a].Name
                        'Library' = $b.name
                        'Location' = $MediaPool[$a].Location
                    }
                    New-Object -TypeName PSObject -Property $hash
                }
            }
        }       
    } elseif (($AllTapes) -and !($CSV)) { #Logic for retrieving all tapes, vault and otherwise
        foreach ($b in $library) {
            Write-Progress "Searching Pool $($b.name)"
            $MediaPool = Get-VBRTapeMedium -Library $b.name
            for ($a = 0; $a -lt $MediaPool.count; $a++) {
                #$tapes[$a]
                $hash =[Ordered] @{
                    'Name' = $MediaPool[$a].Name
                    'Library' = $b.name
                    'Location' = $MediaPool[$a].Location
                }
                New-Object -TypeName PSObject -Property $hash
            }
        }         
    } else {  #Logic for retreiving tapes that are not within the vault
        $Tapes = Get-VBRTapeMedium | where {$_.Location -notlike '*vault*'} 
        for ($a = 0; $a -lt $tapes.count; $a++) {
            $match = $library | Where {$_.ID -eq $tapes[$a].LibraryID }
            $hash =[Ordered] @{
                'Name' = $Tapes[$a].Name
                'Library' = $match.Name
                'Location' = $Tapes[$a].Location
                }
            New-Object psobject -Property $hash 
            #Clear-Variable $match
        }

    }
}
END{}
}

function Get-VBRJobRunTimes {
    <#
    .SYNOPSIS
    This function returns the run times for the last backup runs

    .DESCRIPTION
    This function will return the Job, the type, the next run time, and the last run time (total) for all jobs.

    .EXAMPLE
    Get-VBRJobRunTimes 
    This does exactly what the description says that it will. 
    #> 
BEGIN{
    Get-VBRsnapinState
    $jobs = Get-VBRJob
}
PROCESS{
    foreach ($i in $jobs) {
        $times = $i.findlastsession() 
        $runtime = ($times.endtime.subtract($times.CreationTime))
        #($i.findlastbackup().MetaUpdateTime.subtract([datetime]$i.findlastbackup().LastPointCreationTime))
        $hash = [Ordered]@{
            Job = $i.name
            Type = $i.JobType
            NextRun = $i.ScheduleOptions.NextRun
            LastRuntime = [math]::Round($runtime.minutes,1)
            }
        New-Object -TypeName PSObject -Property $hash
        }

}
END{}
}

function Get-VBRJobOverlapTimes {
    <#
    .SYNOPSIS
    This function correlates jobs to determine if any overlap while running.

    .DESCRIPTION
    This function compares all jobs (or types of jobs) to one another in order to determine if any overlapped while running. The function also returns the total amount of time that the jobs were overlapping. Please note that a parameter is mandatory.

    .EXAMPLE
    Get-VBRJobOverlapTimes -Backups
    This will return a comparison of all VM Backup Jobs.
    
    .EXAMPLE
    Get-VBRJobOverlapTimes -All
    This will return a comparison of all Backup Jobs, from VM Backup, to BackupSync, to Replica.
    
    .EXAMPLE
    Get-VBRJobOverlapTimes -Tape
    Unsure if this will even return anything because of how slow Get-VBRTapeJob is as a function.
         
    #> 
    param(
        [Parameter(ParameterSetname='Backup',Mandatory=$true)]
            [Switch]$Backup,
        [Parameter(ParameterSetname='All',Mandatory=$true)]
            [Switch]$All,
        [Parameter(ParameterSetname='BackupSync',Mandatory=$true)]
            [switch]$BackupSync,
        [Parameter(ParameterSetname='Replica',Mandatory=$true)]
            [switch]$Replica,
        [Parameter(ParameterSetname='Tape',Mandatory=$true)]
            [Switch]$Tape
    )
BEGIN{
    Get-VBRsnapinState
    switch ($PSCmdlet.ParameterSetName) {
        'All' {
            $jobs = Get-VBRJob
            }
        'BackupSync' { 
            $jobs = Get-VBRJob | where {$_.JobType -eq 'BackupSync'} 
            }
        'Replica' { 
            $jobs = Get-VBRJob | where {$_.JobType -eq 'Replica'} 
            }
        'Tape' { 
            $jobs = Get-VBRTapeJob 
            }
        'Backup' { 
            $jobs = Get-VBRJob | where {$_.JobType -eq 'Backup'} 
            }
    }
}
PROCESS{
    $jobs = $jobs | where {$_.IsScheduleEnabled} #Filter Out Disabled Jobs
    $times = $jobs.findlastsession()
    $EndTimes = $times.EndTime
    $StartTimes = $times.CreationTime
    for ($a = 0; $a -lt $jobs.count; $a++) {
        for ($b = 0; $b -lt $jobs.count; $b ++) {
            if ($a -ne $b) { 
                if (($EndTimes[$a] -gt $StartTimes[$b]) -and ($EndTimes[$a] -lt $EndTimes[$b])) { 
                    #Write-Output "Job $($Jobs[$a].Name) overlaps with $($Jobs[$b].Name)"
                    if (($StartTimes[$a] -gt $StartTimes[$b]) -and ($EndTimes[$a] -lt $EndTimes[$b])) {
                        $overlaptime = ($Endtimes[$a].subtract($StartTimes[$a]))
                        } else { 
                        $overlaptime = ($EndTimes[$a].subtract($StartTimes[$b]))
                        }
                    $hash = [Ordered]@{
                        Job = $jobs[$b].Name
                        OverlapJob = $jobs[$a].name
                        JobStart = $StartTimes[$b]
                        JobEnd = $EndTimes[$b]
                        OverlapJobStart = $StartTimes[$a]
                        OverlapJobEnd = $EndTimes[$a]
                        OverlapTime = [math]::ceiling($overlaptime.minutes)
                    }
                New-Object -TypeName psobject -Property $hash
                }
            }
        }
    }
}
END{}

}

    