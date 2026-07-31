<#
.ATTRIBUTION
    This script and the accompanying FakeNames.csv sample data were sourced from:
    https://github.com/fierytermite/practicalthreathunting/tree/master
    Original author: fierytermite
    Used here for lab/educational purposes.
#>

<#
.Synopsis
   Test a CSV from FakeNameGenerator.com for required fields.
.DESCRIPTION
  Test a CSV from FakeNameGenerator.com for required fields.
.EXAMPLE
   Test-LabADUserList -Path .\FakeNameGenerator.com_b58aa6a5.csv
#>
function Test-LabADUserList
{
    [CmdletBinding()]
    [OutputType([Bool])]
    Param
    (
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to CSV generated from fakenamegenerator.com.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path
    )

    Begin {}
    Process
    {
        # Test if the file exists.
        if (Test-Path -Path $Path -PathType Leaf) 
        {
            Write-Verbose -Message "Testing file $($Path)"
        } 
        else 
        {
            Write-Error -Message "File $($Path) was not found or not a file." 
            $false
            return
        }

        # Get CSV header info.
        $fileinfo = Import-Csv -Path $Path | Get-Member | Select-Object -ExpandProperty Name
        $valid = $true
        
            
        if ('City' -notin $fileinfo) {
            Write-Warning -Message 'City field is missing'
            $valid =  $false
        }

        if ('Country' -notin $fileinfo) {
            Write-Warning -Message 'Country field is missing'
            $valid =  $false
        }


        if ('GivenName' -notin $fileinfo) {
            Write-Warning -Message 'GivenName field is missing'
            $valid =  $false
        }

        if ('Occupation' -notin $fileinfo) {
            Write-Warning -Message 'Occupation field is missing'
            $valid =  $false
        }

        if ('Password' -notin $fileinfo) {
            Write-Warning -Message 'Password field is missing'
            $valid =  $false
        }

        if ('StreetAddress' -notin $fileinfo) {
            Write-Warning -Message 'StreetAddress field is missing'
            $valid =  $false
        }

        if ('Surname' -notin $fileinfo) {
            Write-Warning -Message 'Surname field is missing'
            $valid =  $false
        }

        if ('TelephoneNumber' -notin $fileinfo) {
            Write-Warning -Message 'TelephoneNumber field is missing'
            $valid =  $false
        }

        if ('Username' -notin $fileinfo) {
            Write-Warning -Message 'Username field is missing'
            $valid =  $false
        } 

        $valid
    }
    End {}
}

<#
.SYNOPSIS
    Generates a semi random string.
.DESCRIPTION
    Generates a semi random string.
.EXAMPLE
    C:\PS> Get-RandomString

#>
function Get-RandomString {
    [CmdletBinding()]
    param(
        # Size of string
        [Parameter(Mandatory=$false,
                   HelpMessage='Lenght of random string,')]
        [int]
        $Lenght = 5
    )
    
    begin {
    }
    
    process {
        -join ((65..90) + (97..122) | Get-Random -Count $Lenght | % {[char]$_})
    }
    
    end {
    }
}


<#
.Synopsis
   Removes duplicate username entries from Fake Name Generator generated accounts.
.DESCRIPTION
   Removes duplicate username entries from Fake Name Generator generated accounts. Bulk
   generated accounts from fakenamegenerator.com must have as fields:
   * GivenName
   * Surname
   * StreetAddress
   * City
   * Title
   * Username
   * Password
   * Country
   * TelephoneNumber
   * Occupation
.EXAMPLE
    Remove-LabADUsertDuplicate -Path .\FakeNameGenerator.com_b58aa6a5.csv -OutPath .\unique_users.csv
#>
function Remove-LabADUsertDuplicate
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   Position=0,
                   ParameterSetName="Path",
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to CSV to remove duplicates from.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,

        [Parameter(Mandatory=$true,
                   Position=1,
                   ParameterSetName="Path",
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to CSV to remove duplicates from.")]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutPath
    )

    Begin {}
    Process
    {
        Write-Verbose -Message "Processing $($Path)"
        if (Test-LabADUserList -Path $Path) {
            Import-Csv -Path $Path | Group-Object Username | Foreach-Object {
                $_.group | Select-Object -Last 1} | Export-Csv -Path $OutPath -Encoding UTF8
        } else {
            Write-Error -Message "File $($Path) is not valid."
        }
        
    }
    End {}
}

<#
.SYNOPSIS
    Imports a CSV from Fake Name Generator to create test AD User accounts.
.DESCRIPTION
    Imports a CSV from Fake Name Generator to create test AD User accounts. 
    It will create OUs per country under the OU specified. Bulk
    generated accounts from fakenamegenerator.com must have as fields:
    * GivenName
    * Surname
    * StreetAddress
    * City
    * Title
    * Username
    * Password
    * Country
    * TelephoneNumber
    * Occupation

    The -OrganizationalUnit parameter accepts either:
      - A simple OU name (e.g. "DemoUsers") - looked up by name, created at domain root if missing
      - A full distinguished name (e.g. "OU=Users,OU=LAB,DC=lab,DC=local") - used directly
.EXAMPLE
    C:\PS> Import-LabADUser -Path .\unique.csv -OU DemoUsers
.EXAMPLE
    C:\PS> Import-LabADUser -Path .\unique.csv -OU "OU=Users,OU=LAB,DC=lab,DC=local"
#>
function Import-LabADUser
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to one or more locations.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Path,

        [Parameter(Mandatory=$true,
                   position=1,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Organizational Unit name or DistinguishedName.")]
        [String]
        [Alias('OU')]
        $OrganizationalUnit
    )
    
    begin {
        if (-not (Get-Module -Name 'ActiveDirectory')) {
            Write-Error -Message 'ActiveDirectory module is not present'
            return
        }
    }
    
    process {
        Import-Module -Name ActiveDirectory
        $DomDN = (Get-ADDomain).DistinguishedName
        $forest = (Get-ADDomain).Forest

        # --- Resolve the target OU ---
        if ($OrganizationalUnit -match '^(OU|CN)=') {
            # Full DN provided - use it directly
            try {
                $ou = Get-ADOrganizationalUnit -Identity $OrganizationalUnit
            } catch {
                Write-Error -Message "OU not found: $OrganizationalUnit"
                return
            }
        } else {
            # Simple name - search, create at domain root if not found
            $ou = Get-ADOrganizationalUnit -Filter "name -eq '$($OrganizationalUnit)'"
            if ($ou -eq $null) {
                New-ADOrganizationalUnit -Name "$($OrganizationalUnit)" -Path $DomDN
                $ou = Get-ADOrganizationalUnit -Filter "name -eq '$($OrganizationalUnit)'"
            }
        }

        # Bail out if OU could not be resolved
        if ($ou -eq $null) {
            Write-Error -Message "Failed to create or find OU '$OrganizationalUnit'. Aborting."
            return
        }

        Write-Host "Using target OU: $($ou.DistinguishedName)" -ForegroundColor Green

        Import-Csv -Path $Path | Select-Object @{Name="Name";Expression={$_.Surname + ", " + $_.GivenName}},
                @{Name="SamAccountName"; Expression={$_.Username}},
                @{Name="GivenName"; Expression={$_.GivenName}},
                @{Name="Surname"; Expression={$_.Surname}},
                @{Name="City"; Expression={$_.City}},
                @{Name="AccountPassword"; Expression={ (ConvertTo-SecureString -Force -AsPlainText $_.Password)}},
                @{Name="Enabled"; Expression={$true}},
                @{Name="UserPrincipalName"; Expression={$_.Username + "@" + $forest}},
                @{Name="DisplayName"; Expression={$_.Surname + ", " + $_.GivenName}},
                @{Name="StreetAddress"; Expression={$_.StreetAddress}},
                @{Name="EmailAddress"; Expression={$_.Username + "@" + $forest}},
                @{Name="Country"; Expression={$_.Country}},
                @{Name="OfficePhone"; Expression={$_.TelephoneNumber}},
                @{Name="Title"; Expression={$_.Occupation}},
                @{Name="PasswordNeverExpires"; Expression={$true}} | ForEach-Object -Process {

                    # --- Country-level OU under the target OU ---
                    $subou = Get-ADOrganizationalUnit -Filter "name -eq ""$($_.Country)""" -SearchBase $ou.DistinguishedName
                    if ($subou -eq $null) {
                        New-ADOrganizationalUnit -Name $_.Country -Path $ou.DistinguishedName
                        $subou = Get-ADOrganizationalUnit -Filter "name -eq ""$($_.Country)""" -SearchBase $ou.DistinguishedName
                    }

                    # --- City-level OU under the Country OU ---
                    $child_subou = Get-ADOrganizationalUnit -Filter "name -eq ""$($_.City)""" -SearchBase $subou.DistinguishedName
                    if ($child_subou -eq $null) {
                        New-ADOrganizationalUnit -Name $_.City -Path $subou.DistinguishedName
                        $child_subou = Get-ADOrganizationalUnit -Filter "name -eq ""$($_.City)""" -SearchBase $subou.DistinguishedName
                    }

                    # --- Create the user in the City OU ---
                    $_ | Select-Object @{Name="Path"; Expression={$child_subou.DistinguishedName}}, * | New-ADUser
                }
    }    
    end {}
}