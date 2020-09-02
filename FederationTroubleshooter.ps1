<#
.NOTES
	Name: FederationTroubleshooter.ps1
    Author: Josh Jerdon
    Email: jojerd@microsoft.com
	Requires: Administrative Priveleges
	Version History:
    1.02 Initial development.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
	BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
	DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    .SYNOPSIS
    Collects different logs and data used to diagnose and troubleshoot Federation Free / Busy related issues.
    Collects federation certificate details, federation trust details, organization relationships as well as compares system time
    with Windows time server.

    #>   
function ExchangeOnline {
    # Create Log Directories Silently
    New-item -Path ./Troubleshooterlogs -ItemType Directory | Out-Null
    New-Item -Path ./Troubleshooterlogs/Orgs -ItemType Directory | Out-Null

    # Get Federation Certificate Details
    $CertDetails = Get-ExchangeCertificate | Where-Object { $_.CertificateDomains -like "Federation" } | format-list -Property *

    # Output Federation Certificate findings to log file.
    $CertDetails | Out-File .\Troubleshooterlogs\FederationCertificate.log
    
    $OrgRelationships = Get-OrganizationRelationship
    # Retrieve Organization Relationship Details and Output Each Org into an Individual File.
    if ($OrgRelationships.count -gt 0) {
        foreach ($Org in $OrgRelationships) {        
            $OrgName = $Org.Name
            $OrgData = $Org | Format-List -Property *
            $OrgData | Out-File .\Troubleshooterlogs\Orgs\$OrgName.log
        }
    }
    else {
        # Report error if unable to retrieve organization relationship details.
        Write-Error Unable to find any Organization Relationships. -ErrorAction Continue
        Start-Sleep -Seconds 3
    }
    # Retrieve Federation Trust Details.
    $FedTrust = Get-FederationTrust | Format-List
    $FedTrust | Out-File .\Troubleshooterlogs\FederationTrust.log
    Clear-Host
    # Test Federation Trust to ensure everything is configured correctly and dump results to log.
    Write-Host " "
    $User = Read-Host -Prompt "Enter an Email address to test Federation Trust with, Example User@YourDomain.com"
    $FedTest = Test-FederationTrust -UserIdentity $User | format-List
    $FedTest | Out-File .\Troubleshooterlogs\FederationTrustTestResults.log
    
}
    
function ExchangeOnPrem {
    #Check Powershell version.
    if ($PSVersionTable.PSVersion.Major -gt 3) {
        Write-Host "PowerShell meets minimum version requirements, continuing...."
            
        # Check if Exchange Management is already loaded, if so continue, if not load the management snap-in.  
        $CheckSnapin = (Get-PSSnapin | Where-Object { $_.Name -eq "Microsoft.Exchange.Management.PowerShell.E2010" } | Select-Object Name)
        
        if ($CheckSnapin -like "*Exchange.Management.Powershell*") {
            Write-Host " "
            Write-Host "Exchange Snap-in already loaded, continuing" -ForegroundColor Green
            Start-Sleep -Seconds 3
            Clear-Host
        }
        else {
            Write-Host " "
            Write-Host "Loading Exchange Snap-in, Please Wait..."
            Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010 -ErrorAction Stop
            Clear-Host
        }
        #Create log files destinations.
        New-item -Path ./Troubleshooterlogs -ItemType Directory | Out-Null
        New-Item -Path ./Troubleshooterlogs/Orgs -ItemType Directory | Out-Null
        
        # Get Federation Certificate Details
        $CertDetails = Get-ExchangeCertificate | Where-Object { $_.CertificateDomains -like "Federation" } | format-list -Property *

        # Output Federation Certificate findings to log file.
        $CertDetails | Out-File .\Troubleshooterlogs\FederationCertificate.log
        
        $OrgRelationships = Get-OrganizationRelationship
        # Retrieve Organization Relationship Details and Output Each Org into an Individual File.
        if ($OrgRelationships.count -gt 0) {
            foreach ($Org in $OrgRelationships) {        
                $OrgName = $Org.Name
                $OrgData = $Org | Format-List -Property *
                $OrgData | Out-File .\Troubleshooterlogs\Orgs\$OrgName.log
            }
        }
        else {
            # Report error if unable to retrieve organization relationship details.
            Write-Error Unable to find any Organization Relationships. -ErrorAction Continue
            Start-Sleep -Seconds 3
        }
        # Retrieve Federation Trust Details.
        $FedTrust = Get-FederationTrust | Format-List
        $FedTrust | Out-File .\Troubleshooterlogs\FederationTrust.log
        Clear-Host
        # Test Federation Trust to ensure everything is configured correctly and dump results to log.
        Write-Host " "
        $User = Read-Host -Prompt "Enter an Email address to test Federation Trust with, Example User@YourDomain.com"
        $FedTest = Test-FederationTrust -UserIdentity $User | format-List
        $FedTest | Out-File .\Troubleshooterlogs\FederationTrustTestResults.log

        # Compare Systems time with Windows Time server.
        $TimeComparison = w32tm.exe /stripchart /computer:time.windows.com /samples:5 /data
        # Output time comparison details to log file.
        $TimeComparison | Out-File .\Troubleshooterlogs\TimeComparison.log
        
    }
        
    else {
        Write-Error 'PowerShell does not meet minimum version requirements, unable to continue...' -ErrorAction Stop
    }
    
}

$Admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
if ($Admin -eq 'True') {
    Write-Host " "
    Write-Host "Script was executed with elevated permissions, continuing..." -ForegroundColor Green
    Start-Sleep -Seconds 3
    Clear-Host
}
else {
    Write-Error 'This script needs to be executed under PowerShell with Administrative Privileges....' -ErrorAction Stop
}

# Check if PowerShell is being run from Exchange Online or Exchange OnPrem.
$ExchangeSession = Get-PSSession | Select-Object ComputerName

if ($ExchangeSession.ComputerName -like "outlook.office365.com") {
    ExchangeOnline
}
else {
    ExchangeOnPrem
}

    

    