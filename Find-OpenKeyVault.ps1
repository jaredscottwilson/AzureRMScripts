####Pre-reqs####################################################
#Must have Azure Powershell
#Will only work on subscriptions that have the account you authenticate to has access to. 
#Works best with one account that has read-only access to all subscriptions
#Must enable Powershell scripts on your host
#Author: Jared Wilson
#Date 5/18/2020
################################################################

######################################################
#Reference: https://gallery.technet.microsoft.com/scriptcenter/Validate-an-Ipaddress-is-03481731
Function IS-InSubnet() 
{ 
 
[CmdletBinding()] 
[OutputType([bool])] 
Param( 
                    [Parameter(Mandatory=$true, 
                     ValueFromPipelineByPropertyName=$true, 
                     Position=0)] 
                    [validatescript({([System.Net.IPAddress]$_).AddressFamily -match 'InterNetwork'})] 
                    [string]$ipaddress="", 
                    [Parameter(Mandatory=$true, 
                     ValueFromPipelineByPropertyName=$true, 
                     Position=1)] 
                    [validatescript({(([system.net.ipaddress]($_ -split '/'|select -first 1)).AddressFamily -match 'InterNetwork') -and (0..32 -contains ([int]($_ -split '/'|select -last 1) )) })] 
                    [string]$Cidr="" 
    ) 
Begin{ 
        [int]$BaseAddress=[System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse(($cidr -split '/'|select -first 1))).GetAddressBytes()),0) 
        [int]$Address=[System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($ipaddress).GetAddressBytes()),0) 
        [int]$mask=[System.Net.IPAddress]::HostToNetworkOrder(-1 -shl (32 - [int]($cidr -split '/' |select -last 1))) 
} 
Process{ 
        if( ($BaseAddress -band $mask) -eq ($Address -band $mask)) 
        { 
 
            $status=$True 
        }else { 
 
        $status=$False 
        } 
} 
end { Write-output $status } 
} 
################################################################

#IMPORTANT - If you don't have a connected Azure account to PS, you use this to connect/auth
#Connect-AzureRmAccount

$overall_findings = New-Object System.Collections.Generic.List[System.Object]

#make sure to set your own path for files that have your final results
$global:results_path = "C:\Users\$env:UserName\Desktop\AzureRm\results\"
$global:date = (Get-Date -UFormat "%Y-%m-%d")

#this needs to be a list of known external company facing IPs and MSFT IPs. When firewall rules are checked they can be checked against this list. So whatever in here needs to be "known good". You can always go back and add then re-run
$knownIps = "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"

If(!(test-path $global:results_path ))
{
      New-Item -ItemType Directory -Force -Path $path
}

$subscriptions = Get-AzureRmSubscription 
$subscriptions = ($subscriptions.Name | sort | Get-Unique)
foreach($line in $subscriptions) {
	Select-AzureRmSubscription -SubscriptionName $line		
	$keyvaults = (Get-AzureRmResource -ResourceType "Microsoft.KeyVault/vaults")
	foreach($item in $keyvaults) {
		$resourcename = $item.("ResourceGroupName")
		$subscriptionid = $item.("SubscriptionId")
		$name = $item.("Name")
		$kv = Get-AzureRmKeyVault -ResourceGroupName $resourcename -VaultName $name
		$acls = (Get-AzureRmKeyVault -ResourceGroupName $resourcename -VaultName $name).NetworkAcls
		$default_action = (Get-AzureRmKeyVault -ResourceGroupName $resourcename -VaultName $name).NetworkAcls.DefaultAction
		$ip_ranges = (Get-AzureRmKeyVault -ResourceGroupName $resourcename -VaultName $name).NetworkAcls.IpAddressRanges
		if ((!$ip_ranges) -And ($default_action -ne "Deny") -And (!$acls.VirtualNetworkResourceIds)){
			$finding = $name + " has a completely empty IP allow section with " + $default_action + " default action"
			$finding  | Out-File -FilePath $global:results_path$date'openKeyVault.txt' -Append
		}
		else{
			foreach($ip in $ip_ranges){
				if($ip){
					$findings = New-Object 'Collections.Generic.List[Tuple[bool,string]]'
					foreach($range in $knownIps){
						$match_bool = $FALSE
						$subnet_bool = $FALSE
						if($ip -Match '/'){
							if($ip -eq $range){
								$match_bool = $TRUE
								$myTuple = [Tuple]::Create($match_bool,$ip) 
								$findings.Add( $myTuple)
								}
							else{
								$match_bool = $FALSE
								$myTuple = [Tuple]::Create($match_bool,$ip) 
								$findings.Add( $myTuple)
							}
						}
						elseif(IS-InSubnet -ipaddress $ip -Cidr $range){
							$subnet_bool = $TRUE
							$myTuple = [Tuple]::Create($subnet_bool,$ip) 
							$findings.Add( $myTuple)
						}
						else{
							$subnet_bool = $FALSE
							$myTuple = [Tuple]::Create($subnet_bool,$ip) 
							$findings.Add( $myTuple)
							}
						}
						$match = $FALSE
						foreach($item in $findings){
							if($item.Item1 -eq $TRUE){$match = $TRUE}
							}
						if(!$match){
							$out = $name + " has an odd rule allowing " + $ip
							$overall_findings.Add($out)
							}
						}
					}
				}
			}
		}
		
	
									
$finalList = $overall_findings | Sort-Object | Get-Unique
foreach($hit in $finalList){
	$hit | Out-File -FilePath $global:results_path$date'openKeyVault.txt'  -Append
}
