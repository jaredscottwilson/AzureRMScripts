####Pre-reqs####################################################
#Must have Azure Powershell
#Will only work on subscriptions that have the account you authenticate to has access to. 
#Works best with one account that has read-only access to all subscriptions
#Must enable Powershell scripts on your host
#Make sure to set a temp_path for working files and a results_path for results
####Pre-reqs####################################################
#Will search for a public IP or FQDN and then test access and see if
#it's returning 200 OK, will save all IPs/FQDN for records
################################################################


Connect-AzureRmAccount

#make sure to set your own path for temporary files
$global:temp_path = "[Enter Temp Path as String Here]"
#make sure to set your own path for files that have your final results
$global:results_path = "[Enter Results Path as String Here]"

$global:date = (Get-Date -UFormat "%Y-%m-%d")
$subscriptions = Get-AzureRmSubscription 
$subscriptions.Name | sort | Get-Unique | Out-File  $global:temp_path$date'_subscriptions.txt'

foreach($line in Get-Content $global:temp_path$date'_subscriptions.txt') {
	Select-AzureRmSubscription -SubscriptionName $line
	Get-AzureRmResource -ResourceType "Microsoft.Network/publicIPAddresses"| Export-Csv -Path $global:temp_path$line'.csv'
	$pubIPResource = Import-Csv $global:temp_path$line'.csv'
	foreach($item in $pubIPResource) {
		$resourcename = $item.("ResourceGroupName")
		$subscriptionid = $item.("SubscriptionId")
		$name = $item.("Name")
		$publicIp = Get-AzureRmPublicIpAddress -Name $name -ResourceGroupName $resourcename
			
		$fqdnresponsecode=$false
		$ipresponsecode=$false
		
		$ip=$publicIp.IpAddress
		if(($ip -ne "Not Assigned") -And $ip){
			try { 
				$ipresponsecode = (Invoke-WebRequest $ip).StatusCode 
				if($ipresponsecode -eq "200"){
					$date = (Get-Date -UFormat "%Y-%m-%d")
					Write-Host $ip' is open'
					#writing to output just for tracking
					$name >> $global:results_path$date'pubIP.txt'
					$ip >> $global:results_path$date'pubIP.txt'
				}
			}
			catch {
				Write-Host "$ip returned something other than a 200 OK"
			}
		}
		
		$fqdn=$publicIp.DnsSettings.Fqdn
		
		if(($fqdn -ne "Not Assigned") -And $fqdn){
			try { 
				$fqdnresponsecode = (Invoke-WebRequest $fqdn).StatusCode 
				if($fqdnresponsecode -eq "200"){
					$date = (Get-Date -UFormat "%Y-%m-%d")
					Write-Host $fqdn' is open'
					#writing to output just for tracking
					$name >> $global:results_path$date'pubIP.txt'
					$fqdn >> $global:results_path$date'pubIP.txt'
				}
			}
			catch {
				Write-Host "$fqdn returned something other than a 200 OK"
			}
		}
		
		#Keeping all for records
		$fqdn >> $global:temp_path$date'record_keeping_ips-fqdn.txt'
		$ip >> $global:temp_path$date'record_keeping_ips-fqdn.txt'
		
	}
}

Remove-Item $global:temp_path*.csv
