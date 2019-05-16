####Pre-reqs####################################################
#Must have Azure Powershell
#Will only work on subscriptions that have the account you authenticate to has access to. 
#Works best with one account that has read-only access to all subscriptions
#Must enable Powershell scripts on your host
################################################################
#Make sure to set a temp_path for working files and a results_path for results
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
	Get-AzureRmResource -ResourceType "Microsoft.Storage/storageAccounts" | Export-Csv -Path $global:temp_path$line'.csv'
	$blobs = Import-Csv $global:temp_path$line'.csv'
	foreach($item in $blobs) {
		$resourcename = $item.("ResourceGroupName")
		$subscriptionid = $item.("SubscriptionId")
		$name = $item.("Name")
		$open = Get-AzureStorageContainer  -Context ((Get-AzureRmStorageAccount -ResourceGroupName $resourcename -AccountName $name).Context) | Where { $_.PublicAccess -ne "Off" }
		if($open) {
			$open >>$global:results_path$date'publicBlob.txt'
			}
		}
	}
Remove-Item $global:temp_path*.csv  -Exclude 2018*
