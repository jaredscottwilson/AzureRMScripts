####Pre-reqs####################################################
#Must have Azure Powershell
#Will only work on subscriptions that have the account you authenticate to has access to. 
#Works best with one account that has read-only access to all subscriptions
#Must enable Powershell scripts on your host
#Author: Jared Wilson
#Date 5/18/2020
################################################################

#IMPORTANT - If you don't have a connected Azure account to PS, you use this to connect/auth
#Connect-AzureRmAccount

#make sure to set your own path for files that have your final results
$global:results_path = "C:\Users\$env:UserName\Desktop\AzureRm\results\"
$global:date = (Get-Date -UFormat "%Y-%m-%d")

If(!(test-path $global:results_path ))
{
      New-Item -ItemType Directory -Force -Path $path
}

$subscriptions = Get-AzureRmSubscription 
$subscriptions = ($subscriptions.Name | sort | Get-Unique)
foreach($line in $subscriptions) {
	Select-AzureRmSubscription -SubscriptionName $line
	$storage_account = Get-AzureRmResource -ResourceType "Microsoft.Storage/storageAccounts" 
	foreach($item in $storage_account) {
		$resourcename = $item.("ResourceGroupName")
		$subscriptionid = $item.("SubscriptionId")
		$name = $item.("Name")

		$open = Get-AzureStorageContainer  -Context ((Get-AzureRmStorageAccount -ResourceGroupName $resourcename -AccountName $name).Context) | Where { ($_.PublicAccess -ne "Off") -and ($_.LastModified.DateTime -gt ((get-date).AddHours(-36))) }
		if ($open){
			$open >> $global:results_path$date'publicBlob.txt'}
		}
	}

