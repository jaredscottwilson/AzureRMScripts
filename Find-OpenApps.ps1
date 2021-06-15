####Pre-reqs####################################################
#Must have Azure Powershell
#Will only work on subscriptions that have the account you authenticate to has access to. 
#Works best with one account that has read-only access to all subscriptions
#Must enable Powershell scripts on your host
#Author: Jared Wilson
#Date 5/18/2020
################################################################

#IMPORTANT - If you don't have a connected Azure account to PS, you use this to connect/auth
#Connect-AzAccount

#make sure to set your own path for files that have your final results
$global:results_path = "C:\Users\$env:UserName\Desktop\AzureRm\results\"
$global:date = (Get-Date -UFormat "%Y-%m-%d")

If(!(test-path $global:results_path ))
{
      New-Item -ItemType Directory -Force -Path $path
}

$subscriptions = Get-AzRmSubscription 
$subscriptions = ($subscriptions.Name | sort | Get-Unique)

foreach($line in $subscriptions) {
	$global:web = ""
	Select-AzSubscription -SubscriptionName $line
	$webapps = (Get-AzResource -ResourceType "Microsoft.Web/sites")
	foreach($item in $webapps) {
		$resourcename = $item.("ResourceGroupName")
		$name = $item.("Name")
		$location = $item.("Location")
		$url = (Get-AzWebApp -ResourceGroupName $resourcename -Name $name).DefaultHostName
		try { $global:web = Invoke-WebRequest $url } 
		catch { continue }
		$statusCode = $global:web.statusCode
		$size = $global:web.RawContentLength
		if(($statusCode -eq "200") -AND (-Not ($global:web.content | Select-String "Your Function App is up and running" -quiet)) -AND (-Not ($global:web.content | Select-String "Your Function App 2.0 preview is up and running" -quiet)) -AND (-Not ($global:web.content | Select-String "Your App Service app has been created" -quiet)) -AND (-Not ($global:web.content | Select-String "Your App Service app is up and running")) -AND (-Not ($global:web.content | Select-String "This Java based web application has been successfully created"))  -AND (-Not ($global:web.content | Select-String "<h1>This web site is running Python 3.6.6</h1>")) -AND (-Not ($global:web.content | Select-String "<title>Your Azure Function App is up and running.</title>")) -AND (-Not ($global:web.content | Select-String "<title>Microsoft Azure App Service - Welcome</title>")) -AND (-Not ($global:web.content | Select-String "<title>Your Azure Function App is up and running.</title>"))){$url >> $global:results_path$date'publicURL.txt'}
	}
}
			
		
