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

$outItems = New-Object System.Collections.Generic.List[System.Object]

#this needs to be a list of known external company facing IPs and MSFT IPs. When firewall rules are checked they can be checked against this list. So whatever in here needs to be "known good". You can always go back and add then re-run
$knownIps = "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"


#make sure to set your own path for files that have your final results
$global:results_path = "C:\Users\$env:UserName\Desktop\AzureRm\results\"
$global:date = (Get-Date -UFormat "%Y-%m-%d")

If(!(test-path $global:results_path )){New-Item -ItemType Directory -Force -Path $path}

$subscriptions = Get-AzureRmSubscription 
$subscriptions = ($subscriptions.Id | sort | Get-Unique)
foreach($line in $subscriptions) {
	Select-AzureRmSubscription -SubscriptionName $line		
	$resource = (Get-AzureRmResource -ResourceType "Microsoft.Cache/Redis")
	foreach($redis in $resource) {
		$name = $redis.Name
		$rg = $redis.ResourceGroupName
		$sub = $line
		$properties = Get-AzureRmRedisCache -Name $name -ResourceGroupName $rg
		if($properties.EnableNonSslPort){
			$finding = $name+" has non-SSL port enabled"
			$outItems.Add($finding)
		}
		$rules = Get-AzureRmRedisCacheFirewallRule -Name $name -ResourceGroupName $rg
		foreach($rule in $rules){
			$rulename = $rule.RuleName
			$start = $rule.StartIP
			$end = $rule.EndIP
			$rule_findings = New-Object 'Collections.Generic.List[Tuple[bool,string,string]]'
			foreach($range in $knownIps){
				$fw_match = $FALSE
				if((IS-InSubnet -ipaddress $start -Cidr $range) -Or (IS-InSubnet -ipaddress $end -Cidr $range)){
					$fw_match = $TRUE
					$myTuple = [Tuple]::Create($fw_match,$start,$end) 
					$rule_findings.Add( $myTuple)
				}
				else{
					$fw_match = $FALSE
					$myTuple = [Tuple]::Create($fw_match,$start,$end) 
					$rule_findings.Add( $myTuple)
					}
				}
			$match = $FALSE
			foreach($item in $rule_findings){
				if($item.Item1 -eq $TRUE){$match = $TRUE}
			}
			if(!$match){
				$out = 'Rule '+$ruleName+' has an odd ip range '+$start+' to '+$end+' for '+$name
				$outItems.Add($out)
			}
		
		}
	}
}
$finalList = $outItems | Sort-Object | Get-Unique
foreach($string in $finalList){$string | Out-File -FilePath $global:results_path$date'OpenRedis.txt'  -Append}


