#####################################################
#				                    #
#    Audit script V3 by Alan Renouf - Virtu-Al      #
#    Blog: http://virtu-al.net/	                    #
#	     		                            #
#    Usage: Audit.ps1 'pathtolistofservers'         #
# 			                            #
#    The file is optional and needs to be a 	    #
#	 plain text list of computers to be audited #
#	 one on each line, if no list is specified  #
#	 the local machine will be audited.         # 
#                                                   #
#####################################################

param( [string] $auditlist)

Function Get-CustomHTML ($Header){
$Report = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<html><head><title>$($Header)</title>
<META http-equiv=Content-Type content='text/html; charset=windows-1252'>
<meta name="save" content="history">
<style type="text/css">
DIV .expando {DISPLAY: block; FONT-WEIGHT: normal; FONT-SIZE: 8pt; RIGHT: 8px; COLOR: #ffffff; FONT-FAMILY: Arial; POSITION: absolute; TEXT-DECORATION: underline}
TABLE {TABLE-LAYOUT: fixed; FONT-SIZE: 100%; WIDTH: 100%}
*{margin:0}
.dspcont { display:none; BORDER-RIGHT: #B1BABF 1px solid; BORDER-TOP: #B1BABF 1px solid; PADDING-LEFT: 16px; FONT-SIZE: 8pt;MARGIN-BOTTOM: -1px; PADDING-BOTTOM: 5px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; WIDTH: 95%; COLOR: #000000; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; BACKGROUND-COLOR: #f9f9f9}
.filler {BORDER-RIGHT: medium none; BORDER-TOP: medium none; DISPLAY: block; BACKGROUND: none transparent scroll repeat 0% 0%; MARGIN-BOTTOM: -1px; FONT: 100%/8px Tahoma; MARGIN-LEFT: 43px; BORDER-LEFT: medium none; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: medium none; POSITION: relative}
.save{behavior:url(#default#savehistory);}
.dspcont1{ display:none}
a.dsphead0 {BORDER-RIGHT: #B1BABF 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #B1BABF 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; CURSOR: hand; COLOR: #FFFFFF; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #CC0000}
a.dsphead1 {BORDER-RIGHT: #B1BABF 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #B1BABF 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; CURSOR: hand; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #7BA7C7}
a.dsphead2 {BORDER-RIGHT: #B1BABF 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #B1BABF 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; CURSOR: hand; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #7BA7C7}
a.dsphead1 span.dspchar{font-family:monospace;font-weight:normal;}
td {VERTICAL-ALIGN: TOP; FONT-FAMILY: Tahoma}
th {VERTICAL-ALIGN: TOP; COLOR: #CC0000; TEXT-ALIGN: left}
BODY {margin-left: 4pt} 
BODY {margin-right: 4pt} 
BODY {margin-top: 6pt} 
</style>
<script type="text/javascript">
function dsp(loc){
   if(document.getElementById){
      var foc=loc.firstChild;
      foc=loc.firstChild.innerHTML?
         loc.firstChild:
         loc.firstChild.nextSibling;
      foc.innerHTML=foc.innerHTML=='hide'?'show':'hide';
      foc=loc.parentNode.nextSibling.style?
         loc.parentNode.nextSibling:
         loc.parentNode.nextSibling.nextSibling;
      foc.style.display=foc.style.display=='block'?'none':'block';}}  
if(!document.getElementById)
   document.write('<style type="text/css">\n'+'.dspcont{display:block;}\n'+ '</style>');
</script>
</head>
<body>
<b><font face="Arial" size="5">$($Header)</font></b><hr size="8" color="#CC0000">
<font face="Arial" size="1"><b>Version 3 by Alan Renouf virtu-al.net</b></font><br>
<font face="Arial" size="1">Report created on $(Get-Date)</font>
<div class="filler"></div>
<div class="filler"></div>
<div class="filler"></div>
<div class="save">
"@
Return $Report
}

Function Get-CustomHeader0 ($Title){
$Report = @"
		<h1><a class="dsphead0">$($Title)</a></h1>
	<div class="filler"></div>
"@
Return $Report
}

Function Get-CustomHeader ($Num, $Title){
$Report = @"
	<h2><a href="javascript:void(0)" class="dsphead$($Num)" onclick="dsp(this)">
	<span class="expando">show</span>$($Title)</a></h2>
	<div class="dspcont">
"@
Return $Report
}

Function Get-CustomHeaderClose{

	$Report = @"
		</DIV>
		<div class="filler"></div>
"@
Return $Report
}

Function Get-CustomHeader0Close{

	$Report = @"
</DIV>
"@
Return $Report
}

Function Get-CustomHTMLClose{

	$Report = @"
</div>
</body>
</html>
"@
Return $Report
}

Function Get-HTMLTable{
	param([array]$Content)
	$HTMLTable = $Content | ConvertTo-Html
	$HTMLTable = $HTMLTable -replace '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">', ""
	$HTMLTable = $HTMLTable -replace '<html xmlns="http://www.w3.org/1999/xhtml">', ""
	$HTMLTable = $HTMLTable -replace '<head>', ""
	$HTMLTable = $HTMLTable -replace '<title>HTML TABLE</title>', ""
	$HTMLTable = $HTMLTable -replace '</head><body>', ""
	$HTMLTable = $HTMLTable -replace '</body></html>', ""
	Return $HTMLTable
}

Function Get-HTMLDetail ($Heading, $Detail){
$Report = @"
<TABLE>
	<tr>
	<th width='25%'><b>$Heading</b></font></th>
	<td width='75%'>$($Detail)</td>
	</tr>
</TABLE>
"@
Return $Report
}

if ($auditlist -eq ""){
	Write-Host "No list specified, using $env:computername"
	$targets = $env:computername
}
else
{
	if ((Test-Path $auditlist) -eq $false)
	{
		Write-Host "Invalid audit path specified: $auditlist"
		exit
	}
	else
	{
		Write-Host "Using Audit list: $auditlist"
		$Targets = Get-Content $auditlist
	}
}

Foreach ($Target in $Targets){

Write-Output "Collating Detail for $Target"
	$ComputerSystem = Get-WmiObject -computername $Target Win32_ComputerSystem
	switch ($ComputerSystem.DomainRole){
		0 { $ComputerRole = "Standalone Workstation" }
		1 { $ComputerRole = "Member Workstation" }
		2 { $ComputerRole = "Standalone Server" }
		3 { $ComputerRole = "Member Server" }
		4 { $ComputerRole = "Domain Controller" }
		5 { $ComputerRole = "Domain Controller" }
		default { $ComputerRole = "Information not available" }
	}
	
	$OperatingSystems = Get-WmiObject -computername $Target Win32_OperatingSystem
	$TimeZone = Get-WmiObject -computername $Target Win32_Timezone
	$Keyboards = Get-WmiObject -computername $Target Win32_Keyboard
	$SchedTasks = Get-WmiObject -computername $Target Win32_ScheduledJob
	$BootINI = $OperatingSystems.SystemDrive + "boot.ini"
	$RecoveryOptions = Get-WmiObject -computername $Target Win32_OSRecoveryConfiguration
	
	switch ($ComputerRole){
		"Member Workstation" { $CompType = "Computer Domain"; break }
		"Domain Controller" { $CompType = "Computer Domain"; break }
		"Member Server" { $CompType = "Computer Domain"; break }
		default { $CompType = "Computer Workgroup"; break }
	}

	$LBTime=$OperatingSystems.ConvertToDateTime($OperatingSystems.Lastbootuptime)
	Write-Output "..Regional Options"
	$ObjKeyboards = Get-WmiObject -ComputerName $Target Win32_Keyboard
	$keyboardmap = @{
	"00000402" = "BG" 
	"00000404" = "CH" 
	"00000405" = "CZ" 
	"00000406" = "DK" 
	"00000407" = "GR" 
	"00000408" = "GK" 
	"00000409" = "US" 
	"0000040A" = "SP" 
	"0000040B" = "SU" 
	"0000040C" = "FR" 
	"0000040E" = "HU" 
	"0000040F" = "IS" 
	"00000410" = "IT" 
	"00000411" = "JP" 
	"00000412" = "KO" 
	"00000413" = "NL" 
	"00000414" = "NO" 
	"00000415" = "PL" 
	"00000416" = "BR" 
	"00000418" = "RO" 
	"00000419" = "RU" 
	"0000041A" = "YU" 
	"0000041B" = "SL" 
	"0000041C" = "US" 
	"0000041D" = "SV" 
	"0000041F" = "TR" 
	"00000422" = "US" 
	"00000423" = "US" 
	"00000424" = "YU" 
	"00000425" = "ET" 
	"00000426" = "US" 
	"00000427" = "US" 
	"00000804" = "CH" 
	"00000809" = "UK" 
	"0000080A" = "LA" 
	"0000080C" = "BE" 
	"00000813" = "BE" 
	"00000816" = "PO" 
	"00000C0C" = "CF" 
	"00000C1A" = "US" 
	"00001009" = "US" 
	"0000100C" = "SF" 
	"00001809" = "US" 
	"00010402" = "US" 
	"00010405" = "CZ" 
	"00010407" = "GR" 
	"00010408" = "GK" 
	"00010409" = "DV" 
	"0001040A" = "SP" 
	"0001040E" = "HU" 
	"00010410" = "IT" 
	"00010415" = "PL" 
	"00010419" = "RU" 
	"0001041B" = "SL" 
	"0001041F" = "TR" 
	"00010426" = "US" 
	"00010C0C" = "CF" 
	"00010C1A" = "US" 
	"00020408" = "GK" 
	"00020409" = "US" 
	"00030409" = "USL" 
	"00040409" = "USR" 
	"00050408" = "GK" 
	}
	$keyb = $keyboardmap.$($ObjKeyboards.Layout)
	if (!$keyb)
	{ $keyb = "Unknown"
	}
	$MyReport = Get-CustomHTML "$Target Audit"
	$MyReport += Get-CustomHeader0  "$Target Details"
	$MyReport += Get-CustomHeader "2" "General"
		$MyReport += Get-HTMLDetail "Computer Name" ($ComputerSystem.Name)
		$MyReport += Get-HTMLDetail "Computer Role" ($ComputerRole)
		$MyReport += Get-HTMLDetail $CompType ($ComputerSystem.Domain)
		$MyReport += Get-HTMLDetail "Operating System" ($OperatingSystems.Caption)
		$MyReport += Get-HTMLDetail "Service Pack" ($OperatingSystems.CSDVersion)
		$MyReport += Get-HTMLDetail "System Root" ($OperatingSystems.SystemDrive)
		$MyReport += Get-HTMLDetail "Manufacturer" ($ComputerSystem.Manufacturer)
		$MyReport += Get-HTMLDetail "Model" ($ComputerSystem.Model)
		$MyReport += Get-HTMLDetail "Number of Processors" ($ComputerSystem.NumberOfProcessors)
		$MyReport += Get-HTMLDetail "Memory" ($ComputerSystem.TotalPhysicalMemory)
		$MyReport += Get-HTMLDetail "Registered User" ($ComputerSystem.PrimaryOwnerName)
		$MyReport += Get-HTMLDetail "Registered Organisation" ($OperatingSystems.Organization)
		$MyReport += Get-HTMLDetail "Last System Boot" ($LBTime)
		$MyReport += Get-CustomHeaderClose
		Write-Output "..Hotfix Information"
		$colQuickFixes = Get-WmiObject Win32_QuickFixEngineering
		$MyReport += Get-CustomHeader "2" "HotFixes"
			$MyReport += Get-HTMLTable ($colQuickFixes | Where {$_.HotFixID -ne "File 1" } |Select HotFixID, Description)
		$MyReport += Get-CustomHeaderClose
		Write-Output "..Logical Disks"
		$Disks = Get-WmiObject -ComputerName $Target Win32_LogicalDisk
		$MyReport += Get-CustomHeader "2" "Logical Disk Configuration"
			$LogicalDrives = @()
			Foreach ($LDrive in ($Disks | Where {$_.DriveType -eq 3})){
				$Details = "" | Select "Drive Letter", Label, "File System", "Disk Size (MB)", "Disk Free Space", "% Free Space"
				$Details."Drive Letter" = $LDrive.DeviceID
				$Details.Label = $LDrive.VolumeName
				$Details."File System" = $LDrive.FileSystem
				$Details."Disk Size (MB)" = [math]::round(($LDrive.size / 1MB))
				$Details."Disk Free Space" = [math]::round(($LDrive.FreeSpace / 1MB))
				$Details."% Free Space" = [Math]::Round(($LDrive.FreeSpace /1MB) / ($LDrive.Size / 1MB) * 100)
				$LogicalDrives += $Details
			}
			$MyReport += Get-HTMLTable ($LogicalDrives)
		$MyReport += Get-CustomHeaderClose
		Write-Output "..Network Configuration"
		$Adapters = Get-WmiObject -ComputerName $Target Win32_NetworkAdapterConfiguration
		$MyReport += Get-CustomHeader "2" "NIC Configuration"
			$IPInfo = @()
			Foreach ($Adapter in ($Adapters | Where {$_.IPEnabled -eq $True})) {
				$Details = "" | Select Description, "Physical address", "IP Address / Subnet Mask", "Default Gateway", "DHCP Enabled", DNS, WINS
				$Details.Description = "$($Adapter.Description)"
				$Details."Physical address" = "$($Adapter.MACaddress)"
				If ($Adapter.IPAddress -ne $Null) {
				$Details."IP Address / Subnet Mask" = "$($Adapter.IPAddress)/$($Adapter.IPSubnet)"
					$Details."Default Gateway" = "$($Adapter.DefaultIPGateway)"
				}
				If ($Adapter.DHCPEnabled -eq "True")	{
					$Details."DHCP Enabled" = "Yes"
				}
				Else {
					$Details."DHCP Enabled" = "No"
				}
				If ($Adapter.DNSServerSearchOrder -ne $Null)	{
					$Details.DNS =  "$($Adapter.DNSServerSearchOrder)"
				}
				$Details.WINS = "$($Adapter.WINSPrimaryServer) $($Adapter.WINSSecondaryServer)"
				$IPInfo += $Details
			}
			$MyReport += Get-HTMLTable ($IPInfo)
		$MyReport += Get-CustomHeaderClose
		If ((get-wmiobject -ComputerName $Target -namespace "root/cimv2" -list) | Where-Object {$_.name -match "Win32_Product"})
		{
			Write-Output "..Software"
			$MyReport += Get-CustomHeader "2" "Software"
				$MyReport += Get-HTMLTable (get-wmiobject -ComputerName $Target Win32_Product | select Name,Version,Vendor,InstallDate)
			$MyReport += Get-CustomHeaderClose
		}
		Else {
			Write-Output "..Software WMI class not installed"
		}
		Write-Output "..Local Shares"
		$Shares = Get-wmiobject -ComputerName $Target Win32_Share
		$MyReport += Get-CustomHeader "2" "Local Shares"
			$MyReport += Get-HTMLTable ($Shares | Select Name, Path, Caption)
		$MyReport += Get-CustomHeaderClose
		Write-Output "..Printers"
		$InstalledPrinters =  Get-WmiObject -ComputerName $Target Win32_Printer
		$MyReport += Get-CustomHeader "2" "Printers"
			$MyReport += Get-HTMLTable ($InstalledPrinters | Select Name, Location)
		$MyReport += Get-CustomHeaderClose
		Write-Output "..Services"
		$ListOfServices = Get-WmiObject -ComputerName $Target Win32_Service
		$MyReport += Get-CustomHeader "2" "Services"
			$Services = @()
			Foreach ($Service in $ListOfServices){
				$Details = "" | Select Name,Account,"Start Mode",State,"Expected State"
				$Details.Name = $Service.Caption
				$Details.Account = $Service.Startname
				$Details."Start Mode" = $Service.StartMode
				If ($Service.StartMode -eq "Auto")
					{
						if ($Service.State -eq "Stopped")
						{
							$Details.State = $Service.State
							$Details."Expected State" = "Unexpected"
						}
					}
					If ($Service.StartMode -eq "Auto")
					{
						if ($Service.State -eq "Running")
						{
							$Details.State = $Service.State
							$Details."Expected State" = "OK"
						}
					}
					If ($Service.StartMode -eq "Disabled")
					{
						If ($Service.State -eq "Running")
						{
							$Details.State = $Service.State
							$Details."Expected State" = "Unexpected"
						}
					}
					If ($Service.StartMode -eq "Disabled")
					{
						if ($Service.State -eq "Stopped")
						{
							$Details.State = $Service.State
							$Details."Expected State" = "OK"
						}
					}
					If ($Service.StartMode -eq "Manual")
					{
						$Details.State = $Service.State
						$Details."Expected State" = "OK"
					}
					If ($Service.State -eq "Paused")
					{
						$Details.State = $Service.State
						$Details."Expected State" = "OK"
					}
				$Services += $Details
			}
			$MyReport += Get-HTMLTable ($Services)
		$MyReport += Get-CustomHeaderClose
		$MyReport += Get-CustomHeader "2" "Regional Settings"
			$MyReport += Get-HTMLDetail "Time Zone" ($TimeZone.Description)
			$MyReport += Get-HTMLDetail "Country Code" ($OperatingSystems.Countrycode)
			$MyReport += Get-HTMLDetail "Locale" ($OperatingSystems.Locale)
			$MyReport += Get-HTMLDetail "Operating System Language" ($OperatingSystems.OSLanguage)
			$MyReport += Get-HTMLDetail "Keyboard Layout" ($keyb)
		$MyReport += Get-CustomHeaderClose
		Write-Output "..Event Log Settings"
		$LogFiles = Get-WmiObject -ComputerName $Target Win32_NTEventLogFile
		$MyReport += Get-CustomHeader "2" "Event Logs"
			$MyReport += Get-CustomHeader "2" "Event Log Settings"
			$LogSettings = @()
			Foreach ($Log in $LogFiles){
				$Details = "" | Select "Log Name", "Overwrite Outdated Records", "Maximum Size (KB)", "Current Size (KB)"
				$Details."Log Name" = $Log.LogFileName
				If ($Log.OverWriteOutdated -lt 0)
					{
						$Details."Overwrite Outdated Records" = "Never"
					}
				if ($Log.OverWriteOutdated -eq 0)
				{
					$Details."Overwrite Outdated Records" = "As needed"
				}
				Else
				{
					$Details."Overwrite Outdated Records" = "After $($Log.OverWriteOutdated) days"
				}
				$MaxFileSize = ($Log.MaxFileSize) / 1024
				$FileSize = ($Log.FileSize) / 1024
				
				$Details."Maximum Size (KB)" = $MaxFileSize
				$Details."Current Size (KB)" = $FileSize
				$LogSettings += $Details
			}
			$MyReport += Get-HTMLTable ($LogSettings)
			$MyReport += Get-CustomHeaderClose
			Write-Output "..Event Log Errors"
			$WmidtQueryDT = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime([DateTime]::Now.AddDays(-14))
			$LoggedErrors = Get-WmiObject -computer $Target -query ("Select * from Win32_NTLogEvent Where Type='Error' and TimeWritten >='" + $WmidtQueryDT + "'")
			$MyReport += Get-CustomHeader "2" "ERROR Entries"
				$MyReport += Get-HTMLTable ($LoggedErrors | Select EventCode, SourceName, @{N="Time";E={$_.ConvertToDateTime($_.TimeWritten)}}, LogFile, Message)
			$MyReport += Get-CustomHeaderClose
			Write-Output "..Event Log Warnings"
			$WmidtQueryDT = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime([DateTime]::Now.AddDays(-14))
			$LoggedWarning = Get-WmiObject -computer $Target -query ("Select * from Win32_NTLogEvent Where Type='Warning' and TimeWritten >='" + $WmidtQueryDT + "'")
			$MyReport += Get-CustomHeader "2" "WARNING Entries"
				$MyReport += Get-HTMLTable ($LoggedWarning | Select EventCode, SourceName, @{N="Time";E={$_.ConvertToDateTime($_.TimeWritten)}}, LogFile, Message)
			$MyReport += Get-CustomHeaderClose
		$MyReport += Get-CustomHeaderClose
		$MyReport += Get-CustomHeaderClose
	$MyReport += Get-CustomHeader0Close
	$MyReport += Get-CustomHTMLClose
	$MyReport += Get-CustomHTMLClose

	$Date = Get-Date
	$Filename = ".\" + $Target + "_" + $date.Hour + $date.Minute + "_" + $Date.Day + "-" + $Date.Month + "-" + $Date.Year + ".htm"
	$MyReport | out-file -encoding ASCII -filepath $Filename
	Write "Audit saved as $Filename"
}
