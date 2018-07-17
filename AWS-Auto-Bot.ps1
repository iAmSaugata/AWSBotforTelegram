#AWS Bot Automation
#Author : Saugata Datta
#Make sure you have CURL installed in Script or Windows Directory - https://curl.haxx.se/dlwiz/?type=bin
#Email  : Saugata.Datta@technochat.in
#Config Task
if(!$(Get-ScheduledTask | ? {$_.TaskName -eq "AWS-Auto-Bot"})){
    $SecurePassword = $Password = Read-Host "Please provide password of $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"-AsSecureString
    $UserName = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, $SecurePassword
    $Password = $Credentials.GetNetworkCredential().Password 
    $TaskAction = New-ScheduledTaskAction -WorkingDirectory "$PSScriptRoot" -Execute "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument '.\AWS-Auto-Bot.ps1 -ExecutionPolicy RemoteSigned'
    $TaskTrigger = New-JobTrigger -AtStartup -RandomDelay 00:00:30
    Register-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -TaskName "AWS-Auto-Bot" -Description "AWS Automation vi Telegram" -User $UserName -Password $Password | Out-Null
    Start-ScheduledTask -TaskName "AWS-Auto-Bot"
    return
}
#END
if(!(Test-Path -Path "$PSScriptRoot\Debug_Logs" )){ New-Item -ItemType directory -Path "$PSScriptRoot\Debug_Logs" }
$FullLogFileName = "$PSScriptRoot\Debug_Logs\Debug-" + (Get-Date).toString('dd-MM-yyyy-HH-mm-ss') + ".txt"
Start-Transcript -path $FullLogFileName | Out-Null
#Bot Config
#http://bit.ly/2ys1gF5
#Check the above link to know how to create telegram bot and get your boot keys.
$BotName="@YourBotName"
$ChatID="YourChatID"
$BotKey = "YourBotKey"
#Use the following to get your chat ID
#$GetChatID = Invoke-WebRequest -Uri "https://api.telegram.org/bot$BotKey/getUpdates" -Proxy http://my.proxy.com:8080 -ProxyUseDefaultCredentials
#$GetChatID = Invoke-WebRequest -Uri "https://api.telegram.org/bot$BotKey/getUpdates"
#(ConvertFrom-Json $GetChatID.Content).result.message.chat.id
$LastReply = (Get-Content $PSScriptRoot\lastmsgid.txt)[-1]
$LastInput = $LastReply
#Bot-API-LINK
$sendMsgLink = "https://api.telegram.org/bot$BotKey/sendMessage"
$sendPhotoLink = "https://api.telegram.org/bot$BotKey/sendPhoto"
$sendDocLink = "https://api.telegram.org/bot$BotKey/sendDocument"

#Store your AWS Access keys here
Set-AWSCredentials -AccessKey "Your Access Key" -SecretKey "Your Secret Key"
Set-DefaultAWSRegion "ap-southeast-2"

#Get All Snapshots Backups
function GetServerSnaps([string] $InstanceName,[string] $Region)
{
    $SFilter = new-object Amazon.EC2.Model.Filter
    $SFilter.Name = "description"
    $SFilter.Value = "*$InstanceName*"        
    if ($Region){ $CmdOutput = Get-EC2Snapshot -Filter $SFilter -Region $Region }
    if (!$Region){ $CmdOutput =Get-EC2Snapshot -Filter $SFilter }
    if($CmdOutput -ne $null){
        return $CmdOutput | Select-Object SnapshotID, Description, StartTime | Sort-Object StartTime -Descending
    }else{
        return $null
    }
}

#Get instance details from Instance Name
function GetInstanceFromName([string] $InstanceName,[string] $Region)
{
    $Filter = new-object Amazon.EC2.Model.Filter
    $Filter.Name = "tag:Name"
    $Filter.Value = "$InstanceName"
        
    if ($Region){$CmdOutput = Get-EC2Instance -Filter $Filter -Region $Region}
    if (!$Region){$CmdOutput = Get-EC2Instance -Filter $Filter}
    if($CmdOutput){
        return $CmdOutput
    }else{
        return "Make sure name is correct"
    }
}

#Get Instance Volumes
function GetInstanceVolumes([string] $instanceID)
{
    $VFilter = new-object Amazon.EC2.Model.Filter
    $VFilter.Name = "attachment.instance-id"
    $VFilter.Value = "$instanceID"        
    $CmdOutput = Get-EC2Volume -Filter $VFilter
    $Result=@()
    foreach ($Output in $CmdOutput)
    {
        $MyTable=$null
        $MyOb = New-Object -TypeName PSObject
        $MyOb | Add-Member @{ID =$($Output.Attachment.InstanceID)}
        $MyOb | Add-Member @{Device =$($Output.Attachment.Device)}
        $MyOb | Add-Member @{VolumeId =$($Output.VolumeId)}
        $MyOb | Add-Member @{VolumeType=$($Output.VolumeType)}
        $MyOb | Add-Member @{SizeInGB=$($Output.Size)}
        $MyOb | Add-Member @{Encrypted=$($Output.Encrypted)}
        $MyOb | Add-Member @{AZ=$($Output.AvailabilityZone)}
        $Result += $MyOb
    }
    if($Result){
        return $Result
    }else{
        return $null
    }
}

#Send Telegram message
function Send-TeleMessage([string] $BotKey , [array] $ChatIDs , [string] $Message)
{  
    foreach ($ID in $ChatIDs)
    {        
        try
        {            
            #$ExecuteInvokeWeb = Invoke-WebRequest -Uri "$sendMsgLink" -Method Post -ContentType "application/json;charset=utf-8" -Body (ConvertTo-Json -Compress -InputObject @{chat_id=$ID; text="$Message"}) -ErrorAction SilentlyContinue -Proxy http://my.proxy.com:8080 -ProxyUseDefaultCredentials
            $ExecuteInvokeWeb = Invoke-WebRequest -Uri "$sendMsgLink" -Method Post -ContentType "application/json;charset=utf-8" -Body (ConvertTo-Json -Compress -InputObject @{chat_id=$ID; text="$Message"}) -ErrorAction SilentlyContinue
            $Status = (ConvertFrom-Json -InputObject $ExecuteInvokeWeb.Content)
            if($Status.ok){Write-Host "Message successfully sent to Chat ID : $ID (Type : $($Status.result.chat.type))" -ForegroundColor Green
            }
        }
        catch [Exception]
        {
            $exception = $_.Exception.ToString().Split(".")[2]
            Write-Host "Message failed to send at Chat ID : $ID ($exception)" -ForegroundColor Red
        }
    }
}

while ($true) {
    #Start Admin
    #This is for additional security to alow user for start/stop instances
    #Bydefault no one allowed.
    #To alow your self, you have to do it manually, and then you can add others from Telegram.
    $AdminUsers=Get-Content $PSScriptRoot\adminusers.txt
    #End Admin
    #$GetChatMSG = Invoke-WebRequest -Uri "https://api.telegram.org/bot$BotKey/getUpdates" -Proxy http://my.proxy.com:8080 -ProxyUseDefaultCredentials
    $GetChatMSG = Invoke-WebRequest -Uri "https://api.telegram.org/bot$BotKey/getUpdates"
    $GetChatRoom = (ConvertFrom-Json $GetChatMSG.Content).result.message | ? {$_.chat.id -eq "$ChatID"}
    $GetLastFullMessage = if($GetChatRoom){$GetChatRoom[-1]}
    if ($GetLastFullMessage)
    {
        $GetLastMessage = $GetLastFullMessage.text
        $GetUserID = $GetLastFullMessage.from.ID
        $GetUserName = "$($GetLastFullMessage.from.first_name) $($GetLastFullMessage.from.last_name)"
        $Input = $($GetLastFullMessage.text)
        $IsUserAdmin = $AdminUsers.Contains("$GetUserID")
        $GetLastMessageID = $GetLastFullMessage.message_id

        if ($GetLastMessage -eq "/help")
        {
            if ($LastReply -ne $GetLastMessageID)
            {
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message @(
                "Default region will be Sydney, To change the AWS region, please use `n/awsregionsydney or, `n/awsregionvirginia or, `n/awsregionoregon",
                "`n",
                "`n01. To know the basic details of a AWS server, `nuse /info=ServerName",
                "`n",
                "`n02. To know the details of attached volumes of a AWS server, `nuse /getvolumes=ServerName",
                "`n",
                "`n03. To get the list of available snapshots of a AWS server, `nuse /getsnaps=ServerName",
                "`n",
                "`n04. To get the current Console ScreenShot of a AWS server, `nuse /screen=ServerName",
                "`n",
                "`n05. To get the current Console Output of a AWS server, `nuse /consolelog=ServerName",
                "`n",
                "`n06. To start a AWS server, `nuse /start=ServerName",
                "`n",
                "`n07. To stop a AWS server, `nuse /stop=ServerName",
                "`n",
                "`n08. To restart a AWS server, `nuse /restart=ServerName",
                "`n",
                "`n09. To know your User ID, `nuse /myid",
                "`n",
                "`n10. To grant admin access, `nuse /addadmin=UserID",
                "`n",
                "`n11. Use /about to know more about this tool.",
                "`n",
                "`nNote : ServerName is case sensetive and execution permission is limited."
                )
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -like "/getsnaps=*")
        {
            if ($LastReply -ne $GetLastMessageID)
            {
                $Name=$null
                $Name = ($GetLastMessage.Split("=")[-1]).ToUpper()
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Extracting the list of available snapshots of $Name, please wait..."
                $GetInstances = GetInstanceFromName $Name
                if($GetInstances)
                {
                    $ListOfSnaps = $null
                    $ListOfSnaps = GetServerSnaps $Name
                    if($ListOfSnaps)
                    {
                        $ListOfSnaps | Export-Csv -NoTypeInformation "$PSScriptRoot\Snapshots_$Name.csv"
                        #Invoke-WebRequest not working, so using curl.
                        #$cURLExec =  "curl.exe -F caption='List of the available Snapshots of $Name' -F document=@'$PSScriptRoot\Snapshots_$Name.csv' -F chat_id=$ChatID -U : --proxy-ntlm --proxy my.proxy.com:8080 --insecure '$sendDocLink'"
                        $cURLExec =  "curl.exe -F caption='List of the available Snapshots of $Name' -F document=@'$PSScriptRoot\Snapshots_$Name.csv' -F chat_id=$ChatID '$sendDocLink'"
                        Invoke-Expression -Command $cURLExec
                        Remove-Item -Path "$PSScriptRoot\Snapshots_$Name.csv" -Force
                    }
                    else
                    {
                        Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "There is no snapshot taken for $Name."
                    }
                }
                else
                {
                    Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Incorrect Server Name or Region"
                }
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID

            }
        }

        if ($GetLastMessage -like "/getvolumes=*")
        {
            if ($LastReply -ne $GetLastMessageID)
            {
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Extracting information, please wait..."
                $Name=$null
                $Name = ($GetLastMessage.Split("=")[-1]).ToUpper()
                $GetInstance=$null
                $GetInstance = (GetInstanceFromName $Name).Instances
                if($GetInstance)
                {
                    $Volumes = GetInstanceVolumes $($GetInstance.InstanceID)
                    $MyTable = $Volumes | Out-String
                    Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Following volumes are attached to $Name `n$MyTable"
                }
                else
                {
                    Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Incorrect Server Name or Region"
                }
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -like "/consolelog=*")
        {
            if ($LastReply -ne $GetLastMessageID)
            {
                $Name=$null
                $Name = ($GetLastMessage.Split("=")[-1]).ToUpper()
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Extracting Console Output of $Name, please wait"
                $GetInstances = GetInstanceFromName $Name
                if($GetInstances)
                {
                    $Base64Txt = $((GetInstanceFromName $Name).instances.instanceid | Get-EC2ConsoleOutput).Output
                    if($Base64Txt)
                    {
                        $Content = [System.Convert]::FromBase64String($Base64Txt)
                        Set-Content -Path "$PSScriptRoot\ConsoleOutput_$Name.txt" -Value $Content -Encoding Byte -Force
                        #Invoke-WebRequest not working, so using curl.
                        #$cURLExec =  "curl.exe -F caption='Console Output of $Name' -F document=@'$PSScriptRoot\ConsoleOutput_$Name.txt' -F chat_id=$ChatID -U : --proxy-ntlm --proxy my.proxy.com:8080 --insecure '$sendDocLink'"
                        $cURLExec =  "curl.exe -F caption='Console Output of $Name' -F document=@'$PSScriptRoot\ConsoleOutput_$Name.txt' -F chat_id=$ChatID '$sendDocLink'"
                        Invoke-Expression -Command $cURLExec
                        Remove-Item -Path "$PSScriptRoot\ConsoleOutput_$Name.txt" -Force
                    }
                    else
                    {
                        Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Console Output not available or not ready yet for $Name."
                    }
                }
                else
                {
                    Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Incorrect Server Name or Region"
                }
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -like "/addadmin=*")
        {
            if ($LastReply -ne $GetLastMessageID)
            {   
                if($IsUserAdmin)
                {
                    if(!$AdminUsers.Contains("$($GetLastMessage.Split("=")[-1])"))
                    {
                        Add-Content $PSScriptRoot\adminusers.txt $($GetLastMessage.Split("=")[-1])
                        Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "User ID $($GetLastMessage.Split("=")[-1]) is successfully added to the Admin Group."
                    }
                    else
                    {
                        Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "User ID $($GetLastMessage.Split("=")[-1]) is already member of the Admin Group."
                    }
                }
                else
                {
                    Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "You do not have permission to update the admin group."
                }
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -eq "/myid")
        {
            if ($LastReply -ne $GetLastMessageID)
            {
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "User ID of $GetUserName is $GetUserID"
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -like "/screen=*")
        {
            if ($LastReply -ne $GetLastMessageID)
            {
                $Name=$null
                $Name = ($GetLastMessage.Split("=")[-1]).ToUpper()
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Taking Console Screenshot of $Name, please wait"
                $GetInstances = GetInstanceFromName $Name
                if($GetInstances)
                {
                    $Base64 = $($GetInstances.instances.instanceid | Get-EC2ConsoleScreenshot).imagedata
                    if($Base64)
                    {
                        $Content = [System.Convert]::FromBase64String($Base64)
                        Set-Content -Path "$PSScriptRoot\ConsoleScreenshot_$Name.jpg" -Value $Content -Encoding Byte -Force
                        #Invoke-WebRequest not working, so using curl.
                        #$cURLExec =  "curl.exe -F caption='Console Screenshot of $Name' -F photo=@'$PSScriptRoot\ConsoleScreenshot_$Name.jpg' -F chat_id=$ChatID -U : --proxy-ntlm --proxy my.proxy.com:8080 --insecure '$sendPhotoLink'"
                        $cURLExec =  "curl.exe -F caption='Console Screenshot of $Name' -F photo=@'$PSScriptRoot\ConsoleScreenshot_$Name.jpg' -F chat_id=$ChatID '$sendPhotoLink'"
                        Invoke-Expression -Command $cURLExec
                        Remove-Item -Path "$PSScriptRoot\ConsoleScreenshot_$Name.jpg" -Force
                    }
                    else
                    {
                        Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Console Screenshot not available or not ready yet for $Name."
                    }
                }
                else
                {
                    Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Incorrect Server Name or Region"
                }
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -like "/restart=*")
        {
            if ($LastReply -ne $GetLastMessageID)
            {            
                $Name=$null
                $Name = ($GetLastMessage.Split("=")[-1]).ToUpper()
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Restarting the server $Name, please wait..."
                $GetInstance=$null
                $GetInstance = (GetInstanceFromName $Name).Instances            
                if($GetInstance)
                {
                    if ($GetInstance.State.Name.Value -eq "running")
                    {
                    
                        if($IsUserAdmin)
                        {
                            Restart-EC2Instance $($GetInstance.InstanceID) -Force
                            Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Server restart command executed successfully on $Name, try ping the server($($GetInstance.PrivateIpAddress)) from your system."
                        }
                        else
                        {
                            Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "You do not have permission to restart the server."
                        }
                    }
                    else
                    {
                        Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Server $Name is not in a state from which it can be restarted."
                    }
                }
                else
                {
                    Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Incorrect Server Name or Region"
                }
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -like "/stop=*")
        {
            if ($LastReply -ne $GetLastMessageID)
            {            
                $Name=$null
                $Name = ($GetLastMessage.Split("=")[-1]).ToUpper()
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Stopping the server $Name, please wait..."
                $GetInstance=$null
                $GetInstance = (GetInstanceFromName $Name).Instances
                if($GetInstance)
                {
                    if ($GetInstance.State.Name.Value -ne "stopped")
                    {
                        if($IsUserAdmin)
                        {
                            Stop-EC2Instance $($GetInstance.InstanceID) -Force
                            Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Server stop command executed successfully on $Name, try ping the server($($GetInstance.PrivateIpAddress)) from your system."
                        }
                        else
                        {
                            Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "You do not have permission to stop the server."
                        }
                    }
                    else
                    {
                        Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Server $Name is not in a state from which it can be stopped."
                    }
                }
                else
                {
                    Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Incorrect Server Name or Region"
                }
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -like "/start=*")
        {
            if ($LastReply -ne $GetLastMessageID)
            {            
                $Name=$null
                $Name =($GetLastMessage.Split("=")[-1]).ToUpper()
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Starting the server $Name, please wait..."
                $GetInstance=$null
                $GetInstance = (GetInstanceFromName $Name).Instances
                if($GetInstance)
                {
                    if ($GetInstance.State.Name.Value -eq "stopped")
                    {
                        if($IsUserAdmin)
                        {                       
                            Start-EC2Instance $($GetInstance.InstanceID) -Force
                            Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Server start command executed successfully on $Name, try ping the server($($GetInstance.PrivateIpAddress)) from your system."
                        }
                        else
                        {
                            Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "You do not have permission to start the server."
                        }
                    }
                    else
                    {
                        Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Server $Name is not in a state from which it can be started."
                    }
                }
                else
                {
                    Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Incorrect Server Name or Region"
                }
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -like "/info=*")
        {
            if ($LastReply -ne $GetLastMessageID)
            {
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Extracting information, please wait..."
                $Name=$null
                $Name = ($GetLastMessage.Split("=")[-1]).ToUpper()
                $GetInstance=$null
                $GetInstance = (GetInstanceFromName $Name).Instances
                if($GetInstance)
                {
                    $MyTable=$null
                    $MyOb = New-Object -TypeName PSObject
                    $MyOb | Add-Member @{Name=$Name}
                    $MyOb | Add-Member @{ID=$($GetInstance.InstanceId)}
                    $MyOb | Add-Member @{IP=$($GetInstance.PrivateIpAddress)}
                    if($GetInstance.Platform.value){$MyOb | Add-Member @{Platform=$($GetInstance.Platform.value)}}else{
                    $MyOb | Add-Member @{Platform="Unix/Linux"}}
                    $MyOb | Add-Member @{Type=$($GetInstance.InstanceType.Value)}
                    if($($GetInstance.KeyName)){$MyOb | Add-Member @{KeyName=$($GetInstance.KeyName)}}
                    if($($GetInstance.IamInstanceProfile)){$MyOb | Add-Member @{IAMRole=$($GetInstance.IamInstanceProfile.arn.split("/")[-1])}}
                    $MyOb | Add-Member @{Status=$($GetInstance.State.Name.Value)}
                    $MyOb | Add-Member @{Zone=$($GetInstance.Placement.AvailabilityZone)}
                    $MyOb | Add-Member @{SubnetID=$($GetInstance.SubnetID)}
                    $MyOb | Add-Member @{VpcID=$($GetInstance.VpcID)}
                    $MyTable = $MyOb | Out-String
                    Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "$MyTable"
                }
                else
                {
                    Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Incorrect Server Name or Region"
                }
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -eq "/awsregionsydney")
        {
            if ($LastReply -ne $GetLastMessageID)
            {
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "AWS Region set to ap-southeast-2"
                Set-DefaultAWSRegion "ap-southeast-2"
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -eq "/awsregionoregon")
        {
            if ($LastReply -ne $GetLastMessageID)
            {
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "Default AWS Region set to us-west-2"
                Set-DefaultAWSRegion "us-west-2"
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -eq "/awsregionvirginia")
        {
            if ($LastReply -ne $GetLastMessageID)
            {
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message "AWS Region set to us-east-1"
                Set-DefaultAWSRegion "us-east-1"
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }

        if ($GetLastMessage -eq "/about")
        {
            if ($LastReply -ne $GetLastMessageID)
            {
                Send-TeleMessage -BotKey $BotKey -ChatIDs $ChatID -Message @(
                "AWS Auto Bot v1.0",
                "`nBy Saugata Datta",
                "`n(c) TechnoChat.IN",
                "`nhttp://technochat.in"
                )
                $LastReply=$GetLastMessageID
                Add-Content $PSScriptRoot\lastmsgid.txt $GetLastMessageID
            }
        }
        sleep 1
        if ($LastInput -ne $GetLastMessageID)
        {
            Add-Content $PSScriptRoot\BotLog.txt "$((Get-Date).ToUniversalTime().ToString("[dd/MM/yyyy : hh:mm:ss]")) - Input from $GetUserName ($GetUserID) : $Input ($GetLastMessageID) "
            $LastInput=$GetLastMessageID
        }    
    }
}