Import-Module .\StartMenuBin.psm1
$p = Get-Process StartMenuExperienceHost
# Stop the process
Stop-Process -InputObject $p
# Wait for it to finish exiting

Wait-Process -InputObject $p
#Start-Sleep -Seconds 5
$t = Unprotect-StartMenuBin | ConvertFrom-Json
#$t.pinnedList = @() #清空開始選單
$t.pinnedList = $t.pinnedList | where id -NE "W~MSEdge" #測試移除edge

##測試放置內建程式至資料夾
$customName = "Windows 11內建程式"
$toMove = $t.pinnedList | Where-Object { $_.pinType -ne 2 -and $_.pinnedBy -eq 8}
$toKeep = $data.pinnedList | Where-Object { $_.pinType -eq 2 }
if ($toMove.Count -gt 0) {
    $newItems = $toMove | ForEach-Object {
        [PSCustomObject]@{
            id = $_.id
            pinnedBy = $_.pinnedBy
        }
    }
    $newGroup = [PSCustomObject]@{
        id = "{$([guid]::NewGuid().ToString())}"
        pinnedBy = 4
        pinType  = 2
        name = $customName
        items = $newItems
    }
    $t.pinnedList = @($toKeep; $newGroup)
}


$t = $t | ConvertTo-Json -Compress -Depth 100
Protect-StartMenuBin -PlainText $t