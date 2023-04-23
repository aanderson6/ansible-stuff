if (test-path -path c:\users\ansible) {
    Write-Host "Ansible User Exists!"
    Exit
}
if (test-path -path c:\programdata\ssh\sshd_config) {
    Write-Host "OpenSSH installed!"
    Exit
}

Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install -y --package-parameters=/SSHServerFeature openssh

$file = 'C:\ProgramData\ssh\sshd_config'
(Get-Content $file) -replace 'Match Group administrators', '#Match Group administrators' | Set-Content $file
(Get-Content $file) -replace 'AuthorizedKeysFile __PROGRAMDATA__\/ssh\/administrators_authorized_keys', '#AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys' | Set-Content $file
Add-Content -Value 'PubkeyAuthentication yes' -Path $file
Add-Content -Value 'PasswordAuthentication no' -Path $file

$secStringPassword = ConvertTo-SecureString "password" -AsPlainText -Force
$credObject = New-Object System.Management.Automation.PSCredential ("AD\ansible", $secStringPassword)
Enter-PSSession -Credential $credObject -ComputerName localhost
Exit-PSSession

Set-Location C:\users\ansible
New-Item -Name ".ssh" -ItemType "Directory"
"ssh-key" | Out-File -FilePath .ssh\authorized_keys -Encoding utf8

$acl = Get-Acl .\.ssh\authorized_keys
$acl.SetAccessRuleProtection($true,$true)
Set-Acl .\.ssh\authorized_keys $acl
$acl = Get-Acl .\.ssh\authorized_keys
$acl.Access | %{$acl.RemoveAccessRule($_)} | Out-Null
$permission  = "BUILTIN\Administrators","FullControl", "Allow"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($rule)
$permission  = "AD\ansible","FullControl", "Allow"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($rule)
$permission  = "SYSTEM","FullControl", "Allow"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($rule)
Set-Acl .\.ssh\authorized_keys $acl

New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "$Env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

Set-Service -Name sshd -StartupType automatic
Restart-Service -Name sshd
