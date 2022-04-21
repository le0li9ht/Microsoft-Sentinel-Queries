$path=args[1]
$ipipchecklist = Get-Content -Path $path
$Port=$args[0]
if (($Port -eq $null) -or ($path -eq $null)) {
        Write-Output "Please pass port number and Iplist file path as arguments
        `nRunas below:
        Telnetcheck.ps1 <portnumber> <filepath>
        `n If you want to export output to a file then run as `nTelnetcheck.ps1 <portnumber> <filepath> >output.txt"
        exit          
}
ForEach ($file in $ipchecklist) {
$file=$file.Trim()
$Socket = New-Object Net.Sockets.TcpClient
$ErrorActionPreferenc = 'SilentlyContinue'
$Socket.Connect($file, $Port)
$ErrorActionPreference = 'Continue'

if ($Socket.Connected) {
   "For ${file}: Port $Port is open"
    $Socket.Close()
}
else {
            "${file}: Port $Port is closed or filtered" 

        }
$Socket = $null
}
