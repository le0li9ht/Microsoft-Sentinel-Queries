#arguments
$Port=$args[0]
$path=$args[1]
#validate whether the arguments are given properly
if (($Port -eq $null) -or ($path -eq $null)) {
        Write-Output "Please pass port number and Iplist file path as arguments
        `nRunas below:
         Telnetcheck.ps1 <portnumber> <filepath>
        `nIf you want to export output to a file then run as 
        `n        Telnetcheck.ps1 <portnumber> <filepath> >output.txt"
        exit          
}
#read the IPlistfile
$ipchecklist = Get-Content -Path $path
#run a loop to get each IP from the given file
ForEach ($file in $ipchecklist) {
#trim whitespaces from the entry
$file=$file.Trim()
#if the entry is not null
if( $file -ne $null) {
#Create Socket Object
$Socket = New-Object Net.Sockets.TcpClient
#SilentlyContinue: No effect. The error message isn't displayed and execution continues without interruption.
$ErrorActionPreference = 'SilentlyContinue'
#Connect to the port
$Socket.Connect($file, $Port)
#Continue: (Default) Displays the error message and continues executing.
$ErrorActionPreference = 'SilentlyContinue'
#If the connection to the port is success print port is open or closed or filtered.
if ($Socket.Connected) {
   "For ${file} Port $Port is open"
    $Socket.Close()
}
else {
            "For ${file} Port $Port is closed or filtered" 
        }
#close the socket
$Socket.close()
#put null value in Socket
$Socket = $null
}}
