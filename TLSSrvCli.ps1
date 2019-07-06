#
# objective is to have some psh tools to use/verify/understand TLS mutual authentication
# when using the MS certificate store
# taken from p.o.w.e.r.c.a.t obfuscated to defeat naive av tools
#
# get better at selecting the server and client certificate
# - I can either import a p12 directly or I can use the cert store
#   (with middleware to copy the token in there)
# - cert store would avoid the pin problem I think (at least prompt for it)
function New-SSLClientStream
{
    Param (
        [Parameter(Position = 0)]
        [String]$Target,
        
        [Parameter(Position = 1)]
        [Int]$Port, 
        
        [Parameter(Position = 2)]
        [String]$SslThumb, 

        [Parameter(Position = 3)]
        [Int]$Timeout = 60
    )

    # used if we're talking TLS, but not enforced, we just have to have something
    $TargetCNorSAN = "unknown"
    # does this look like an IP or a name?
    if ($Target -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
	write-host "we think $Target is an IP"
	$ServerAddr = [Net.IPAddress]$Target
	# leave the remote server name as defaulted
    }
    else {
	write-host "we think $Target is NOT an IP"
	# this means callers have to use a name and not an IP
	$ServerDNS = Resolve-DNSName -Name $Target -Type A -DNSOnly | where Section -eq Answer
	$ServerAddr = [Net.IPAddress]$ServerDNS.IP4Address
	# expect the destination to have it's DNS name in the CN or SAN
	$TargetCNorSAN = $Target
    }
    
    $TcpClient = New-Object Net.Sockets.TcpClient

    $ConnectResult = $TcpClient.BeginConnect($ServerAddr, $Port, $null, $null)

    $Stopwatch = [Diagnostics.Stopwatch]::StartNew()

    do {
        if ([console]::KeyAvailable) {          
            $Key = [console]::ReadKey($true)
            if ($Key.Key -eq [Consolekey]::Escape) {
                Write-Host 'Caught escape sequence, stopping TCP setup.'
                $TcpClient.Dispose()
                $Stopwatch.Stop()
                return $null
            }
        }
        if ($Stopwatch.Elapsed.TotalSeconds -gt $Timeout) {
            Write-Host 'Timeout exceeded, stopping TCP setup.'
            $TcpClient.Dispose()
            $Stopwatch.Stop()
            return $null
        }
    } until ($ConnectResult.IsCompleted)

    $Stopwatch.Stop()

    try { $TcpClient.EndConnect($ConnectResult) }
    catch {
        Write-Host "Connection to $($ServerAddr.IPAddressToString):$Port [tcp] failed. $($_.Exception.Message)"
        $TcpClient.Dispose()
        return $null
    }
    Write-Host "Connection to $($ServerAddr.IPAddressToString):$Port [tcp] succeeded!"
        
    $TcpStream = $TcpClient.GetStream()
    $Buffer = New-Object Byte[] $TcpClient.ReceiveBufferSize
    # here is where we can choose where to get the cert from
    # $Certificate = new X509Certificate2("filename", "password")
    if ($PSBoundParameters.SslThumb) { 
	$Certificate = Get-ChildItem Cert:\CurrentUser\My | where Thumbprint -Match $SslThumb
	Write-Host "Attempting client cert with DN = $($Certificate.Subject)"
	$CertColl = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
	$CertColl.Add($Certificate)
#        $TcpStream = New-Object System.Net.Security.SslStream($TcpStream, $false)
        $TcpStream = New-Object System.Net.Security.SslStream($TcpStream, $false, { param($Sender, $Cert, $Chain, $Policy) Write-Host "sender = $($Sender), cert = $($Cert), chain = $(Cchain), ssl policy errors = $($Policy)" ; return $true })
	$targethost = $TargetCNorSAN
        $TcpStream.AuthenticateAsClient($targethost,$CertColl,$false)
        Write-Host "TLS Encrypted: $($TcpStream.IsEncrypted)"
        Write-Host "TLS Signed: $($TcpStream.IsSigned)"
        Write-Host "TLS Authenticated: $($TcpStream.IsAuthenticated)"
        Write-Host "TLS Mutually Authenticated: $($TcpStream.IsMutuallyAuthenticated)"
	Write-Host "CRL check: $($TcpStream.CheckCertRevocationStatus)"
        # rjb
	if ($TcpStream.LocalCertificate -ne $null) {
	    Write-Host "Local certificate is $($TcpStream.LocalCertificate.Subject)"
	}
	else {
	    Write-Host "Local certificate is null"
	}
	if ($TcpStream.RemoteCertificate -ne $null) {
	    Write-Host "Remote certificate is $($TcpStream.RemoteCertificate.Subject)"
	}
	else {
	    Write-Host "Remote certificate is null"
	}
    }

    $Properties = @{
        Socket = $TcpClient.Client
        TcpStream = $TcpStream
        Buffer = $Buffer
        Read = $TcpStream.BeginRead($Buffer, 0, $Buffer.Length, $null, $null)
    }        
    return New-Object psobject -Property $Properties
}

function New-SSLServerStream
{
    Param (
        [Parameter(Position = 0)]
        [Int]$Port, 
        
        [Parameter(Position = 1)]
        [String]$SslCn, 

        [Parameter(Position = 2)]
        [Int]$Timeout = 60
    )

    $TcpListener = New-Object Net.Sockets.TcpListener $Port
    $TcpListener.Start()
    $ConnectResult = $TcpListener.BeginAcceptTcpClient($null, $null)

    Write-Host "Listening on 0.0.0.0:$Port [tcp]"
        
    $Stopwatch = [Diagnostics.Stopwatch]::StartNew()
      
    do {
        if ([console]::KeyAvailable) {          
            $Key = [console]::ReadKey($true)
            if ($Key.Key -eq [Consolekey]::Escape) {
                Write-Host 'Caught escape sequence, stopping TCP setup.'
                $TcpListener.Stop()
                $Stopwatch.Stop()
                return $null
            }
        }
        if ($Stopwatch.Elapsed.TotalSeconds -gt $Timeout) {
            Write-Host 'Timeout exceeded, stopping TCP setup.'
            $TcpListener.Stop()
            $Stopwatch.Stop()
            return $null
        }
    } until ($ConnectResult.IsCompleted)

    $Stopwatch.Stop() 

    $TcpClient = $TcpListener.EndAcceptTcpClient($ConnectResult)
    $TcpListener.Stop()
        
    if (!$TcpClient) {
	Write-Host "Connection to $($ServerAddr.IPAddressToString):$Port [tcp] failed."
	return $null
    }

    Write-Host "Connection from $($TcpClient.Client.RemoteEndPoint.ToString()) accepted."

    $TcpStream = $TcpClient.GetStream()
    $Buffer = New-Object Byte[] $TcpClient.ReceiveBufferSize

    if ($PSBoundParameters.SslCn) { 
        $TcpStream = New-Object System.Net.Security.SslStream($TcpStream, $false, { param($Sender, $Cert, $Chain, $Policy) Write-Host "ssl policy errors = $($Policy)" ; return $true }, { param($Sender, $targetHost, $localCerts, $remoteCert, $acceptableIssuers) return $localCerts[0] })
	# here is where we can choose where to get the cert from
	$Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
	$CertFlags = New-Object System.Security.Cryptography.X509Certificates.X509KeyStorageFlags::Exportable
	$Certificate.Import("msys2-ssc.pfx", "CNNMXBYC", $CertFlags)
        # $Certificate = Get-ChildItem Cert:\CurrentUser\My | where Subject -Match $SslCn
	Write-Host "Server cert DN = $($Certificate.Subject)"
        $TcpStream.AuthenticateAsServer($Certificate, $true, $false)
        Write-Host "TLS Encrypted: $($TcpStream.IsEncrypted)"
        Write-Host "TLS Signed: $($TcpStream.IsSigned)"
        Write-Host "TLS Authenticated: $($TcpStream.IsAuthenticated)"
	Write-Host "CRL check: $($TcpStream.CheckCertRevocationStatus)"
        # rjb
	if ($TcpStream.LocalCertificate -ne $null) {
	    Write-Host "Local certificate is $($TcpStream.LocalCertificate.Subject)"
	}
	else {
	    Write-Host "Local certificate is null"
	}
	if ($TcpStream.RemoteCertificate -ne $null) {
	    Write-Host "Remote certificate is $($TcpStream.RemoteCertificate.Subject)"
	}
	else {
	    Write-Host "Remote certificate is null"
	}
#        $PeerCertInfo = New-Object system.security.cryptography.x509certificates.x509certificate2($TcpStream.RemoteCertificate)
#        Write-Host "Peer Thumbprint: $($PeerCertInfo.ThumbPrint)"
    }
        
    $Properties = @{
        Socket = $TcpClient.Client
        TcpStream = $TcpStream
        Buffer = $Buffer
        Read = $TcpStream.BeginRead($Buffer, 0, $Buffer.Length, $null, $null)
    }
    return New-Object psobject -Property $Properties
}


function Read-NetworkStream($Stream)
{
    try { $BytesRead = $Stream.TcpStream.EndRead($Stream.Read) }
    catch { Write-Host "Failed to read Tcp stream. $($_.Exception.Message)." ; continue }

    if ($BytesRead) {
        $BytesReceived = $Stream.Buffer[0..($BytesRead - 1)]
        [Array]::Clear($Stream.Buffer, 0, $BytesRead)
    }
    $Stream.Read = $Stream.TcpStream.BeginRead($Stream.Buffer, 0, $Stream.Buffer.Length, $null, $null)

    if ($BytesRead) { return $BytesReceived }
    else { Write-Host 'Tcp stream closed by remote end.' }
}

function Write-NetworkStream($Stream,$Bytes)
{
    try { $Stream.TcpStream.Write($Bytes, 0, $Bytes.Length) }
    catch { Write-Host "Failed to write to Tcp stream. $($_.Exception.Message)." }
}

function Close-NetworkStream {
    Param (
        [Parameter(Position = 1)]
        [Object]$Stream
    )    

    try { 
        if ($PSVersionTable.CLRVersion.Major -lt 4) {
	    $Stream.Socket.Close()
	    $Stream.TcpStream.Close()
	}
        else {
	    $Stream.Socket.Dispose()
	    $Stream.TcpStream.Dispose()
	}
    }
    catch { Write-Host "Failed to close Tcp stream. $($_.Exception.Message)." }
}

function myclient
{
    Param (
	[Parameter(Position = 0)] [String]$ServerAddr = "127.0.0.1",
	[Parameter(Position = 1)] [Int]$Port = 4545,
	[Parameter(Position = 2)] [String]$SslThumb = "5A5B",
	[Parameter(Position = 3)] [Int]$Timeout = 10
    )

    try { $ClientStream = New-SSLClientStream $ServerAddr $Port $SslThumb $Timeout }
    catch { Write-Host "Failed to open tcp stream. $($_.Exception.Message)" ; return }

    $EncodingType = New-Object Text.UTF8Encoding

    [console]::TreatControlCAsInput = $true

    while ($true) {
        
        # Catch Esc / Read-Host
        if ([console]::KeyAvailable) {          
            $Key = [console]::ReadKey()
            if ($Key.Key -eq [Consolekey]::Escape) {
                Write-Host 'Caught escape sequence, stopping...'
                break
            }

            $BytesToSend = $EncodingType.GetBytes($Key.KeyChar + (Read-Host) + "`n") 
            Write-NetworkStream $ClientStream $BytesToSend

        }

        # Get data from the network
        if ($InitialBytes) { $ReceivedBytes = $InitialBytes ; $InitialBytes = $null }
        elseif ($ClientStream.Socket.Connected -or $ClientStream.Pipe.IsConnected) { 
            if ($ClientStream.Read.IsCompleted) { $ReceivedBytes = Read-NetworkStream $ClientStream } 
            else { Start-Sleep -Milliseconds 1 ; continue }
        }
        else { Write-Host "tcp connection broken, exiting." ; break }

        # Console
        try { Write-Host -NoNewline $EncodingType.GetString($ReceivedBytes).TrimEnd("`r") }
        catch { break } # network stream closed

    }
    Write-Host "`n"

    try { Close-NetworkStream $ClientStream }
    catch { Write-Host "Failed to close client stream. $($_.Exception.Message)" }

    [console]::TreatControlCAsInput = $false
}

function myserver
{
    Param (
	[Parameter(Position = 0)] [Int]$Port = 4545,
	[Parameter(Position = 1)] [String]$SslCn = "four1",
	[Parameter(Position = 2)] [Int]$Timeout = 10
    )

    try {
	$ServerStream = New-SSLServerStream $Port $SslCn $Timeout
	if ($ServerStream -eq $null) {
	    throw "no stream returned"
	}
    }
    catch {
	Write-Host "Failed to open tcp stream. $($_.Exception.Message)"
	return
    }

    $EncodingType = New-Object Text.UTF8Encoding

    while ($true) {
        # Catch Esc / Read-Host
        if ([console]::KeyAvailable) {          
            $Key = [console]::ReadKey()
            if ($Key.Key -eq [Consolekey]::Escape) {
                Write-Host 'Caught escape sequence, stopping...'
                break
            }
            $BytesToSend = $EncodingType.GetBytes($Key.KeyChar + (Read-Host) + "`n") 
            Write-NetworkStream $ServerStream $BytesToSend
        }

        # Get data from the network
        if ($InitialBytes) {
	    $ReceivedBytes = $InitialBytes
	    $InitialBytes = $null
	}
        elseif ($ServerStream.Socket.Connected -or $ServerStream.Pipe.IsConnected) { 
            if ($ServerStream.Read.IsCompleted) {
		$ReceivedBytes = Read-NetworkStream $ServerStream
	    }
            else {
		Start-Sleep -Milliseconds 1
		continue
	    }
        }
        else {
	    Write-Host "tcp connection broken, exiting."
	    break
	}
        # Console
        try { Write-Host -NoNewline $EncodingType.GetString($ReceivedBytes).TrimEnd("`r") }
        catch { break } # network stream closed

    }
    Write-Host "`n"

    try { Close-NetworkStream $ServerStream }
    catch { Write-Host "Failed to close server stream. $($_.Exception.Message)" }
}

