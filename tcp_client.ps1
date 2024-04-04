$serverIP = "10.0.2.15" 
$serverPort = 7777  
$message = "It's-a me! Mario"

$client = New-Object System.Net.Sockets.TcpClient
$client.Connect($serverIP, $serverPort)

$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$reader = New-Object System.IO.StreamReader($stream)

$writer.WriteLine($message)
$writer.Flush()

$response = $reader.ReadLine()
Write-Host "서버 응답: $response"

$writer.Close()
$reader.Close()
$client.Close()
