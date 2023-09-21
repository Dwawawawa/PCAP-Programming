$serverIP = "172.24.242.216" 
$serverPort = 7777  
$message = "여기는 j2s, 화이트햇스쿨 응답하라 오버!"

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
