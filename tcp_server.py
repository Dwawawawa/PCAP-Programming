import socket

server_ip = "0.0.0.0"  # 모든 인터페이스에서 연결을 수락합니다.
server_port = 7777

# 소켓 생성
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 소켓을 특정 IP 주소와 포트 번호에 바인딩
server_socket.bind((server_ip, server_port))

# 클라이언트 연결을 수락
server_socket.listen(5)

print(f"서버가 {server_ip}:{server_port}에서 실행 중입니다.")

while True:
    # 클라이언트와의 연결을 수락
    client_socket, client_address = server_socket.accept()
    print(f"클라이언트 {client_address[0]}:{client_address[1]}가 연결되었습니다.")

    # 클라이언트로부터 메시지 수신
    data = client_socket.recv(1024)
    if not data:
        break

    received_message = data.decode('utf-8')
    print(f"클라이언트로부터 받은 메시지: {received_message}")

    # 클라이언트에게 응답을 보냄
    response_message = "I'm-a Luigi, number one!!"
    client_socket.send(response_message.encode('utf-8'))

    # 클라이언트 소켓 닫기
    client_socket.close()

# 서버 소켓 닫기
server_socket.close()
