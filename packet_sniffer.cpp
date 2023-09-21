#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <cstring> 

struct ethheader {
    u_char  ether_dhost[6];    // 목적지 MAC 주소
    u_char  ether_shost[6];    // 소스 MAC 주소
    u_short ether_type;         // 프레임의 타입 (IP, ARP 등)
};

struct ipheader {
    unsigned char      iph_ihl:4,    // IP 헤더 길이 (버전 및 헤더 길이)
                       iph_ver:4;    // IP 버전
    unsigned char      iph_tos;      // 서비스 타입 (Type of Service)
    unsigned short int iph_len;      // IP 패킷 길이 (헤더 + 데이터)
    unsigned short int iph_ident;    // 패킷 식별자
    unsigned short int iph_flag:3,   // 플래그 필드 (플래그 및 단편화 옵션)
                       iph_offset:13; // 단편화 옵션 오프셋
    unsigned char      iph_ttl;      // Time to Live
    unsigned char      iph_protocol; // 프로토콜 타입 (TCP, UDP, ICMP 등)
    unsigned short int iph_chksum;   // IP 헤더 체크섬
    struct  in_addr    iph_sourceip; // 송신자 IP 주소
    struct  in_addr    iph_destip;   // 수신자 IP 주소
};

struct tcpheader {
    u_short tcp_sport;           // 송신 TCP 포트
    u_short tcp_dport;           // 수신 TCP 포트
    u_int   tcp_seq;             // 순차 번호
    u_int   tcp_ack;             // 확인 번호
    u_char  tcp_offx2;           // 데이터 오프셋 및 예약 필드
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;           // 플래그 (FIN, SYN, RST, PSH, ACK 등)
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;             // 윈도우 크기
    u_short tcp_sum;             // TCP 체크섬
    u_short tcp_urp;             // 긴급 포인터
};

using namespace std;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    cout << "Ethernet Header:" << endl;
    cout << "Source MAC: ";
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth->ether_shost[i]);
        if (i < 5) cout << ":";
    }
    cout << endl;

    cout << "Destination MAC: ";
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth->ether_dhost[i]);
        if (i < 5) cout << ":";
    }
    cout << endl;

    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        cout << "IP Header:" << endl;
        cout << "Source IP: " << inet_ntoa(ip->iph_sourceip) << endl;
        cout << "Destination IP: " << inet_ntoa(ip->iph_destip) << endl;

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));

            cout << "TCP Header:" << endl;
            cout << "Source Port: " << ntohs(tcp->tcp_sport) << endl;
            cout << "Destination Port: " << ntohs(tcp->tcp_dport) << endl;

            int data_offset = TH_OFF(tcp) * 4;
            int message_length = ntohs(ip->iph_len) - (ip->iph_ihl * 4) - data_offset;
            cout << "Message Data (first " << min(message_length, 16) << " bytes): ";
            for (int i = 0; i < min(message_length, 16); i++) {
                printf("%02x", packet[sizeof(struct ethheader) + (ip->iph_ihl * 4) + data_offset + i]);
            }
            cout << endl;
        }
    }
    cout << "--------------------------------------" << endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    // 네트워크 인터페이스 목록 찾기
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding network interfaces: " << errbuf << endl;
        return 1;
    }

    // 첫 번째 인터페이스 선택 (예: alldevs)
    dev = alldevs->name;
    
    // 디바이스 열기
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Could not open device " << dev << ": " << errbuf << endl;
        return 1;
    }

    // TCP 패킷 스니핑 및 처리
    cout << "Start capturing TCP packets on device: " << dev << endl;
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}