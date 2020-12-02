#pragma once
#define WIN32
#define HAVE_REMOTE
#define Ethernet_IPv4 0x0800
#define Ethernet_ARP 0x0806
#include <iostream>
#include "pcap.h"
#include <cstring>
#include <windows.h>
#include <WinSock2.h>

#pragma comment(lib,"ws2_32")
	

using namespace std;

#ifndef PCH_H
#define PCH_H
//Ethernet֡ size:14(Ethernet II)
struct EthernetHeader
{
	BYTE byDestMac[6];
	BYTE bySrcMac[6];
	USHORT usType;
};

//TCP ͷ��Ϣ size:20
struct TCPHeader
{
	USHORT m_sSourPort;   // Դ�˿ں�16bit
	USHORT m_sDestPort;   // Ŀ�Ķ˿ں�16bit
	ULONG m_uiSequNum;// ���к�32bit
	ULONG m_uiAcknowledgeNum;  // ȷ�Ϻ�32bit
	USHORT m_sHeaderLenAndFlag;// ǰ4λ��TCPͷ���ȣ���6λ����������6λ����־λ
	USHORT m_sWindowSize;// ���ڴ�С16bit
	USHORT m_sCheckSum;// �����16bit
	USHORT m_surgentPointer;// ��������ƫ����16bit
};

//ARP ͷ��Ϣ
struct ARPHeader
{
	USHORT usHardwareType;//Ethernet(1)
	USHORT ProtocolType;//IPv4(0x0800)
	BYTE byHardwareSize;
	BYTE byProtocolSize;
	BYTE byOpcode;//request(1)
	BYTE bySenderMAC[6];
	DWORD dwSenderIPaddress;
	BYTE byTargetMAC[6];
	DWORD dwTargetIPaddress;
};

// 4�ֽڵ�IP��ַ
typedef struct _IPAddress
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} IPAddress;

// IPv4 �ײ�
typedef struct _IPHeader
{
	BYTE m_byVerHLen;     //4λ�汾+4λ�ײ�����
	BYTE m_byTOS;         //��������
	USHORT m_usTotalLen; //�ܳ���
	USHORT m_usID; //��ʶ
	USHORT m_usFlagFragOffset; //3λ��־+13λ��ƫ��
	BYTE m_byTTL; //���ʱ��
	BYTE m_byProtocol; //Э��
	USHORT m_usHChecksum; //�ײ������
	IPAddress m_ulSrcIP; //ԴIP��ַ
	IPAddress m_ulDestIP; //Ŀ��IP��ַ
	UINT   op_pad;         // ѡ�������
}IPHeader;

// UDP �ײ�
typedef struct _UDPHeader
{
	USHORT src_port;          // Դ�˿�(Source port) 
	USHORT dest_port;         // Ŀ�Ķ˿�(Destination port) 
	USHORT datalen;           // UDP���ݰ�����(Datagram length) 
	USHORT checksum;          // У���(Checksum) 
} UDPHeader;

// ICMPͷ��Ϣ
struct ICMPHeader
{
	BYTE m_byType; //����
	BYTE m_byCode; //����
	USHORT m_usChecksum; //�����
	USHORT m_usID; //��ʶ��
	USHORT m_usSeq; //���
	ULONG m_ulTimeStamp; //ʱ������Ǳ�׼ICMPͷ����
};


// �����ص�
void end_loop();
// �ص�����
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

#endif //PCH_H

//#include "pch.h"

pcap_t* adhandle;
time_t t_start, t_end;
// ͳ�ư���
int ip_count = 0, icmp_count = 0, arp_count = 0;

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	char errorbuff[PCAP_ERRBUF_SIZE];
	int index = 0;
	char sel_name[256] = { 0 };
	// Ĭ���������� 
	u_int netmask = 0xffffffff;

	bpf_program bpf_pro = { 0 };

	// ��ȡ���ػ����豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errorbuff) == PCAP_ERROR)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errorbuff);
		return 0;
	}

	// ��ӡ�б�
	for (d = alldevs; d != NULL; d = d->next, index++) {
		//��ȡ ip ��ַ
		for (pcap_addr_t* tmp = d->addresses, *t = NULL; tmp != t; tmp = tmp->next)
		{
			if (tmp->addr->sa_family == AF_INET)
			{
				if (tmp->addr)
				{
					printf("��Address��:%s\n", inet_ntoa(((sockaddr_in*)tmp->addr)->sin_addr));
				}
			}
		}
		printf("��Description��:%s\n��Name��:%s\n\n", d->description, d->name);

		// ѡ���Լ������������ݴ�ӡ���б���Ϣ���Լ�ѡ��index��ֵ��
		if (index == 2)
		{
			for (pcap_addr_t* tmp = d->addresses, *t = NULL; tmp != t; tmp = tmp->next)
			{
				netmask = ((struct sockaddr_in*)(tmp->netmask))->sin_addr.S_un.S_addr;
			}
			strcpy(sel_name, d->name);
		}
	}

	// ���豸
	if ((adhandle = pcap_open(sel_name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errorbuff)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		// �ͷ��豸�б�
		pcap_freealldevs(alldevs);
		return 0;
	}

	// ���������·��
	if (pcap_datalink(adhandle) != DLT_EN10MB) // ��̫��
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return 0;
	}

	// ���������
	if (pcap_compile(adhandle, &bpf_pro, "ip or icmp or arp", 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return 0;
	}

	// ���ù�������
	if (pcap_setfilter(adhandle, &bpf_pro) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return 0;
	}

	// �ͷ��豸�б�
	pcap_freealldevs(alldevs);

	t_start = time(NULL);
	//��ʼ������
	pcap_loop(adhandle, 0, packet_handler, NULL);

	//�ͷ�һ��������
	pcap_freecode(&bpf_pro);
	pcap_close(adhandle);

	printf("ip = %d , icmp = %d , arp = %d\n\n", ip_count, icmp_count, arp_count);

	return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	EthernetHeader* ethernet = (EthernetHeader*)pkt_data;

	// �������ֽ�����ת���������ֽ�����
	auto tep = ntohs(ethernet->usType);
	// ARP
	if (tep == Ethernet_ARP)
	{
		ARPHeader* arpHeader = (ARPHeader*)(ethernet + 1);

		for (byte item : arpHeader->bySenderMAC)
		{
			printf("%d-", item);
		}
		printf("\n\n");

		arp_count += 1;
	}
	// IP
	if (tep == Ethernet_IPv4)
	{
		// ��IP�㿪ʼ����ȡԭʼ��IP��Э�飻��ƫ��14�ֽڣ���̫��֡ͷ�����ȣ���ȡ����
		IPHeader* iphdr = (IPHeader*)(pkt_data + sizeof(EthernetHeader));
		printf("%d.%d.%d.%d\t%d.%d.%d.%d\n",
			iphdr->m_ulSrcIP.byte1, iphdr->m_ulSrcIP.byte2,
			iphdr->m_ulSrcIP.byte3, iphdr->m_ulSrcIP.byte4,
			iphdr->m_ulDestIP.byte1, iphdr->m_ulDestIP.byte2,
			iphdr->m_ulDestIP.byte3, iphdr->m_ulDestIP.byte4
		);
		printf("%d.%05d\tlen:%d\n\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

		// ICMP
		if (iphdr->m_byProtocol == IPPROTO_ICMP)
		{
			ICMPHeader* icmphdr = (ICMPHeader*)(pkt_data + 14 + sizeof(IPHeader));
			printf("Type:%d\t%d\n", icmphdr->m_byType, icmphdr->m_ulTimeStamp);
			char data[100] = { 0 };
			memcpy(data, ((char*)icmphdr) + sizeof(ICMPHeader), 50);
			data[strlen(data) - 1] = '\0';
			printf("Data:%s\n\n", data);

			icmp_count += 1;
		}
		else
		{
			ip_count += 1;
		}
	}

	end_loop();
}

void end_loop() {
	t_end = time(NULL);
	if (difftime(t_end, t_start) >= 5)
	{
		pcap_breakloop(adhandle);
	}
}
