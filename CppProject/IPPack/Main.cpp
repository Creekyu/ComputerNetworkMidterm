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
//Ethernet帧 size:14(Ethernet II)
struct EthernetHeader
{
	BYTE byDestMac[6];
	BYTE bySrcMac[6];
	USHORT usType;
};

//TCP 头信息 size:20
struct TCPHeader
{
	USHORT m_sSourPort;   // 源端口号16bit
	USHORT m_sDestPort;   // 目的端口号16bit
	ULONG m_uiSequNum;// 序列号32bit
	ULONG m_uiAcknowledgeNum;  // 确认号32bit
	USHORT m_sHeaderLenAndFlag;// 前4位：TCP头长度；中6位：保留；后6位：标志位
	USHORT m_sWindowSize;// 窗口大小16bit
	USHORT m_sCheckSum;// 检验和16bit
	USHORT m_surgentPointer;// 紧急数据偏移量16bit
};

//ARP 头信息
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

// 4字节的IP地址
typedef struct _IPAddress
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} IPAddress;

// IPv4 首部
typedef struct _IPHeader
{
	BYTE m_byVerHLen;     //4位版本+4位首部长度
	BYTE m_byTOS;         //服务类型
	USHORT m_usTotalLen; //总长度
	USHORT m_usID; //标识
	USHORT m_usFlagFragOffset; //3位标志+13位段偏移
	BYTE m_byTTL; //存活时间
	BYTE m_byProtocol; //协议
	USHORT m_usHChecksum; //首部检验和
	IPAddress m_ulSrcIP; //源IP地址
	IPAddress m_ulDestIP; //目的IP地址
	UINT   op_pad;         // 选项与填充
}IPHeader;

// UDP 首部
typedef struct _UDPHeader
{
	USHORT src_port;          // 源端口(Source port) 
	USHORT dest_port;         // 目的端口(Destination port) 
	USHORT datalen;           // UDP数据包长度(Datagram length) 
	USHORT checksum;          // 校验和(Checksum) 
} UDPHeader;

// ICMP头信息
struct ICMPHeader
{
	BYTE m_byType; //类型
	BYTE m_byCode; //代码
	USHORT m_usChecksum; //检验和
	USHORT m_usID; //标识符
	USHORT m_usSeq; //序号
	ULONG m_ulTimeStamp; //时间戳（非标准ICMP头部）
};


// 结束回调
void end_loop();
// 回调函数
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

#endif //PCH_H

//#include "pch.h"

pcap_t* adhandle;
time_t t_start, t_end;
// 统计包数
int ip_count = 0, icmp_count = 0, arp_count = 0;

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	char errorbuff[PCAP_ERRBUF_SIZE];
	int index = 0;
	char sel_name[256] = { 0 };
	// 默认子网掩码 
	u_int netmask = 0xffffffff;

	bpf_program bpf_pro = { 0 };

	// 获取本地机器设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errorbuff) == PCAP_ERROR)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errorbuff);
		return 0;
	}

	// 打印列表
	for (d = alldevs; d != NULL; d = d->next, index++) {
		//获取 ip 地址
		for (pcap_addr_t* tmp = d->addresses, *t = NULL; tmp != t; tmp = tmp->next)
		{
			if (tmp->addr->sa_family == AF_INET)
			{
				if (tmp->addr)
				{
					printf("【Address】:%s\n", inet_ntoa(((sockaddr_in*)tmp->addr)->sin_addr));
				}
			}
		}
		printf("【Description】:%s\n【Name】:%s\n\n", d->description, d->name);

		// 选择自己的网卡（根据打印的列表信息，自己选定index的值）
		if (index == 2)
		{
			for (pcap_addr_t* tmp = d->addresses, *t = NULL; tmp != t; tmp = tmp->next)
			{
				netmask = ((struct sockaddr_in*)(tmp->netmask))->sin_addr.S_un.S_addr;
			}
			strcpy(sel_name, d->name);
		}
	}

	// 打开设备
	if ((adhandle = pcap_open(sel_name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errorbuff)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		// 释放设备列表
		pcap_freealldevs(alldevs);
		return 0;
	}

	// 检查数据链路层
	if (pcap_datalink(adhandle) != DLT_EN10MB) // 以太网
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return 0;
	}

	// 编译过滤器
	if (pcap_compile(adhandle, &bpf_pro, "ip or icmp or arp", 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return 0;
	}

	// 设置过滤条件
	if (pcap_setfilter(adhandle, &bpf_pro) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return 0;
	}

	// 释放设备列表
	pcap_freealldevs(alldevs);

	t_start = time(NULL);
	//开始处理函数
	pcap_loop(adhandle, 0, packet_handler, NULL);

	//释放一个过滤器
	pcap_freecode(&bpf_pro);
	pcap_close(adhandle);

	printf("ip = %d , icmp = %d , arp = %d\n\n", ip_count, icmp_count, arp_count);

	return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	EthernetHeader* ethernet = (EthernetHeader*)pkt_data;

	// 将网络字节序列转换成主机字节序列
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
		// 从IP层开始，获取原始的IP层协议；并偏移14字节（以太网帧头部长度）读取数据
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
