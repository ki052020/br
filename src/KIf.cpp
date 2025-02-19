#include <sys/epoll.h>

#include "my_basic.h"
#include "KException.h"
#include "KIf.h"

#include "main.h"

// -------------------------------------------------------------------------
static void Printf_mac_addrs(KHdr_v6* const pHdr_v6)
{
	pHdr_v6->Wrt_IF_signature();
	const auto [pcstr_dst, _1] = g_IF_Infos.Get_Name_by_mac_addr(pHdr_v6->Get_DST_mac_addr());
	printf("++ dst mac -> %s\n", pcstr_dst);
	const auto [pcstr_src, _2] = g_IF_Infos.Get_Name_by_mac_addr(pHdr_v6->Get_SRC_mac_addr());
	printf("   src mac -> %s\n", pcstr_src);
}

////////////////////////////////////////////////////////////////////////////
// KIf_EPOLLIN
KIf_EPOLLIN::KIf_EPOLLIN(
		const KIF_Info& if_info, const int protocol, const bool bPromisc, const int fd_epoll)
	: KSocket(if_info, protocol, bPromisc)
	, m_pReadBuf{ new uint8_t[EN_BYTES_read_buf] }
{
	epoll_event event;
	event.events = EPOLLIN;
	event.data.ptr = this;

	if (epoll_ctl(fd_epoll, EPOLL_CTL_ADD, m_fd, &event) < 0)
	{
		delete[] m_pReadBuf;
		THROW("epoll_ctl(fd_epoll, EPOLL_CTL_ADD, m_fd, &event) < 0");
	}
}

// -------------------------------------------------------------------------
KIf_EPOLLIN::~KIf_EPOLLIN() noexcept
{
	delete[] m_pReadBuf;
}

// -------------------------------------------------------------------------
// 戻り値 -> 将来何かに利用することを想定しているだけ
int KIf_EPOLLIN::On_EPOLLIN(const uint32_t events)
{
	if (events != EPOLLIN)
	{
		std::string str;
		str.reserve(100);
		str = str + "events != EPOLLIN / events -> " + std::to_string(events);
		THROW(str);
	}
		
	const int bytes_read = (int)read(m_fd, (void*)m_pReadBuf, EN_BYTES_read_buf);
	if (bytes_read <= 0)
		{ THROW("bytes_read <= 0"); }
		
	// 現在は、暫定的な処理しかしない
	return this->Do_On_EPOLLIN(bytes_read);

//	return G_AnalyzePacket(m_pReadBuf, bytes_read);
}

// -------------------------------------------------------------------------
// デバッグ用： dst mac addr が自分宛でない場合、mac addr 情報を表示する
void KIf_EPOLLIN::Chk_DST_mac_addr(KHdr_v6* const pHdr_v6)
{
	uint64_t dst_mac_addr = *(uint64_t*)m_pReadBuf & 0xffff'ffff'ffff;
	if (dst_mac_addr != m_mac_addr)
		{ Printf_mac_addrs(pHdr_v6); }
}


////////////////////////////////////////////////////////////////////////////
// KIf_WAN
int KIf_WAN::Do_On_EPOLLIN(const int bytes_read)
{
	KHdr_v6 hdr_v6{ m_pReadBuf, bytes_read, this };
#if true
	this->Chk_DST_mac_addr(&hdr_v6);
#endif

	printf(MGT_B("--- KIf_WAN\n"));
	return G_AnalyzePacket(m_pReadBuf, bytes_read);
}

// -------------------------------------------------------------------------
void KIf_WAN::Wrt_Signature(FILE* const pf) const
{
	fprintf(pf, MGT_B("--- KIf_WAN\n"));
}


////////////////////////////////////////////////////////////////////////////
// KIf_LAN

// 戻り値 -> 将来何かに利用することを想定しているだけ
int KIf_LAN::Do_On_EPOLLIN(const int bytes_read)
{
	KHdr_v6 hdr_v6{ m_pReadBuf, bytes_read, this };
#if true
	this->Chk_DST_mac_addr(&hdr_v6);
#endif

	for (KHdr_Next hdr_next = hdr_v6.Get_Hdr_Next(); hdr_next.m_Next_Header >= 0; )
	{
		switch(int next_header = hdr_next.m_Next_Header; next_header)
		{
		case IPPROTO_HOPOPTS: {
			const KHop_v6 hop_v6{ hdr_next };
			hop_v6.Dump();
			hdr_next = hop_v6.Get_Hdr_Next();
			}
			continue;
			
		case IPPROTO_ICMPV6:
			this->Proc_Icmp_v6(hdr_next);
			return 0;  // ICMPv6 の後にヘッダが続くことはない
			
		default:
			Printf_mac_addrs(&hdr_v6);
			printf("   不明な Next_Header -> %d", next_header);
		}
		break;
	}
	
#if false
	printf(GRN_B("--- KIf_LAN\n"));
	return G_AnalyzePacket(m_pReadBuf, bytes_read);
#endif
	return 0;
}

// -------------------------------------------------------------------------
void KIf_LAN::Wrt_Signature(FILE* const pf) const
{
	fprintf(pf, GRN_B("--- KIf_LAN\n"));
}

// -------------------------------------------------------------------------
void KIf_LAN::Proc_Icmp_v6(const KHdr_Next& hdr_next)
{
	// ##### デバッグ
	{
		const uint8_t* ptop = (uint8_t*)hdr_next.m_pHdr_v6->mc_pEth_hdr;
		const int bytes_consumed = int(hdr_next.m_pNext - ptop);
		if (bytes_consumed + hdr_next.m_bytes_rem_next != hdr_next.m_pHdr_v6->mc_bytes_packet_entire)
			{ THROW("KIf_LAN::Proc_Icmp_v6() -> 読み取りバイト数に不整合を検知しました。"); }
	}
	
	// ---------------------------------------	
	const uint8_t* ptr = hdr_next.m_pNext;
	int bytes = hdr_next.m_bytes_rem_next;
	
	switch (const int type = *ptr; type)
	{
	case 143: {  // Version 2 Multicast Listener Report RFC3810
		KIcmp_v6 imcp_v6{ hdr_next };
		}
		return;

	default:
		hdr_next.m_pHdr_v6->Wrt_IF_signature();
		printf("++ ICMPv6 : 不明な type -> %d\n", type);
		printf("   ICMPv6 bytes -> %d\n\n", bytes);
		break;
	}
}

