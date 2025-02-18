#include <sys/epoll.h>

#include "my_basic.h"
#include "KException.h"
#include "KIf.h"
#include "KIPv6.h"

#include "main.h"


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


////////////////////////////////////////////////////////////////////////////
// KIf_WAN
int KIf_WAN::Do_On_EPOLLIN(const int bytes_read)
{
	printf(MGT_B("--- KIf_WAN\n"));
	return G_AnalyzePacket(m_pReadBuf, bytes_read);
}

// -------------------------------------------------------------------------
void KIf_WAN::Show_Signature() const
{
	printf(MGT_B("--- KIf_WAN\n"));
}


////////////////////////////////////////////////////////////////////////////
// KIf_LAN
int KIf_LAN::Do_On_EPOLLIN(const int bytes_read)
{
	KHdr_v6 hdr_v6{ m_pReadBuf, bytes_read, this };
	
	for (KHdr_Next blk_next = hdr_v6.Get_Hdr_Next(); blk_next.m_Next_Header >= 0; )
	{
		switch(int next_header = blk_next.m_Next_Header; next_header)
		{
		case IPPROTO_HOPOPTS: {
			const KHop_v6 hop_v6{ blk_next };
			hop_v6.Dump();
			blk_next = hop_v6.Get_Hdr_Next();
			}
			continue;
			
		case IPPROTO_ICMPV6: {
			const KIcmp_v6 icmp_v6{ blk_next };
			}
			break;  // ICMPv6 の後にヘッダが続くことはない
			
		default:
			this->Show_Signature();
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
void KIf_LAN::Show_Signature() const
{
	printf(GRN_B("--- KIf_LAN\n"));
}

