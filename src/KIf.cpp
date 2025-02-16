#include <sys/epoll.h>

#include "my_basic.h"
#include "KException.h"
#include "KIf.h"

#include "main.h"

///////////////////////////////////////////////////////////////////////
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

// -------------------------------------------------------------------------------------
KIf_EPOLLIN::~KIf_EPOLLIN() noexcept
{
	delete[] m_pReadBuf;
}

// -------------------------------------------------------------------------------------
// 戻り値 -> 将来何かに利用することを想定しているだけ
int KIf_EPOLLIN::PreProc_EPOLLIN(const uint32_t events)
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
//	return this->On_EPOLLIN(bytes_read);

	return G_AnalyzePacket(m_pReadBuf, bytes_read);
}
