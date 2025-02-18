#pragma once
#include <stdint.h>

#include "KSocket.h"

// ---------------------------------------------------------------
// KIF
class KIf_EPOLLIN : public KSocket
{
	enum { EN_BYTES_read_buf = 65535 };
public:
	KIf_EPOLLIN(const KIF_Info& if_info, int protocol, bool bPromisc, int fd_epoll);
	virtual ~KIf_EPOLLIN() noexcept;
	
	// 戻り値 -> 将来何かに利用することを想定しているだけ
	int On_EPOLLIN(uint32_t events);
	
	// デバッグ用
	virtual void Show_Signature() const = 0;
	
protected:
	uint8_t* const m_pReadBuf;
	// 戻り値 -> 将来何かに利用することを想定しているだけ
	virtual int Do_On_EPOLLIN(int bytes_read) = 0;
};


// ---------------------------------------------------------------
// KIf_WAN
class KIf_WAN : public KIf_EPOLLIN
{
public:
	KIf_WAN(const KIF_Info& if_info, int protocol, bool bPromisc, int fd_epoll)
		: KIf_EPOLLIN(if_info, protocol, bPromisc, fd_epoll) {}

	virtual ~KIf_WAN() noexcept {}
	virtual void Show_Signature() const override;
	virtual int Do_On_EPOLLIN(int bytes_read) override;
};

// ---------------------------------------------------------------
// KIf_LAN
class KIf_LAN : public KIf_EPOLLIN
{
public:
	KIf_LAN(const KIF_Info& if_info, int protocol, bool bPromisc, int fd_epoll)
		: KIf_EPOLLIN(if_info, protocol, bPromisc, fd_epoll) {}

	virtual ~KIf_LAN() noexcept {}
	virtual void Show_Signature() const override;
	virtual int Do_On_EPOLLIN(int bytes_read) override;
};
