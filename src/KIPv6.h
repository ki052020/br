#pragma once
#include	<netinet/if_ether.h>
#include	<netinet/ip6.h>
#include	<netinet/icmp6.h>

#include "KException.h"

// --------------------------------------------------------------------
void G_DBG_Show_Eth_hdr(const void* pEth_hdr, FILE* fd = stdout);

// --------------------------------------------------------------------
// KIp_v6
class KIp_v6
{
	friend class KIcmp_v6;
public:
	KIp_v6(const void* const pEth_hdr,const void* const pIp6_hdr)
		: mc_pEth_hdr{ (ether_header*)pEth_hdr }
		, mc_pIp6_hdr{ (ip6_hdr*)pIp6_hdr }
	{
		// 念のための確認
		if ((*(uint8_t*)pIp6_hdr & 0xf0) != 0x60)
			{ THROW("*(uint8_t*)pIp6_hdr & 0xf0 != 0x60"); }
	}

	// ---------------------------------------
	bool Is_Src_null() const;  // DAD で利用される
	bool Is_Dst_multicast() const;  // ARP で利用される

	const char* Get_Src_Name() const;
	const char* Get_Dst_Name() const;

	void DBG_ShowSelf(FILE* fd = stdout) const;
	void DBG_Show_Eth_IPv6_Hdr(FILE* fd = stdout) const;

private:
	const ether_header* const mc_pEth_hdr;
	const ip6_hdr* const mc_pIp6_hdr;
};

// --------------------------------------------------------------------
class KIcmp_v6
{
public:
	KIcmp_v6(const KIp_v6* pIpv6, const void* const pIcmp_v6)
		: mc_pIP_v6{ pIpv6 }
		, mc_pIcmp6_hdr{ (icmp6_hdr*)pIcmp_v6 } {}

	void DBG_ShowSelf(int payload_len, FILE* fd = stdout) const;

	const KIp_v6* const mc_pIP_v6;
	const icmp6_hdr* const mc_pIcmp6_hdr;

private:
	const uint8_t* pIcmp6_hdr_ui8() const { return (uint8_t*)mc_pIcmp6_hdr; }

	// オプション部分の長さだけを渡すこと
	void DBG_Show_N_Sol(int option_len, FILE* fd = stdout) const;
	void DBG_Show_N_Sol_1_2(const uint8_t* p_option, int option_len, FILE* fd = stdout) const;

	void DBG_Show_N_Adv(int option_len, FILE* fd = stdout) const;
};

