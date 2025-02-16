#include "my_basic.h"
#include <arpa/inet.h>
#include <tuple>
#include "KIPv6.h"

#include <format>
#define DBG_F( fd, fmt, ... )  fprintf(fd, (std::format(fmt, __VA_ARGS__)).c_str());

#include "main.h"
#include "KSocket.h"

#define END_MARK "\x1b[1mEND\x1b[0m"

///////////////////////////////////////////////////////////////////////
// KIp_v6
bool KIp_v6::Is_Src_null() const
{
	const uint64_t* psrc_ui64 = (uint64_t*)mc_pIp6_hdr->ip6_src.s6_addr;
	return (psrc_ui64[0] == 0 && psrc_ui64[1] == 0);
}

// --------------------------------------------------------------------
bool KIp_v6::Is_Dst_multicast() const
{
	const uint8_t* psrc_ui8 = mc_pIp6_hdr->ip6_src.s6_addr;
	if (psrc_ui8[0] != 0xff) { return false; }
	if (psrc_ui8[1] != 0x02) { return true; }

	THROW("multicast address != 0xff02");
}

// --------------------------------------------------------------------
const char* KIp_v6::Get_Src_Name() const
{
	const uint8_t* psrc_ui8 = mc_pIp6_hdr->ip6_src.s6_addr;
	const auto [pname, _] = g_IF_Infos.Get_Name_by_v6_addr(psrc_ui8);
	return pname;
}

// --------------------------------------------------------------------
const char* KIp_v6::Get_Dst_Name() const
{
	const uint8_t* psrc_ui8 = mc_pIp6_hdr->ip6_dst.s6_addr;
	const auto [pname, _] = g_IF_Infos.Get_Name_by_v6_addr(psrc_ui8);
	return pname;
}

// --------------------------------------------------------------------
// KIp_v6::DBG_Show
void KIp_v6::DBG_ShowSelf(FILE* fd) const
{
	const int payload_len = Cx_ntohs(mc_pIp6_hdr->ip6_plen);
	DBG_F(fd, "--- v6 payload -> {} B\n", payload_len);

	switch(mc_pIp6_hdr->ip6_nxt)
	{
	case IPPROTO_ICMPV6:
		KIcmp_v6{ this, ((uint8_t*)mc_pIp6_hdr) + 40 }.DBG_ShowSelf(payload_len, fd);
		return;

	case IPPROTO_TCP:
		fprintf(fd, "   TCP\n\n");
		return;

	case IPPROTO_UDP:
		fprintf(fd, "   UDP\n\n");
		return;
	}
}

// --------------------------------------------------------------------
// KIp_v6::DBG_Show_Eth_IPv6_Hdr
void KIp_v6::DBG_Show_Eth_IPv6_Hdr(FILE* fd) const
{
	uint64_t dst_mac_addr = *(uint64_t*)mc_pEth_hdr & 0xffff'ffff'ffff;
	uint64_t src_mac_addr = *(uint64_t*)((uint8_t*)mc_pEth_hdr + 6) & 0xffff'ffff'ffff;

	const auto [cstr_src_mac_addr, _2] = g_IF_Infos.Get_Name_by_mac_addr(src_mac_addr);
	const auto [cstr_dst_mac_addr, _1] = g_IF_Infos.Get_Name_by_mac_addr(dst_mac_addr);
	fprintf(fd, " -- Ether header\n   src mac -> %s\n   dst mac -> %s\n"
					, cstr_src_mac_addr, cstr_dst_mac_addr);

	const uint8_t* p_v6_hdr = (uint8_t*)mc_pIp6_hdr;
	const auto [cstr_src_v6_addr, _3] = g_IF_Infos.Get_Name_by_v6_addr(p_v6_hdr + 8);
	const auto [cstr_dst_v6_addr, _4] = g_IF_Infos.Get_Name_by_v6_addr(p_v6_hdr + 24);
	fprintf(fd, " -- IPv6 header\n   src v6 addr -> %s\n   dst v6 addr -> %s\n"
					, cstr_src_v6_addr, cstr_dst_v6_addr);
}


///////////////////////////////////////////////////////////////////////
// KIcmp_v6
// KIcmp_v6::DBG_Show

#define OPT WHT_B("   opt : ")

void KIcmp_v6::DBG_ShowSelf(const int payload_len, FILE* fd) const
{
	switch (mc_pIcmp6_hdr->icmp6_type)
	{
	case 1:
		fprintf(fd, "   ICMPv6 -> Destination Unreachable\n\n");
		return;
	case 128:
		fprintf(fd, "   ICMPv6 -> Echo Request\n\n");
		return;
	case 129:
		fprintf(fd, "   ICMPv6 -> Echo Reply\n\n");
		return;
	case 133:
		fprintf(fd, "   ICMPv6 -> " MGT_B("R_Sol") "\n\n");
		return;
	case 134:
		fprintf(fd, "   ICMPv6 -> " MGT_B("R_Adv") "\n\n");
		return;

	case 135:  // ICMPv6 -> Neighbor Solicitation
		this->DBG_Show_N_Sol(payload_len - 24);
		return;

	case 136:  // ICMPv6 -> Neighbor Advertisement
		this->DBG_Show_N_Adv(payload_len - 24);
		return;

	default:
		fprintf(fd, "   ICMPv6 -> ??\n\n");
		return;
	}
}

// --------------------------------------------------------------------
// KIcmp_v6::DBG_Show_N_Sol
void KIcmp_v6::DBG_Show_N_Sol(const int option_len, FILE* fd) const
{
	const uint8_t* pIcmp6_hdr_ui8 = this->pIcmp6_hdr_ui8();
	const void* pTgt_addr_ui64 = (const void*)(pIcmp6_hdr_ui8 + 8);

	// -------------------------------------
	// Target addr
	const auto [pcstr_Tgt_addr, b_known] = g_IF_Infos.Get_Name_by_v6_addr(pTgt_addr_ui64);
	fprintf(fd, "   ICMPv6 -> " GRN_B("N_Sol") " / Target v6 addr -> %s\n", pcstr_Tgt_addr);
	if (b_known == false)
		{ mc_pIP_v6->DBG_Show_Eth_IPv6_Hdr(fd); }

	// -------------------------------------
	if (option_len == 0)
	{
		fprintf(fd, OPT "none\n\n");
		return;
	}

	const uint8_t* p_opt = pIcmp6_hdr_ui8 + 24;
	switch (*p_opt)
	{
	case 1:
	case 2:
		this->DBG_Show_N_Sol_1_2(p_opt, option_len, fd);
		return;

	default:
		DBG_F(fd, OPT "{}\n\n", *p_opt);
		return;
	}
}

// --------------------------------------------------------------------
// KIcmp_v6::DBG_Show_N_Sol_1_2
// 1 -> Source L2 Address / 2 -> Target L2 Address
void KIcmp_v6::DBG_Show_N_Sol_1_2(const uint8_t* const p_opt, const int opt_len, FILE* fd) const
{
	if (opt_len != 8)
		{ THROW("option_len != 8"); }

	if (*p_opt == 1)
		{ fprintf(fd, OPT "Source L2 addr -> "); }
	else
		{ fprintf(fd, OPT "Target L2 addr -> "); }

	const uint64_t mac_addr = *(uint64_t*)(p_opt + 2);
	const auto [cstr_mac_addr, b_known] = g_IF_Infos.Get_Name_by_mac_addr(mac_addr);
	fprintf(fd, "%s\n", cstr_mac_addr);

	if (b_known == false)
		{ mc_pIP_v6->DBG_Show_Eth_IPv6_Hdr(fd); }
	fprintf(fd, "\n");

#if false
	{
		fprintf(fd, "   " END_MARK "\n\n");
		return;
	}

	// 未知の mac addr を受け取ったときは、追加情報を表示する
	mc_pIP_v6->DBG_Show_Eth_IPv6_Hdr(fd);
	fprintf(fd, "\n\n");
//	fprintf(fd, "   " END_MARK "\n\n");
#endif
}

// --------------------------------------------------------------------
// KIcmp_v6::DBG_Show_N_Adv
void KIcmp_v6::DBG_Show_N_Adv(int n_adv_opt_len, FILE* fd) const
{
	const uint8_t* pIcmp6_hdr_ui8 = this->pIcmp6_hdr_ui8();
	const void* pTgt_addr_ui64 = (const void*)(pIcmp6_hdr_ui8 + 8);

	// -------------------------------------
	// Target addr
	const auto [pcstr_Tgt_addr, _] = g_IF_Infos.Get_Name_by_v6_addr(pTgt_addr_ui64);
	fprintf(fd, "   ICMPv6 -> " GRN_B("N_Adv") " / ");
	{
		const uint8_t flags = *(pIcmp6_hdr_ui8 + 4);
		fprintf(fd, "\x1b[1;32m");
		if (flags & 0x80) { fprintf(fd, "Rt-src "); }
		if (flags & 0x40) { fprintf(fd, "Sol-rep "); }
		if (flags & 0x20) { fprintf(fd, "Ov "); }
		if (flags & 0xe0)
			{ fprintf(fd, "\x1b[0m/ "); }
		else
			{ fprintf(fd, "\x1b[0m"); }
	}
	fprintf(fd, "Target v6 addr -> %s\n", pcstr_Tgt_addr);

	// -------------------------------------
	if (n_adv_opt_len == 0)
	{
		fprintf(fd, OPT "none\n\n");
		return;
	}

	const uint8_t* p_opt = pIcmp6_hdr_ui8 + 24;
	switch (*p_opt)
	{
	default:
		DBG_F(fd, "   option -> {}\n\n", *p_opt);
		return;
	}
}
