#include "my_basic.h"
#include <arpa/inet.h>
#include <tuple>
#include "KIPv6.h"

#include <format>
#define DBG_F( fd, fmt, ... )  fprintf(fd, (std::format(fmt, __VA_ARGS__)).c_str());

#include "main.h"
#include "KIf.h"

#define END_MARK "\x1b[1mEND\x1b[0m"

////////////////////////////////////////////////////////////////////////////
// KHdr_v6
//【要注意】 現在のコンストラクタは「VLAN の存在を想定していない」
KHdr_v6::KHdr_v6(const void* const pEth_hdr, const int bytes_packet_entire, const KIf_EPOLLIN* pIF)
	: mc_pEth_hdr{ (ether_header*)pEth_hdr }
	, mc_bytes_packet_entire{ bytes_packet_entire }
	, m_pV6_hdr{ (ip6_hdr*)((uint8_t*)pEth_hdr + 14) }  // 現時点では、VLAN に対応していない
	, mc_pIF{ pIF }
{
	// 14 -> イーサフレームヘッダ bytes / 40 -> v6 ヘッダ bytes
	if (bytes_packet_entire < 14 + 40)
		{ THROW("bytes_packet_entire < 14 + 40"); }
		
	// ---------------------------------------
	// 念のため、イーサフレームの ether_type をチェックしておく
	if (mc_pEth_hdr->ether_type != CEV_ntohs(ETH_P_IPV6))
	{
		std::string str;
		str.reserve(100);
		str = "unknown ether_type -> ";
		str = str + std::to_string(mc_pEth_hdr->ether_type);
		THROW(str);
	}

	// Hop by Hop のとき、Payload Length の値が 9126 となる場合があるため
	// Length 値のチェックはしないことにした。
#if false
	// ---------------------------------------
	// 念のため、Payload Length の値をチェックしておく
	if (const int payload_length = mc_pV6_hdr->ip6_plen
			; payload_length != bytes_packet_entire - (16 + 40))
	{
		this->Dump();
		
		std::string str;
		str.reserve(150);
		str = "IPv6 ヘッダの Payload Length の値に不整合を検知しました。\n";
		str = str + "   Payload Length -> " + std::to_string(payload_length)
				+ "\n   bytes_packet_entire -> " + std::to_string(bytes_packet_entire);
		THROW(str);
	}
#endif
	
	m_bytes_rem_next = bytes_packet_entire - 54;
}

// -------------------------------------------------------------------------
void KHdr_v6::Dump(FILE* const pf) const
{
	fprintf(pf, "+++ IPv6 ヘッダ dump\n   Version -> %d\n", (m_pV6_hdr->ip6_vfc >> 4));
	fprintf(pf, "   Payload Length -> %d\n", m_pV6_hdr->ip6_plen);
	fprintf(pf, "   Next Header -> %d\n", m_pV6_hdr->ip6_nxt);
	fprintf(pf, "   Hop Limit -> %d\n", m_pV6_hdr->ip6_hops);
	{
		const auto [pcstr, _1] = g_IF_Infos.Get_Name_by_v6_addr(this->Get_SRC_v6_addr());
		fprintf(pf, "   Src v6 addr -> %s\n", pcstr);
	}
	{
		const auto [pcstr, _1] = g_IF_Infos.Get_Name_by_v6_addr(this->Get_DST_v6_addr());
		fprintf(pf, "   Dst v6 addr -> %s\n", pcstr);
	}
}

// -------------------------------------------------------------------------
void KHdr_v6::Wrt_IF_signature(FILE* const pf)
{
	if (mb_wrtn_IF_signature == true) { return; }
	
	mc_pIF->Wrt_Signature(pf);
	mb_wrtn_IF_signature = true;
}


////////////////////////////////////////////////////////////////////////////
// KHop_v6
KHop_v6::KHop_v6(const KHdr_Next& blk_next)
	: KHdr_Cur{ blk_next }
	, mc_bytes_this_blk{ *(mc_pCur + 1) * 8 + 8 }
{
	if (mc_bytes_rem_cur < mc_bytes_this_blk)
		{ THROW("mc_bytes_cur < mc_bytes_this_blk"); }
}

// -------------------------------------------------------------------------
// ptr -> 拡張ヘッダの option の先頭部分（値５が格納されているアドレス）
static void S_Dump_Router_Alert(const uint8_t* const ptr, FILE* pf = stdout)
{
	if (*(ptr + 1) != 2)
		{ THROW("Hop by Hop -> Router Alert -> length != 2"); }
		
	switch (const int value = *(ptr + 2) * 256 + *(ptr + 3); value)
	{
	case 0:
		fprintf(pf, "   Router Alert -> MLD message\n\n");
		return;
		
	case 1:
		fprintf(pf, "   Router Alert -> RSVP message\n\n");
		return;
		
	case 2:
		fprintf(pf, "   Router Alert -> Active Networks message\n\n");
		return;
		
	default:
		fprintf(pf, "   Router Alert -> 不明な value -> %d\n\n", value);
	}
}

// -------------------------------------------------------------------------
void KHop_v6::Dump(FILE* const pf) const
{
	mc_pHdr_v6->Wrt_IF_signature(pf);
	fprintf(pf, "++ Hop by Hop\n");
	
	const uint8_t option_type = *(mc_pCur + 2);
	switch (option_type)
	{
	case 5:  // Router Alert Option
		if (mc_bytes_this_blk != 8)
			{ THROW("Hop by Hop -> Router Alert において、データサイズに不整合を検出しました。"); }
		S_Dump_Router_Alert(mc_pCur + 2);
		return;
	
	default:
		fprintf(pf, "   Hdr Ext Length -> %d\n", *(mc_pCur + 1));
		KHop_v6::Dump_TLV(option_type);
		fprintf(pf, "\n");
		break;
	}
}

// -------------------------------------------------------------------------
void KHop_v6::Dump_TLV(const uint8_t option_type, FILE* pf)
{
	fprintf(pf, "   act -> %02b\n", (option_type >> 6));
	fprintf(pf, "   chg -> %01b\n", ((option_type >> 5) & 1));
	fprintf(pf, "   type raw value -> 0x%02x\n", option_type);
}


////////////////////////////////////////////////////////////////////////////
// KIcmp_v6
// デバッグ用
KIcmp_v6::KIcmp_v6(const KHdr_Next& hdr_next)
	: KHdr_Cur{ hdr_next }
{
	switch (const int type = *mc_pCur; type)
	{
	case 143:  // Version 2 Multicast Listener Report RFC3810
		// https://datatracker.ietf.org/doc/html/rfc3810
		this->Dump_v2_Multicast_Listener_Report();
		printf("\n");
		return;
		
	default:
		mc_pHdr_v6->Wrt_IF_signature();
		printf("++ ICMPv6 : 不明な type -> %d\n", type);
		printf("   ICMPv6 bytes -> %d\n\n", mc_bytes_rem_cur);
		break;
	}
}

// -------------------------------------------------------------------------
void KIcmp_v6::Dump(FILE* pf) const
{
	mc_pHdr_v6->Wrt_IF_signature();
	
//	fprintf(pf, "   type -> %d\n", *(mc_pCur));
	fprintf(pf, "   bytes_rem_cur -> %d\n\n", mc_bytes_rem_cur);
}

// -------------------------------------------------------------------------
static const uint8_t* S_Dump_Mcast_Address_Record(const uint8_t* ptr, FILE* pf = stdout)
{
	fprintf(pf, "      Record Type -> %d\n", *ptr++);
	const int aux_data_len = *ptr++;
	fprintf(pf, "      Aux Data Len -> %d\n", aux_data_len);
	const int num_srcs = *ptr * 256 + *(ptr + 1);
	fprintf(pf, "      Number of Sources -> %d\n", num_srcs);
	ptr += 2;
	
	const auto [pcstr_multicast_addr, _0] = g_IF_Infos.Get_Name_by_v6_addr(ptr);
	fprintf(pf, "      Multicast addr -> %s\n", pcstr_multicast_addr);
	
	return ptr + (16 + num_srcs * 16 + aux_data_len);
}

// -------------------------------------------------------------------------
void KIcmp_v6::Dump_v2_Multicast_Listener_Report(FILE* pf) const
{
	const uint8_t* const pTmnt = mc_pCur + mc_bytes_rem_cur;
	
	mc_pHdr_v6->Wrt_IF_signature();
	// RFC 3810
	fprintf(pf, "++ ICMPv6 : v2 Multicast Listener Report\n");
	const uint16_t num_records = Cx_ntohs(*(uint16_t*)(mc_pCur + 6));
	fprintf(pf, "   Nr of Mcast Address Records -> %d\n", num_records);
	
	const uint8_t* ptr = mc_pCur + 8;
	ptr = S_Dump_Mcast_Address_Record(ptr);
	
	if (ptr == pTmnt) { return; }
	
	// -------------------------------------
	fprintf(pf, "!!! UNREAD bytes -> %d\n", int(pTmnt - ptr));
}


////////////////////////////////////////////////////////////////////////////
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
#if true
	DBG_F(fd, "   v6 payload -> {} B / ip6_nxt -> {}\n", payload_len, mc_pIp6_hdr->ip6_nxt);
#endif

	switch(mc_pIp6_hdr->ip6_nxt)
	{
//	case IPPROTO_HOPOPTS:  // 0
	case IPPROTO_ICMPV6:  // 58
		KIcmp_v6_{ this, ((uint8_t*)mc_pIp6_hdr) + 40 }.DBG_ShowSelf(payload_len, fd);
		return;

	case IPPROTO_TCP:  // 6
		fprintf(fd, "   TCP\n\n");
		return;

	case IPPROTO_UDP:  // 17
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
// KIcmp_v6_
// KIcmp_v6_::DBG_Show

#define OPT WHT_B("   opt : ")

void KIcmp_v6_::DBG_ShowSelf(const int payload_len, FILE* fd) const
{
#if false
	DBG_F(fd, "   icmp6_type -> {}\n", mc_pIcmp6_hdr->icmp6_type);
#endif

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
// KIcmp_v6_::DBG_Show_N_Sol
void KIcmp_v6_::DBG_Show_N_Sol(const int option_len, FILE* fd) const
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
// KIcmp_v6_::DBG_Show_N_Sol_1_2
// 1 -> Source L2 Address / 2 -> Target L2 Address
void KIcmp_v6_::DBG_Show_N_Sol_1_2(const uint8_t* const p_opt, const int opt_len, FILE* fd) const
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
// KIcmp_v6_::DBG_Show_N_Adv
void KIcmp_v6_::DBG_Show_N_Adv(int n_adv_opt_len, FILE* fd) const
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
