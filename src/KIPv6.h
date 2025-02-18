#pragma once
#include	<netinet/if_ether.h>
#include	<netinet/ip6.h>
#include	<netinet/icmp6.h>

#include "KException.h"

// --------------------------------------------------------------------
void G_DBG_Show_Eth_hdr(const void* pEth_hdr, FILE* fd = stdout);



struct KHdr_v6;

// --------------------------------------------------------------------
struct KHdr_Next
{
	// 次のヘッダが無い場合、-1 となる
	int m_Next_Header;

	KHdr_v6* m_pHdr_v6;
	const uint8_t* m_pNext;
	// 次のヘッダが無い場合、0 となるはず
	int m_bytes_rem_next;
};

// --------------------------------------------------------------------
struct KHdr_Cur
{
	KHdr_Cur(const KHdr_Next& next)
		: mc_pHdr_v6{ next.m_pHdr_v6 }
		, mc_pCur{ next.m_pNext }
		, mc_bytes_rem_cur{ next.m_bytes_rem_next } {}
		
	KHdr_v6* const mc_pHdr_v6;
	const uint8_t* const mc_pCur;
	const int mc_bytes_rem_cur;  // 自分のブロック以降の全ての bytes
};


// --------------------------------------------------------------------
class KIf_EPOLLIN;

struct KHdr_v6
{
	// イーサフレームヘッダのアドレスを渡す（プリアンブルは除く）
	// bytes_packet_entire : イーサフレームヘッダを含む、パケット全体の bytes
	// pIF : デバッグ用に、シグネチャを表示するため
	KHdr_v6(const void* const pEth_hdr, int bytes_packet_entire, const KIf_EPOLLIN* pIF);
	
	//【要注意】現在は、VLAN の存在を想定していない
	KHdr_Next Get_Hdr_Next()
		{ return { m_pV6_hdr->ip6_nxt, this, (uint8_t*)m_pV6_hdr + 40, m_bytes_rem_next }; }
	
	// 以下はデバッグ用に値を保存している
	const ether_header* const mc_pEth_hdr;
	const int mc_bytes_packet_entire;
	
	// ----------------------------
	void Dump(FILE* pf = stdout) const;
	const uint8_t* Get_SRC_v6_addr() const { return ((uint8_t*)m_pV6_hdr) + 8; }
	const uint8_t* Get_DST_v6_addr() const { return ((uint8_t*)m_pV6_hdr) + 24; }
	
	void Show_IF_signature();

private:
	// 今後の VLAN 対応も考慮して、mc_pV6_hdr の値を独立して持たせている
	const ip6_hdr* const m_pV6_hdr;
	int m_bytes_rem_next;
	
	// デバッグ用
	const KIf_EPOLLIN* const mc_pIF;
	// IF signature は一度しか表示しないようにしている
	bool mb_showed_IF_signature = false;
};


// --------------------------------------------------------------------
struct KHop_v6 : public KHdr_Cur
{
	KHop_v6(const KHdr_Next& hdr_next);
	KHdr_Next Get_Hdr_Next() const
		{ return { *mc_pCur, mc_pHdr_v6, mc_pCur + mc_bytes_this_blk, mc_bytes_rem_cur - mc_bytes_this_blk }; }
	
	uint8_t Get_NextHeader() const { return *mc_pCur; }
	// 最初の ８bytes を含まない、８bytes 単位で表されたこのヘッダのサイズ。
	int Get_Hdr_Ext_Length() const { return *(mc_pCur + 1); }
	
	const int mc_bytes_this_blk;

	// ----------------------------
	void Dump(FILE* pf = stdout) const;
	// RFC2460
	static void Dump_TLV(const uint8_t* p_option, FILE* pf = stdout);
};


// --------------------------------------------------------------------
void Proc_Icmp_v6();

struct KIcmp_v6 : public KHdr_Cur
{
	KIcmp_v6(const KHdr_Next& blk_next);
	KHdr_Next Get_Blk_Next() const { return { -1, 0, 0, 0 }; }

	// ----------------------------
	void Dump(FILE* pf = stdout) const;
	
private:
	int m_bytes_this_blk = 0;
};


// --------------------------------------------------------------------
// KIp_v6
class KIp_v6
{
	friend class KIcmp_v6_;
public:
	KIp_v6(const void* const pEth_hdr, const void* const pIp6_hdr)
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
class KIcmp_v6_
{
public:
	KIcmp_v6_(const KIp_v6* pIpv6, const void* const pIcmp_v6)
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

