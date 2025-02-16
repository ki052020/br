#include	<stdio.h>
#include	<unistd.h>
#include <sys/epoll.h>

#include "my_basic.h"
#include "KException.h"
#include "KSocket.h"
#include "KIPv6.h"
#include "KIf.h"

#include "main.h"

// ---------------------------------------------------------------
#define MSEC_epoll_timeout 1000
#define MAX_PCS_epoll_events 10

// ---------------------------------------------------------------
int main(int argc, const char* argv[])
{
	// ---------------------------------
	if (argc != 2)
	{
		printf("argc != 2\n\n");
		return 0;
	}

	// ---------------------------------
	uint8_t buf[65535];
	int bytes_read = 0;

	try
	{
		// ---------------------
		// fd_epoll
		struct AutoCloser_fd_epoll {
			AutoCloser_fd_epoll() { if (mc_fd_epoll < 0) { THROW("mc_fd_epoll < 0"); } }
			~AutoCloser_fd_epoll() { close(mc_fd_epoll); }
			operator int() { return mc_fd_epoll; }
			
			const int mc_fd_epoll = epoll_create1(0);
		} fd_epoll;
		
		// ---------------------
		// p_ifaddrs_list
		struct AutoCloser_ifaddrs {
			AutoCloser_ifaddrs() {
				if (getifaddrs(&m_p_ifaddrs) < 0) { THROW("getifaddrs(&m_p_ifaddrs) < 0"); }
			}
			~AutoCloser_ifaddrs() { freeifaddrs(m_p_ifaddrs); }
			operator const ifaddrs*() { return m_p_ifaddrs; }
		private:
			ifaddrs* m_p_ifaddrs = NULL;
		} p_ifaddrs_list;

		// ---------------------------------
		// if_Wan の生成
		KIf_WAN if_Wan = [&p_ifaddrs_list, &fd_epoll]()
			{
				KIF_Info if_info{ "enp2s0", p_ifaddrs_list };
				
			   // protocol = ETH_P_ALL | ETH_P_IP | ETH_P_IPV6
				// ETH_P_ALL を指定すると、送信時のパケットもキャプチャできるようになる
				return KIf_WAN{ if_info, ETH_P_IPV6, true, fd_epoll };
			}();		
		if_Wan.Set_NickName(MGT_B("if_Wan"));
		g_IF_Infos.push_back(&if_Wan);
		
		// ---------------------------------
		// if_Lan の生成
		//【注意】link up していない interface を KIF オブジェクトにすると、
		// epoll_wait() で「EPOLLERR」が生成される
#if false
		KIf_LAN if_Lan{
			KIF_Info{ "enx7cc2c63c49d0", p_ifaddrs_list }
			, ETH_P_IPV6, true, fd_epoll
		};
#else
		KSocket if_Lan{ KIF_Info{"enx7cc2c63c49d0", p_ifaddrs_list}, ETH_P_IPV6, true };
#endif

		if_Lan.Set_NickName(GRN_B("if_Lan"));
		g_IF_Infos.push_back(&if_Lan);

		// ---------------------------------
		// ONU 情報を追加
		KIF_Info ONU_if_info(YLW_B("HGW"));
		{
			ONU_if_info.Set_MacAddr(be64toh(0x5852'8a77'6312'0000));
			const uint64_t intf_addr = ONU_if_info.Add_v6_addr_by_cstr(argv[1]);

			uint64_t onu_v6_addr[2];
			onu_v6_addr[0] = be64toh(0xfe80'0000'0000'0000);
			onu_v6_addr[1] =intf_addr;
			ONU_if_info.Add_v6_addr_by_bin2(onu_v6_addr);

			g_IF_Infos.push_back(&ONU_if_info);
		}
		// ---------------------------------
		// 宅内ルーター情報を追加
		KIF_Info Rt_0_if_info(YLW_B("Router_0"));
		{
			Rt_0_if_info.Set_MacAddr(be64toh(0x94c6'910c'2133'0000));

			uint64_t rt_0_v6_addr[2];
			rt_0_v6_addr[0] = be64toh(0xfe80'0000'0000'0000);
			rt_0_v6_addr[1] = be64toh(0x96c6'91ff'fe0c'2133);
			Rt_0_if_info.Add_v6_addr_by_bin2(rt_0_v6_addr);

			g_IF_Infos.push_back(&Rt_0_if_info);
		}



#if MY_DEBUG
		// ---------------------------------
		// デバッグ用表示
		g_IF_Infos.DBG_ShowSelf();
#endif



		// イベントループ
		epoll_event ary_events[MAX_PCS_epoll_events];
//		for (;;)		
		for (int cnt = 10; cnt > 0;)
		{
			// --------------------------------------
			// epoll_wait() 外でシグナルが発せられたときのことを考慮して、timeout を設定している
			const int retval_epoll_wait
				= epoll_wait(
					fd_epoll, ary_events, MAX_PCS_epoll_events
					, MSEC_epoll_timeout	// timeout（ミリ秒）
				);
/*
			if (IsShuttingDown() == true)
			{
				break;  // exit epoll event loop
			}
*/
			if (retval_epoll_wait == 0) { continue; }  // timeout 時の処理
		
			if (retval_epoll_wait < 0)
			{
				if (errno == EINTR)
				{
					printf("+++ errno == EINTR を検知しました。\n\n");
					break;  // exit epoll event loop
				}

				THROW("retval_epoll_wait < 0");
			}
		
			// --------------------------------------
			const epoll_event* pary_events = ary_events;
			for (int i = retval_epoll_wait; i > 0; pary_events++, i--)
			{
				KIf_EPOLLIN* const p_if_EPOLLIN = (KIf_EPOLLIN*)pary_events->data.ptr;
				if (p_if_EPOLLIN->PreProc_EPOLLIN(pary_events->events) == 0)
					{ cnt--; }
				else
					{ THROW("PreProc_EPOLLIN() が不明な値を返しました。"); }
			}
		}
	}
	catch (const KException& ex)
	{
		ex.DBG_Show();
		DBG_dump(buf, bytes_read);
	}

	return 0;
}

// ---------------------------------------------------------------
int G_AnalyzePacket(const uint8_t* pbuf, int bytes)
{
	if (const ether_header* peh = (const ether_header*)pbuf;
		peh->ether_type != CEV_ntohs(ETH_P_IPV6))
	{
		return -1;
#if false
		// VLAN タグ付きの場合も、現在はエラーとしている
		THROW(std::format("catch unknown ether_type -> {:#04x}"
			, ntohs(peh->ether_type)));
#endif
	}

	// 現時点では、vlan タグがないものとして想定している
	KIp_v6 v6_pckt{ pbuf, pbuf + 14 };
	v6_pckt.DBG_ShowSelf();

	return 0;
}


//////////////////////////////////////////////////////////////////
// GIF_Infos
void GIF_Infos::DBG_ShowSelf(FILE* fd) const
{
	for (const KIF_Info* p_if_info : m_vec_IF_Infos)
	{
		p_if_info->DBG_ShowSelf(fd);
	}
}

// ---------------------------------------------------------------
// GIF_Infos::Get_Name_by_v6_addr
std::pair<const char*, bool> GIF_Infos::Get_Name_by_v6_addr(const void* p_v6_addr) const
{
	for (const KIF_Info* const p_if_info : m_vec_IF_Infos)
	{
		if (p_if_info->Contains_v6_addr((const uint64_t*)p_v6_addr))
			{ return { p_if_info->Get_Name().c_str(), true }; }
	}

	return { KIF_Info::CStr_frm_v6_addr((const uint8_t*)p_v6_addr), false };
}

// ---------------------------------------------------------------
// GIF_Infos::Get_Name_by_mac_addr
std::pair<const char*, bool> GIF_Infos::Get_Name_by_mac_addr(uint64_t ui64_mac_addr) const
{
	ui64_mac_addr &= 0xffff'ffff'ffff;

	for (const KIF_Info* const p_if_info : m_vec_IF_Infos)
	{
		if (p_if_info->mac_addr() == ui64_mac_addr)
			{ return { p_if_info->Get_Name().c_str(), true }; }
	}

	return { KIF_Info::CStr_frm_mac_addr(ui64_mac_addr), false };
}
