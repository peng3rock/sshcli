/*

 Copyright (c) 2006-2017 Microsemi Corporation "Microsemi". All Rights Reserved.

 Unpublished rights reserved under the copyright laws of the United States of
 America, other countries and international treaties. Permission to use, copy,
 store and modify, the software and its source code is granted but only in
 connection with products utilizing the Microsemi switch and PHY products.
 Permission is also granted for you to integrate into other products, disclose,
 transmit and distribute the software only in an absolute machine readable
 format (e.g. HEX file) and only in or with products utilizing the Microsemi
 switch and PHY products.  The source code of the software may not be
 disclosed, transmitted or distributed without the prior written permission of
 Microsemi.

 This copyright notice must appear in any copy, modification, disclosure,
 transmission or distribution of the software.  Microsemi retains all
 ownership, copyright, trade secret and proprietary rights in the software and
 its source code, including all modifications thereto.

 THIS SOFTWARE HAS BEEN PROVIDED "AS IS". MICROSEMI HEREBY DISCLAIMS ALL
 WARRANTIES OF ANY KIND WITH RESPECT TO THE SOFTWARE, WHETHER SUCH WARRANTIES
 ARE EXPRESS, IMPLIED, STATUTORY OR OTHERWISE INCLUDING, WITHOUT LIMITATION,
 WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR USE OR PURPOSE AND
 NON-INFRINGEMENT.


*/

#ifndef _VTSS_CLI_API_H_
#define _VTSS_CLI_API_H_


#include "main.h"       /* For init_cmd_t */
#include <time.h>       /* For time_t */
#ifndef _STDARG_H
#include <stdarg.h>     /* For va_list */
#endif

#ifdef VTSS_SW_OPTION_AUTH
#include "vtss_auth_api.h"  /* For vtss_auth_agent_t */
#endif /* VTSS_SW_OPTION_AUTH */

#ifdef VTSS_SW_OPTION_ICLI
#include "sysutil_api.h"
#include "misc_api.h"
#endif

#include "vtss_os_wrapper.h"

/* The most simple character codes */
#define CTLC 0x03
#define CTLD 0x04
#define BEL  0x07
#define CTLH 0x08
#define BS   CTLH
#define LF   0x0a
#define CR   0x0d
#define ESC  0x1b
#define DEL  0x7f

#define CLI_DEL_KEY_LINUX   CTLD
#define CLI_BS_KEY_LINUX    DEL
#define CLI_DEL_KEY_WINDOWS DEL
#define CLI_BS_KEY_WINDOWS  CTLH

#define CURSOR_RIGHT         0x43 /* C */
#define CURSOR_LEFT          0x44 /* D */
#define CURSOR_DELETE_TO_EOL 0x4B /* K */


#ifdef VTSS_SW_OPTION_L3
enum node_type
{
  AUTH_NODE,			/* Authentication mode of vty interface. */
  RESTRICTED_NODE,		/* Restricted view mode */
  VIEW_NODE,			/* View node. Default mode of vty interface. */
  AUTH_ENABLE_NODE,		/* Authentication mode for change enable. */
  ENABLE_NODE,			/* Enable node. */
  CONFIG_NODE,			/* Config node. Default mode of config file. */
  VRF_NODE,			/* VRF node. */
  SERVICE_NODE, 		/* Service node. */
  DEBUG_NODE,			/* Debug node. */
  AAA_NODE,			/* AAA node. */
  KEYCHAIN_NODE,		/* Key-chain node. */
  KEYCHAIN_KEY_NODE,		/* Key-chain key node. */
  ZEBRA_NODE,			/* zebra connection node. */
  TABLE_NODE,			/* rtm_table selection node. */
  RIP_NODE,			/* RIP protocol mode node. */
  RIPNG_NODE,			/* RIPng protocol mode node. */
  BABEL_NODE,			/* Babel protocol mode node. */
  BGP_NODE,			/* BGP protocol mode which includes BGP4+ */
  BGP_VPNV4_NODE,		/* BGP MPLS-VPN PE exchange. */
  BGP_VPNV6_NODE,		/* BGP MPLS-VPN PE exchange. */
  BGP_IPV4_NODE,		/* BGP IPv4 unicast address family.  */
  BGP_IPV4M_NODE,		/* BGP IPv4 multicast address family.  */
  BGP_IPV6_NODE,		/* BGP IPv6 address family */
  BGP_IPV6M_NODE,		/* BGP IPv6 multicast address family. */
  BGP_ENCAP_NODE,		/* BGP ENCAP SAFI */
  BGP_ENCAPV6_NODE,		/* BGP ENCAP SAFI */
  OSPF_NODE,			/* OSPF protocol mode */
  OSPF6_NODE,			/* OSPF protocol for IPv6 mode */
  ISIS_NODE,			/* ISIS protocol mode */
  PIM_NODE,			/* PIM protocol mode */
  MASC_NODE,			/* MASC for multicast.  */
  IRDP_NODE,			/* ICMP Router Discovery Protocol mode. */
  INTERFACE_NODE,		/* Interface mode node. */
  IP_NODE,			/* Static ip route node. */
  ACCESS_NODE,			/* Access list node. */
  PREFIX_NODE,			/* Prefix list node. */
  ACCESS_IPV6_NODE,		/* Access list node. */
  PREFIX_IPV6_NODE,		/* Prefix list node. */
  AS_LIST_NODE,			/* AS list node. */
  COMMUNITY_LIST_NODE,		/* Community list node. */
  RMAP_NODE,			/* Route map node. */
  SMUX_NODE,			/* SNMP configuration node. */
  DUMP_NODE,			/* Packet dump node. */
  FORWARDING_NODE,		/* IP forwarding node. */
  PROTOCOL_NODE,                /* protocol filtering node */
  VTY_NODE,			/* Vty node. */
};
#endif /* VTSS_SW_OPTION_L3 */


#ifdef __cplusplus
extern "C" {
#endif

//
// Definition of CLI rc errors.
// CLI uses also VTSS_OK, VTSS_UNSPECIFIED_ERROR and VTSS_INCOMPLETE
//
enum {
    CLI_ERROR_IO_TIMEOUT = MODULE_ERROR_START(VTSS_MODULE_ID_CLI),
};

#ifdef VTSS_SW_OPTION_ICLI
typedef enum {
    CLI_WAY_CONSOLE,
    CLI_WAY_TELNET,
    CLI_WAY_SSH,
} cli_way_t;
#endif

/****************************************************************************/
/*  CLI IO layer                                                            */
/****************************************************************************/
#define CLI_PASSWD_CHAR_TIMEOUT     (30 * 1000)
#define CLI_COMMAND_CHAR_TIMEOUT    (10 * 60 * 1000)
#define CLI_NO_CHAR_TIMEOUT         (-1)

/* The minimum timeout is 1 second, so this can not be larger than 1 second */
#define CLI_GETCH_WAKEUP            (1000) /* getch wake up interval in mS */

typedef struct cli_iolayer {
    void (*cli_init)(struct cli_iolayer *pIO);
    int  (*cli_getch)(struct cli_iolayer *pIO, int timeout, char *ch); /* timeout in mS */
    int  (*cli_vprintf)(struct cli_iolayer *pIO, const char *fmt, va_list ap);
    void (*cli_putchar)(struct cli_iolayer *pIO, char ch);
    void (*cli_puts)(struct cli_iolayer *pIO, const char *str);
    void (*cli_flush)(struct cli_iolayer *pIO);
    void (*cli_close)(struct cli_iolayer *pIO);
    BOOL (*cli_login)(struct cli_iolayer *pIO);

    int fd;

    int char_timeout;  /* vCLI only: cli_getch() timeout in mS during normal command parsing */

    BOOL bIOerr;
    BOOL bEcho;

    /*
     * The cDEL and cBS are used to discern BS and DEL keys on different connections.
     * Here's how different OSs and clients map the keys (standard-wise):
     *
     * Client,   OS      | BS-key | DEL-key | Ctrl+D | Ctrl+H
     * ------------------|--------|---------|--------|--------
     * TeraTerm, Windows |   0x08 |    0x7F |   0x04 |   0x08
     * Telnet,   Windows |   0x08 |    0x7F |   0x04 |   0x08
     * Telnet,   Linux   |   0x7F |    0x04 |   0x04 |   0x08
     *
     * Since there's no way to determine the client/OS, we cannot determine
     * what to do (backspace or delete) if we receive 0x7F. Therefore,
     * cli_telnet.c assumes the Telnet/Linux, whereas cli.c assumes the
     * TeraTerm/Windows combination of keys. The code is made such that
     * it always map CTRL+D and CTRL+H as DEL and BS, respectively, so
     * if everything else fails, use these combinations.
     */
    char cDEL;
    char cBS;
    u8   priv_lvl;
    BOOL authenticated;
#ifdef VTSS_SW_OPTION_ICLI
    u32 icli_session_id;
    u32 session_way;
#endif /* VTSS_SW_OPTION_ICLI */

    char           username[VTSS_SYS_USERNAME_LEN];
    mesa_ip_addr_t client_ip;   /* IP address of the client. Only used in Telnet and SSH */
    u16            client_port; /* TCP port of the client. Only used in Telnet and SSH */
#ifdef VTSS_SW_OPTION_AUTH
    vtss_appl_auth_agent_t agent;    /* Agent that owns this cli session */
    u16                    agent_id; /* Unique agent ID. Used for accounting when non zero */
#endif /* VTSS_SW_OPTION_AUTH */
} cli_iolayer_t;

/* Legacy cli_io_t. Used to also contain old CLI command structure */
typedef struct cli_io {
    cli_iolayer_t  io;
} cli_io_t;

/****************************************************************************/
/*  CLI IO layer public interface                                           */
/****************************************************************************/

/* Assign a user defined iolayer to current thread */
void cli_set_io_handle(cli_iolayer_t *pIO);

/* Get iolayer for current thread */
cli_iolayer_t *cli_get_io_handle(void);

/* Get iolayer for serial thread (console) */
cli_iolayer_t *cli_get_serial_io_handle(void);

/*
 * cli_io_getkey() is a nonblocking poll for a specific keyboard key.
 * If a specific (or any) key is pressed since the last call of cli_io_getkey()
 * or cli_io_getch() the key is returned. Otherwise NUL is returned.
 * Use ch = 0 for any key and e.g. ch = 3 (or 0x03 or '\003') for ctrl-c.
 */
char cli_io_getkey(cli_iolayer_t *pIO, char ch);

/*
 * cli_io_getch() get a character from a file descriptor (or socket).
 * It is used by console (serial), Telnet and SSH.
 *
 * If timeout = 0 the fd is polled for a character.
 * If timeout > 0 cli_io_getch() times out after 'timeout' mS if no character is received.
 * If timeout < 0 cli_io_getch() waits forever.
 * Returns VTSS_OK if a character is received, CLI_ERROR_IO_TIMEOUT if timeout and
 * VTSS_UNSPECIFIED_ERROR if an error has occured.
 */
mesa_rc cli_io_getch(cli_iolayer_t *pIO, int timeout, char *ch);

#ifdef VTSS_SW_OPTION_AUTH
/* Generic login dialog used by serial, Telnet and SSH */
BOOL cli_io_login(cli_iolayer_t *pIO, vtss_appl_auth_agent_t agent, int timeout);
#endif /* VTSS_SW_OPTION_AUTH */

int cli_io_printf(cli_iolayer_t *pIO, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));

/* The following uses iolayer in current thread */
#define CPRINTF(fmt, ...)   cli_printf(fmt, ## __VA_ARGS__)
int  cli_printf(const char *fmt, ...) __attribute__ ((format (__printf__, 1, 2)));
void cli_puts(const char *str);
void cli_putchar(char ch);
void cli_flush(void);
char cli_getkey(char ch);
int cli_fd(void);

/* Generic CLI thread used by serial, Telnet and SSH */
void cli_thread(vtss_addrword_t data); /* CLI task entry */

/* Close the serial CLI session and force the user to login again */
void cli_serial_close(void);

/* Initialize Telnet CLI */
void cli_telnet_start(void);

/* Close all active Telnet CLI sessions */
void cli_telnet_close(void);

/* Initialize CLI module */
mesa_rc cli_io_init(vtss_init_data_t *data);

cli_io_t *vtss_appl_cli_console_io_get(void);

#define TELNET_SECURITY_SUPPORTED
#ifdef TELNET_SECURITY_SUPPORTED
/* Set TELNET security mode. When security mode is enabled,
   we should use the SSH instead of telnet */
void cli_io_telnet_set_security_mode(mesa_bool_t security_mode);

mesa_bool_t cli_io_telnet_get_security_mode();

#endif /* TELNET_SECURITY_SUPPORTED */
void newcli_showrun_set();
void newcli_showrundef_set();
void newcli_showrun_set_tl();
void newcli_showrundef_set_tl();
int  newcli_sessionid_set(ULONG sessionid, int value);

bool telnet_module_enabled();
bool cli_module_enabled();
extern cli_iolayer_t * get_pIO_for_print(u32 session_id);
extern void set_pIO_for_print(u32 session_id , cli_iolayer_t *pIo);
extern void unset_pIO_for_print(u32 session_id);
#ifdef __cplusplus
}
#endif

#endif /* _VTSS_CLI_API_H_ */

/****************************************************************************/
/*                                                                          */
/*  End of file.                                                            */
/*                                                                          */
/****************************************************************************/
