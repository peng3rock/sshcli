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
#include "cli_io_api.h"  /* For cli_iolayer_t */
#include "critd_api.h"
#include "cli_trace_def.h"
#include "mgmt_api.h"
#include "sysutil_api.h" /* For VTSS_SYS_USERNAME_LEN */
#include <sys/param.h>
#include <fcntl.h>
#include "msg_api.h"     /* For msg_wait() */
#include <sys/socket.h>
#include "main_conf.hxx"
#include "vtss_icli_session.h"
#include "icli_os.h"
#include "vtss_users_api.h"



#ifdef VTSS_SW_OPTION_CONSOLE
#error CLI module is not compatible with CONSOLE module!
#endif /* VTSS_SW_OPTION_CONSOLE */

#ifdef VTSS_SW_OPTION_ICLI

#include "icli_api.h"

/* Verify some constants until iCLI uses common header files */
#if ICLI_USERNAME_MAX_LEN != VTSS_SYS_USERNAME_LEN
#error ICLI_USERNAME_MAX_LEN != VTSS_SYS_USERNAME_LEN
#endif
#if ICLI_PASSWORD_MAX_LEN != VTSS_SYS_PASSWD_LEN
#error ICLI_PASSWORD_MAX_LEN != VTSS_SYS_PASSWD_LEN
#endif
#endif /* VTSS_SW_OPTION_ICLI */

#ifdef VTSS_SW_OPTION_ICFG /* CP, 06/24/2013 13:57, Bugzilla#12076 - slient upgrade */
#include "icfg_api.h"
#endif



vtss_tick_count_t user_psw_modify_time = VTSS_USERS_PSW_MODIFY_TIME;


/* Global variable struct */
typedef struct {
    vtss_handle_t thread_handle;
    vtss_thread_t thread_block;
    u32           ioindex;  /* Index for the per thread data */
    critd_t       crit;     /* Shared data critical region protection */
} cli_global_t;

static cli_global_t cli;

#if !defined(CLI_TELNET_MAX_CLIENT)
#define CLI_TELNET_MAX_CLIENT       4
#endif
static vtss_handle_t    Newcli_thread_handle;
static vtss_thread_t    Newcli_thread_block;
static vtss_flag_t        Newcli_Notice_Flag;
int                    Newcli_sessionid[CLI_TELNET_MAX_CLIENT];
extern BOOL board_support_security();

#if (VTSS_TRACE_ENABLED)
static vtss_trace_reg_t trace_reg = {
    VTSS_TRACE_MODULE_ID, "cli", "Command line interface"
};

static vtss_trace_grp_t trace_grps[TRACE_GRP_CNT] = {
    /* VTSS_TRACE_GRP_DEFAULT */ {
        "default",
        "Default",
        VTSS_TRACE_LVL_WARNING,
        VTSS_TRACE_FLAGS_TIMESTAMP
    },
    /* VTSS_TRACE_GRP_TELNET */ {
        "telnet",
        "Telnet",
        VTSS_TRACE_LVL_WARNING,
        VTSS_TRACE_FLAGS_TIMESTAMP
    },
    /* VTSS_TRACE_GRP_POE */ {
        "poe",
        "PoE",
        VTSS_TRACE_LVL_ERROR,
        VTSS_TRACE_FLAGS_NONE
    },

    /* VTSS_TRACE_GRP_LLDP */ {
        "lldp",
        "LLDP",
        VTSS_TRACE_LVL_ERROR,
        VTSS_TRACE_FLAGS_NONE
    },
    /* VTSS_TRACE_GRP_CRIT */ {
        "crit",
        "Critical regions",
        VTSS_TRACE_LVL_ERROR,
        VTSS_TRACE_FLAGS_TIMESTAMP
    },
};
#define CLI_CRIT_ENTER() critd_enter(&cli.crit, VTSS_TRACE_GRP_CRIT, VTSS_TRACE_LVL_NOISE, __FILE__, __LINE__)
#define CLI_CRIT_EXIT()  critd_exit( &cli.crit, VTSS_TRACE_GRP_CRIT, VTSS_TRACE_LVL_NOISE, __FILE__, __LINE__)
#else
#define CLI_CRIT_ENTER() critd_enter(&cli.crit)
#define CLI_CRIT_EXIT()  critd_exit( &cli.crit)
#endif /* VTSS_TRACE_ENABLED */

extern BOOL board_support_complexpwd(void);

/****************************************************************************/
/* iCLI generalization functions                                            */
/****************************************************************************/
static void cli_banner_motd(cli_iolayer_t *pIO)
{
#ifdef VTSS_SW_OPTION_ICLI
    icli_session_data_t data;
    data.session_id = pIO->icli_session_id;
    if (icli_session_data_get(&data) == VTSS_OK) {
        if (data.b_motd_banner) {
            char banner[ICLI_BANNER_MAX_LEN + 1];
            if (icli_banner_motd_get(banner) == VTSS_OK) {
                if (banner[0]) {
                    cli_putchar('\n');
                    cli_puts(banner);
                    cli_putchar('\n');
                }
            } else {
                T_E("Unable to get motd banner");
            }
        }
    } else {
        T_E("Unable to get iCLI session data");
    }
#endif /* VTSS_SW_OPTION_ICLI */
}

static void cli_pre_login(cli_iolayer_t *pIO)
{
#ifdef VTSS_SW_OPTION_ICLI
    char ch;
    cli_puts("\nPress ENTER to get started");
    while (cli_io_getkey(pIO, 0)) {
        /* Empty input buffer */
    }
    while (pIO->cli_getch(pIO, CLI_NO_CHAR_TIMEOUT, &ch) == VTSS_OK) {
        if (ch == CR) {
            cli_putchar('\n');
            break;
        }
    }
#endif /* VTSS_SW_OPTION_ICLI */
}

#ifdef VTSS_SW_OPTION_AUTH
static void cli_banner_login(cli_iolayer_t *pIO, vtss_appl_auth_agent_t agent)
{
#ifdef VTSS_SW_OPTION_ICLI
    char banner[ICLI_BANNER_MAX_LEN + 1];
    if (agent == VTSS_APPL_AUTH_AGENT_CONSOLE) {
        cli_pre_login(pIO);
    }
    if (icli_banner_login_get(banner) == VTSS_OK) {
        if (banner[0]) {
            cli_putchar('\n');
            cli_puts(banner);
            cli_putchar('\n');
        }
    } else {
        T_E("Unable to get login banner");
    }
#endif /* VTSS_SW_OPTION_ICLI */
}
#endif /* VTSS_SW_OPTION_AUTH */

static void cli_banner_exec(cli_iolayer_t *pIO)
{
#ifdef VTSS_SW_OPTION_ICLI
    icli_session_data_t data;
    data.session_id = pIO->icli_session_id;
    if (icli_session_data_get(&data) == VTSS_OK) {
        if (data.b_exec_banner) {
            char banner[ICLI_BANNER_MAX_LEN + 1];
            if (icli_banner_exec_get(banner) == VTSS_OK) {
                if (banner[0]) {
                    cli_putchar('\n');
                    cli_puts(banner);
                    cli_putchar('\n');
                }
            } else {
                T_E("Unable to get exec banner");
            }
        }
    } else {
        T_E("Unable to get iCLI session data");
    }
#endif /* VTSS_SW_OPTION_ICLI */
}

static void cli_parser_loop(cli_iolayer_t *pIO)
{
    mesa_rc rc;

    while (!pIO->bIOerr) {
#ifdef VTSS_SW_OPTION_ICLI
        if ((rc = icli_session_engine(pIO->icli_session_id)) != ICLI_RC_OK) {
            T_I("iCLI session terminated (%d)", rc);
            break;
        }

        T_D("iCLI session continue");
#endif /* VTSS_SW_OPTION_ICLI */
    }
}

#ifdef VTSS_SW_OPTION_ICLI
/*
    get session input by char

    INPUT
        app_id  : application ID
        timeout : in millisecond
                  = 0 - no wait
                  < 0 - forever

    OUTPUT
        c : char inputted

    RETURN
        TRUE  : successful
        FALSE : failed due to timeout
*/
static BOOL _icli_char_get(
    IN  icli_addrword_t     app_id,
    IN  i32                 timeout,
    OUT i32                 *c
)
{
    cli_iolayer_t       *pIO = (cli_iolayer_t *)app_id;
    char                ch;
    i32                 rc;

    /* get char */
    rc = pIO->cli_getch(pIO, timeout, &ch);

    if ( rc != VTSS_OK ) {
        T_R("rc:0x%X", rc);
#if 1 /* Bugzilla#11486, 04/08/2013 15:02 */
        if ( pIO->bIOerr == TRUE ) {
            if ( pIO->icli_session_id != ICLI_SESSION_ID_NONE ) {
                (void)icli_session_close( pIO->icli_session_id );
            }
        }
#endif
        return FALSE;
    }
    *c = ch;
    return TRUE;
}

/*
    output one char on session
*/
static BOOL _icli_char_put(
    IN  icli_addrword_t     app_id,
    IN  char                c
)
{
    cli_iolayer_t       *pIO = (cli_iolayer_t *)app_id;

    pIO->cli_putchar(pIO, c);

    if ( pIO->bIOerr == TRUE ) {
        return FALSE;
    }

    return TRUE;
}

/*
    output string on session
*/
static BOOL _icli_str_put(
    IN  icli_addrword_t     app_id,
    IN  const char          *str
)
{
    cli_iolayer_t       *pIO = (cli_iolayer_t *)app_id;

    pIO->cli_puts(pIO, str);

    if ( pIO->bIOerr == TRUE ) {
        return FALSE;
    }

    return TRUE;
}

static void _open_icli_session(
    IN cli_iolayer_t    *pIO
)
{
    icli_session_open_data_t    open_data;
    i32                         rc;

    /* reset session ID */
    pIO->icli_session_id = ICLI_SESSION_ID_NONE;

    /* prepare open data */
    memset(&open_data, 0, sizeof(open_data));

    open_data.way    = (icli_session_way_t) pIO->session_way;
    open_data.app_id = (icli_addrword_t)pIO;

    switch ( pIO->session_way ) {
    case CLI_WAY_CONSOLE:
        open_data.way         = ICLI_SESSION_WAY_THREAD_CONSOLE;
        open_data.name        = "CONSOLE";
        break;

    case CLI_WAY_TELNET:
        open_data.way         = ICLI_SESSION_WAY_THREAD_TELNET;
        open_data.name        = "TELNET";
        open_data.client_ip   = pIO->client_ip;
        open_data.client_port = pIO->client_port;
        break;

    case CLI_WAY_SSH:
        open_data.way         = ICLI_SESSION_WAY_THREAD_SSH;
        open_data.name        = "SSH";
        open_data.client_ip   = pIO->client_ip;
        open_data.client_port = pIO->client_port;
        break;

    default:
        T_E("invalid session way = %d\n", pIO->session_way);
        return;
    }

    /* I/O callback */
    open_data.char_get  = _icli_char_get;
    open_data.char_put  = _icli_char_put;
    open_data.str_put   = _icli_str_put;

    /* open ICLI session */
    rc = icli_session_open(&open_data, &(pIO->icli_session_id));
    if ( rc != ICLI_RC_OK ) {
        T_E("Fail to open a session for TELNET, err = %d\n", rc);
        return;
    }
    /* set user name for SSH */
    if ( pIO->session_way == CLI_WAY_SSH ) {
        if (icli_session_privilege_set(pIO->icli_session_id, (icli_privilege_t)pIO->priv_lvl) != ICLI_RC_OK) {
            T_E("Fail to set priv_lvl %u to ICLI session %d\n", pIO->priv_lvl, pIO->icli_session_id);
        }
#ifdef VTSS_SW_OPTION_AUTH
        if (icli_session_agent_id_set(pIO->icli_session_id, pIO->agent_id) != ICLI_RC_OK) {
            T_E("Fail to set agent_id %u to ICLI session %d\n", pIO->agent_id, pIO->icli_session_id);
        }
#endif /* VTSS_SW_OPTION_AUTH */
        if (icli_session_user_name_set(pIO->icli_session_id, pIO->username) != ICLI_RC_OK) {
            T_E("Fail to set user name %s to ICLI session %d\n", pIO->username, pIO->icli_session_id);
        }
    }
}

static void _close_icli_session(
    IN cli_iolayer_t    *pIO
)
{
    if ( pIO->icli_session_id != ICLI_SESSION_ID_NONE ) {
        (void)icli_session_close( pIO->icli_session_id );
        pIO->icli_session_id = ICLI_SESSION_ID_NONE;
    }
}
#endif /* VTSS_SW_OPTION_ICLI */

/****************************************************************************/
/* CLI public functions                                                     */
/****************************************************************************/
/* Generic CLI thread used by serial, Telnet and SSH */
void cli_thread(vtss_addrword_t data)
{
    cli_iolayer_t   *pIO;
    BOOL            b_loop = TRUE;

    pIO = (cli_iolayer_t *)data;

    if (pIO->session_way == CLI_WAY_CONSOLE) {
        // This thread may have both Console, Telnet, and SSH as I/O layer.
        // If it's the console (only one single instance for the entire
        // life-span) then wait with the login-prompt until we get the
        // master up event. We could have chosen to wait with creating
        // the thread until MASTER_UP in cli_io_init(), but then we
        // should have made sure that only one single thread was created
        // in a stacking environment, where the MASTER_UP event may
        // occur multiple times.
        msg_wait(MSG_WAIT_UNTIL_MASTER_UP_POST, VTSS_MODULE_ID_CLI);
    }

    vtss_thread_set_data(cli.ioindex, (vtss_addrword_t)pIO); /* Store the IO layer in my thread data */

    // Be sure to have set up the thread data first

    while (b_loop) {

#ifdef VTSS_SW_OPTION_ICLI
        /* open ICLI session */
        _open_icli_session(pIO);
#endif /* VTSS_SW_OPTION_ICLI */

        CLI_CRIT_ENTER();
        pIO->cli_init(pIO);
        CLI_CRIT_EXIT();

        cli_banner_motd(pIO);

        if (pIO->cli_login) {
            if (!pIO->cli_login(pIO)) {
#ifdef VTSS_SW_OPTION_ICLI
                /*
                    close ICLI session
                    put here before cli_close()
                    because cli_close() for Telnet/SSH will exit thread directly.
                */
                _close_icli_session(pIO);
#endif /* VTSS_SW_OPTION_ICLI */

                pIO->cli_close(pIO);

                VTSS_OS_MSLEEP(1000);  /* To stall password cracking */
#ifdef VTSS_SW_OPTION_ICLI
                if (pIO->session_way != CLI_WAY_CONSOLE) {
                    b_loop = FALSE;
                }
#endif
                continue;
            }
        } else {
            cli_pre_login(pIO); /* Wait for user to press enter (iCLI only) */
        }

        cli_banner_exec(pIO);

        cli_parser_loop(pIO); /* Main parser loop */

#ifdef VTSS_SW_OPTION_AUTH
        char hostname[INET6_ADDRSTRLEN];
        (void)vtss_auth_logout(pIO->agent,
                               misc_ip_txt(&pIO->client_ip, hostname),
                               pIO->username,
                               pIO->priv_lvl,
                               pIO->agent_id);

#endif /* VTSS_SW_OPTION_AUTH */

#ifdef VTSS_SW_OPTION_ICLI
        /*
            close ICLI session
            put here before cli_close()
            because cli_close() for Telnet/SSH will exit thread directly.
        */


        _close_icli_session(pIO);
#endif /* VTSS_SW_OPTION_ICLI */

        pIO->cli_close(pIO); /* <- only cli serial returns from this function! */

#ifdef VTSS_SW_OPTION_ICLI
        if (pIO->session_way != CLI_WAY_CONSOLE) {
            b_loop = FALSE;
        }
#endif
    } /* while (b_loop) */

}
#define NEWCLI_NOTICE_EVENT_ANY      0xFFFF  /* Any possible bit... */
#define NEWCLI_NOTICE_EVENT_SHOWRUN             0x0001
#define NEWCLI_NOTICE_EVENT_SHOWRUN_DEF      0x0002
#define NEWCLI_NOTICE_EVENT_SHOWRUN_TL             0x0004
#define NEWCLI_NOTICE_EVENT_SHOWRUN_DEF_TL      0x0008
extern mesa_rc vtss_icfg_query_all_for_asyn(BOOL all_defaults, int session_id);

void Newcli_thread(vtss_addrword_t data)
{
    vtss_flag_value_t    events;
    int i;
    while(1)
    {


        events = vtss_flag_wait(&Newcli_Notice_Flag, NEWCLI_NOTICE_EVENT_ANY,   VTSS_FLAG_WAITMODE_OR_CLR);
        if (events & NEWCLI_NOTICE_EVENT_SHOWRUN)
        {
            vtss_icfg_query_all_for_asyn(0,0);
        }
        if(events & NEWCLI_NOTICE_EVENT_SHOWRUN_DEF)
        {
            vtss_icfg_query_all_for_asyn(1,0);
        }
        if (events & NEWCLI_NOTICE_EVENT_SHOWRUN_TL)
        {
            for(i = 0; i < CLI_TELNET_MAX_CLIENT; i++)
            {
                if(Newcli_sessionid[i])
                {
                    vtss_icfg_query_all_for_asyn(0, i);
                    Newcli_sessionid[i] =0;
                }
            }
        }
        if(events & NEWCLI_NOTICE_EVENT_SHOWRUN_DEF_TL)
        {
            for(i = 0; i < CLI_TELNET_MAX_CLIENT; i++)
            {
                if(Newcli_sessionid[i])
                {
                    vtss_icfg_query_all_for_asyn(1, i);
                    Newcli_sessionid[i] = 0;
                }
            }
       }
    }
    return;
}
void newcli_showrun_set()
{
    vtss_flag_setbits(&Newcli_Notice_Flag, NEWCLI_NOTICE_EVENT_SHOWRUN);
    return;
}
void newcli_showrundef_set()
{
    vtss_flag_setbits(&Newcli_Notice_Flag, NEWCLI_NOTICE_EVENT_SHOWRUN_DEF);
    return;
}
void newcli_showrun_set_tl()
{
    vtss_flag_setbits(&Newcli_Notice_Flag, NEWCLI_NOTICE_EVENT_SHOWRUN_TL);
    return;
}
void newcli_showrundef_set_tl()
{
    vtss_flag_setbits(&Newcli_Notice_Flag, NEWCLI_NOTICE_EVENT_SHOWRUN_DEF_TL);
    return;
}
int  newcli_sessionid_set(ULONG sessionid, int value)
{
    if(sessionid < CLI_TELNET_MAX_CLIENT)
    {
        Newcli_sessionid[sessionid] = value;
        return 0;
    }
    return 1;
}
int newcli_sessionid_rd(ULONG sessionid)
{
    if(sessionid < CLI_TELNET_MAX_CLIENT)
       return Newcli_sessionid[sessionid];
    return 0;
}
/* CLI Generic IO layer */

char cli_io_getkey(cli_iolayer_t *pIO, char ch)
{
    char c;
    while (pIO->cli_getch(pIO, 0, &c) == VTSS_OK) {
        if ((ch == 0) || (ch == c)) {
            return c;
        }
    }
    return 0;
}

mesa_rc cli_io_getch(cli_iolayer_t *pIO, int timeout, char *ch)
{
    struct timeval tv;
    int            rounds, num, len, wakeup = CLI_GETCH_WAKEUP; // Wake from select each 'wakeup' mS
    fd_set         set;
    char           c;

    if (timeout == 0) {
        rounds = 1; // One round
        wakeup = 0; // Wakeup immediately
    } else if (timeout < 0) {
        rounds = -1; // No timeout
    } else {
        rounds = timeout / CLI_GETCH_WAKEUP;
        if (timeout % CLI_GETCH_WAKEUP) {
            rounds++;
        }
    }

    T_R("rounds:%d", rounds);
    while (rounds && !pIO->bIOerr) {
        FD_ZERO(&set);
        FD_SET((unsigned int)pIO->fd, &set);

        tv.tv_sec  = wakeup / 1000;
        tv.tv_usec = (wakeup % 1000) * 1000;

        num = select(pIO->fd + 1, &set, NULL, NULL, &tv);
        T_D("num:%d", num);
        switch (num) {
        case 1: // There is something to read
            len = read(pIO->fd, &c, 1);
            T_D("len:%d", len);
            if (len != 1) {
                pIO->bIOerr = TRUE;
                return VTSS_UNSPECIFIED_ERROR;
            }
            *ch = c;
            return VTSS_OK;
        case 0: // Timeout
            if (rounds > 0) {
                rounds--;
            }
            break;
        default: // Error
            pIO->bIOerr = TRUE;
            T_R("T2, ch:%d", *ch);
            return VTSS_UNSPECIFIED_ERROR;
        }
    }
    if (pIO->bIOerr) {
        T_R("T1, ch:%d", *ch);
        return VTSS_UNSPECIFIED_ERROR;
    }
    T_N("TIMEOUT, ch:%d", *ch);
    return CLI_ERROR_IO_TIMEOUT;
}

int cli_io_printf(cli_iolayer_t *pIO, const char *fmt, ...)
{
    int     rc;
    va_list ap;

    if (!pIO) {
        return 0;
    }

    va_start(ap, fmt);
    rc = pIO->cli_vprintf(pIO, fmt, ap);
    va_end(ap);

    return rc;
}

int cli_printf(const char *fmt, ...)
{
    cli_iolayer_t *pIO = (cli_iolayer_t *) vtss_thread_get_data(cli.ioindex);
    int           rc = 0;
    va_list       ap;

    if (!pIO) {
        return 0;
    }

    va_start(ap, fmt);
    rc = pIO->cli_vprintf(pIO, fmt, ap);
    va_end(ap);

    return rc;
}

void cli_puts(const char *str)
{
    cli_iolayer_t *pIO = (cli_iolayer_t *) vtss_thread_get_data(cli.ioindex);

    if (!pIO) {
        return;
    }

    pIO->cli_puts(pIO, str);
}

void cli_putchar(char ch)
{
    cli_iolayer_t *pIO = (cli_iolayer_t *) vtss_thread_get_data(cli.ioindex);

    if (!pIO) {
        return;
    }

    pIO->cli_putchar(pIO, ch);
}

void cli_flush(void)
{
    cli_iolayer_t *pIO = (cli_iolayer_t *) vtss_thread_get_data(cli.ioindex);

    if (!pIO) {
        return;
    }

    pIO->cli_flush(pIO);
}

char cli_getkey(char ch)
{
    cli_iolayer_t *pIO = (cli_iolayer_t *) vtss_thread_get_data(cli.ioindex);

    if (!pIO) {
        return '\0';
    }

    return cli_io_getkey(pIO, ch);
}

int cli_fd(void)
{
    cli_iolayer_t *pIO = (cli_iolayer_t *) vtss_thread_get_data(cli.ioindex);

    if (!pIO) {
        return -1;
    }

    return pIO->fd;
}

#ifdef VTSS_SW_OPTION_AUTH
BOOL cli_io_login(cli_iolayer_t *pIO, vtss_appl_auth_agent_t agent, int timeout)
{
    char ch, hostname[INET6_ADDRSTRLEN], passwd[VTSS_SYS_PASSWD_LEN];
    char *username = pIO->username;
    int  ct, auth_cnt = 5;
    u8   priv_lvl;
    u16  agent_id;
    mesa_rc rc;
    users_conf_t    conf;

    pIO->agent = agent;
    if (agent == VTSS_APPL_AUTH_AGENT_SSH) {
        pIO->authenticated = TRUE;


        return TRUE; /* Nothing more to do. SSH uses its own authentication mechanism */
    }
    cli_banner_login(pIO, agent);

    while (auth_cnt--) {
        cli_puts("\nUsername: ");

        username[ct = 0] = '\0';
        while (!pIO->bIOerr && ct < VTSS_SYS_USERNAME_LEN) {
            if (pIO->cli_getch(pIO, timeout, &ch) != VTSS_OK) {
                return FALSE;
            }
            if ((ch == CTLD) || (ch == CTLH) || (ch == DEL)) {
                if (ct) {
                    ct--;
                    username[ct] = '\0';
                    cli_putchar(ESC);
                    cli_putchar(0x5b);
                    cli_putchar(CURSOR_LEFT);
                    cli_putchar(ESC);
                    cli_putchar(0x5b);
                    cli_putchar(CURSOR_DELETE_TO_EOL);
                    cli_flush();
                }
                continue;
            } else if (ch == CR) {
                break;              /* End of username */
            } else if (ch >= 32 && ch <= 126) {  /* Rack up chars */
                cli_putchar(ch);
                username[ct++] = ch;
                if (ct < VTSS_SYS_USERNAME_LEN) {
                    username[ct] = '\0';
                } else {
                    username[VTSS_SYS_USERNAME_LEN - 1] = '\0';
                }
            }
        }

        if (pIO->bIOerr) {
            return FALSE;
        }

        cli_puts("\nPassword: ");

        passwd[ct = 0] = '\0';
        while (!pIO->bIOerr && ct < VTSS_SYS_PASSWD_LEN) {
            if (pIO->cli_getch(pIO, timeout, &ch) != VTSS_OK) {
                return FALSE;
            }
            if ((ch == CTLD) || (ch == CTLH) || (ch == DEL)) {
                if (ct) {
                    ct--;
                    passwd[ct] = '\0';
                }
                continue;
            } else if (ch == CR) {
                break;              /* End of passwd */
            } else if (ch >= 32 && ch <= 126) {  /* Rack up chars */
                passwd[ct++] = ch;
                if (ct < VTSS_SYS_PASSWD_LEN) {
                    passwd[ct] = '\0';
                } else {
                    passwd[VTSS_SYS_PASSWD_LEN - 1] = '\0';
                }
            }
        }

        if (pIO->bIOerr) {
            return FALSE;
        }

#if 1 /* CP, 04/09/2013 14:01, consume redundant NEWLINE */
        if ( agent == VTSS_APPL_AUTH_AGENT_TELNET ) {
            (void)pIO->cli_getch( pIO, 100, &ch );
        }
#endif

        	rc = vtss_auth_login(agent, misc_ip_txt(&pIO->client_ip, hostname), username, passwd, &priv_lvl, &agent_id, USER_TYPE_INVALIE);

        if (rc == VTSS_OK) {
            CLI_CRIT_ENTER();
            pIO->authenticated = TRUE;
            pIO->priv_lvl      = priv_lvl;
            pIO->agent_id      = agent_id;
            CLI_CRIT_EXIT();
#ifdef VTSS_SW_OPTION_ICLI
            if (icli_session_privilege_set(pIO->icli_session_id, (icli_privilege_t)priv_lvl) != ICLI_RC_OK) {
                T_E("Fail to set priv_lvl %u to ICLI session %d\n", priv_lvl, pIO->icli_session_id);
            }
            if (icli_session_agent_id_set(pIO->icli_session_id, agent_id) != ICLI_RC_OK) {
                T_E("Fail to set agent_id %u to ICLI session %d\n", agent_id, pIO->icli_session_id);
            }
            if (icli_session_user_name_set(pIO->icli_session_id, username) != ICLI_RC_OK) {
                T_E("Fail to set user name %s to ICLI session %d\n", username, pIO->icli_session_id);
            }
#endif /* VTSS_SW_OPTION_ICLI */
            cli_putchar('\n');



            /* add by tangyong for security */
            if (vtss_user_password_complexity_get()) {
                memset(&conf, 0, sizeof(users_conf_t));

                strncpy(conf.username, username, strlen(username));

                rc = vtss_users_mgmt_conf_get(&conf, FALSE);
                if (rc != VTSS_RC_OK) {
                    cli_puts("\nFailed to get user info.\n");
                    return TRUE;
                }

                /* No password change in 90 days */
                if (vtss_current_time() > (conf.psw_modify_time + VTSS_OS_MSEC2TICK(user_psw_modify_time * 1000))) {
                    cli_puts("\nYour password has not been changed for more than 90 days, please change it.\n");
                    return TRUE;
                }

                /* Check default password */
                if (board_support_complexpwd()) {
                    if (strcmp(passwd, VTSS_SYS_ADMIN_COMPLE_PWD) == 0) {
                        cli_puts("\nNote: Please change the default password!\n");
                    }
                } else {
                    if (strcmp(passwd, VTSS_SYS_ADMIN_PASSWORD) == 0) {
                        cli_puts("\nNote: Please change the default password!\n");
                    }
                }
            }
            /* end by tangy */
            return TRUE; /* Success */
        }

        if (rc == VTSS_APPL_AUTH_ERROR_USER_LOCKED)
            cli_puts("\nThe account has been locked because of too many failures! Please try again in 10 minutes.\n");
        else
            cli_puts("\nWrong username or password!");
    }
    return FALSE;
}
#endif /* VTSS_SW_OPTION_AUTH */

void cli_set_io_handle(cli_iolayer_t *pIO)
{
    vtss_thread_set_data(cli.ioindex, (vtss_addrword_t)pIO);
}

cli_iolayer_t *cli_get_io_handle(void)
{
    return (cli_iolayer_t *)vtss_thread_get_data(cli.ioindex);
}

static bool telnet_enabled;
static bool cli_enabled;

bool telnet_module_enabled()
{
    return telnet_enabled;
}

bool cli_module_enabled()
{
    return cli_enabled;
}

/****************************************************************************/
/*  Initialization                                                          */
/****************************************************************************/
mesa_rc cli_io_init(vtss_init_data_t *data)
{
    if (data->cmd == INIT_CMD_EARLY_INIT) {
        /* Initialize and register trace ressources */
        VTSS_TRACE_REG_INIT(&trace_reg, trace_grps, TRACE_GRP_CNT);
        VTSS_TRACE_REGISTER(&trace_reg);
    }

    T_D("enter, cmd: %d, isid: %u, flags: 0x%x", data->cmd, data->isid, data->flags);

    switch (data->cmd) {
    case INIT_CMD_INIT:
        /* Create semaphore for critical regions */
        critd_init(&cli.crit, "cli.crit", VTSS_MODULE_ID_CLI, VTSS_TRACE_MODULE_ID, CRITD_TYPE_MUTEX);
        CLI_CRIT_EXIT();

        cli.ioindex = vtss_thread_new_data_index();

        cli_enabled = vtss::appl::main::module_enabled("cli");
#ifdef VTSS_SW_OPTION_CLI_TELNET
        telnet_enabled = vtss::appl::main::module_enabled("telnet");
#endif
        break;

    case INIT_CMD_START:
        if (cli_enabled) {
            vtss_thread_create(VTSS_THREAD_PRIO_DEFAULT,
                               cli_thread,
                               (vtss_addrword_t)vtss_appl_cli_console_io_get(),
                               "CLI Serial",
                               nullptr,
                               0,
                               &cli.thread_handle,
                               &cli.thread_block);
        }

#ifdef VTSS_SW_OPTION_CLI_TELNET
        if (telnet_enabled) {
            cli_telnet_start();
        }
#endif
        {
            vtss_flag_init(&Newcli_Notice_Flag);
            vtss_thread_create(VTSS_THREAD_PRIO_DEFAULT,
                               Newcli_thread,
                               0,
                               "NewCLI Serial",
                               nullptr,
                               0,
                               &Newcli_thread_handle,
                               &Newcli_thread_block);
        }

        break;

    case INIT_CMD_MASTER_UP: {
        break;
    }

    case INIT_CMD_CONF_DEF:
#ifdef VTSS_SW_OPTION_CLI_TELNET
        cli_telnet_close();
#endif
        break;

    default:
        break;
    }

    return VTSS_OK;
}

/****************************************************************************/
/*                                                                          */
/*  End of file.                                                            */
/*                                                                          */
/****************************************************************************/
