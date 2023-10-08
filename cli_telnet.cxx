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

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "vtss_os_wrapper.h"

#include "main.h"
#include "cli_io_api.h"
#include "cli_trace_def.h"
#include "sysutil_api.h"
#include "control_api.h"
#include "vtss_trace_api.h"
#ifdef VTSS_SW_OPTION_AUTH
#include "vtss_auth_api.h"
#endif /* VTSS_SW_OPTION_AUTH */
#include "msg_api.h"     /* For msg_wait() */

#define VTSS_ALLOC_MODULE_ID VTSS_MODULE_ID_CLI

#if !defined(CLI_TELNET_MAX_CLIENT)
#define CLI_TELNET_MAX_CLIENT       4
#endif
#if !defined(CLI_TELNET_PORT)
#ifdef __SIMULATOR__
/*这里与内核自带的telnet端口冲突，临时修改为2323，后期再做调整*/
#define CLI_TELNET_PORT             2323    /* Default telnet port */
#else
#define CLI_TELNET_PORT             23    /* Default telnet port */
#endif
#endif
#if !defined(CLI_TELNET_THREAD_NAME_MAX)
#define CLI_TELNET_THREAD_NAME_MAX  16       /* Maximum thread name */
#endif

static vtss_thread_t cli_telnet_parent_thread_data;
static vtss_handle_t cli_telnet_parent_thread_handle;

#define CLI_TELNET_FLAG_RUNNING    0x00000001 /* Start/stop telnet server */
static vtss_flag_t   cli_telnet_parent_flag;

static char          cli_telnet_child_name[CLI_TELNET_MAX_CLIENT][CLI_TELNET_THREAD_NAME_MAX];
static vtss_thread_t cli_telnet_child_data[CLI_TELNET_MAX_CLIENT];
static vtss_handle_t cli_telnet_child_handle[CLI_TELNET_MAX_CLIENT];

// Special characters used by Telnet - must be interpretted here
#define TELNET_IAC    0xFF // Interpret as command (escape)
#define TELNET_SE     0xF0 // End of subnegotiation parameters
#define TELNET_IP     0xF4 // Interrupt process
#define TELNET_SB     0xFA // Subnegotiation of the indicated option follows
#define TELNET_WILL   0xFB // I Will do XXX
#define TELNET_WONT   0xFC // I Won't do XXX
#define TELNET_DO     0xFD // Will you XXX
#define TELNET_DONT   0xFE // Don't you XXX

#define TELNET_OPT_ECHO                     1
#define TELNET_OPT_SUPPRESS_GO_AHEAD        3
#define TELNET_OPT_STATUS                   5
#define TELNET_OPT_TIMING_MARK              6
#define TELNET_OPT_TERMINAL_TYPE            24
#define TELNET_OPT_WINDOW_SIZE              31
#define TELNET_OPT_TERMINAL_SPEED           32
#define TELNET_OPT_REMOTE_FLOW_CONTROL      33
#define TELNET_OPT_LINEMODE                 34
#define TELNET_OPT_ENVIRONMENT_VARIABLES    36

// Sub-option qualifiers
#define TELNET_QUAL_IS      0   // option is
#define TELNET_QUAL_SEND    1   // send option

// The max. name length of terminal type
#define TELNET_TERMINAL_TYPE_NAME_MAX   32

#ifdef VTSS_SW_OPTION_IPV6
# define PEXIT(m)                         \
    do {                                  \
        if (s       >= 0) close(s);       \
        if (conn    >= 0) close(conn);    \
        if (s6      >= 0) close(s6);      \
        if (conn_v6 >= 0) close(conn_v6); \
        T_EG(VTSS_TRACE_GRP_TELNET, m);   \
        return;                           \
    } while(0)
#else
# define PEXIT(m)                         \
    do {                                  \
        if (s    >= 0) close(s);          \
        if (conn >= 0) close(conn);       \
        T_EG(VTSS_TRACE_GRP_TELNET, m);   \
        return;                           \
    } while(0)
#endif /* VTSS_SW_OPTION_IPV6 */

static const u8 telnet_opts[] = {
    TELNET_IAC, TELNET_WILL, TELNET_OPT_SUPPRESS_GO_AHEAD,
    TELNET_IAC, TELNET_WILL, TELNET_OPT_ECHO,
    TELNET_IAC, TELNET_DONT, TELNET_OPT_LINEMODE,
    TELNET_IAC, TELNET_DO,   TELNET_OPT_TERMINAL_TYPE,
};

static mesa_bool_t telnet_security_mode = FALSE;

/*lint -sem(telnet_trace_flush, thread_protected) */
/*lint -sem(telnet_trace_putchar, thread_protected) */
/*lint -sem(telnet_trace_vprintf, thread_protected) */
/*lint -sem(telnet_trace_write_string, thread_protected) */
/*lint -sem(telnet_trace_write_string_len, thread_protected) */
/*lint -sem(cli_telnet_do_close, thread_protected) */
/*lint -sem(cli_telnet, thread_protected) */
/*lint -sem(cli_telnet_create_child_thread, thread_protected) */

/* CLI Telnet IO layer */

typedef struct cli_io_telnet {
    cli_io_t                base;
    int                     listen_fd;
    BOOL                    trace_registered;
    vtss_trace_io_t         *trace_layer;
    uint                    trace_reg;
    BOOL                    valid;
    char                    prev_ch;
    char                    client_ttype[TELNET_TERMINAL_TYPE_NAME_MAX]; // Client terminal type
} cli_io_telnet_t;

/* Raw Telnet IO layer */

static void send_options(cli_io_telnet_t *pTIO, unsigned char c0, unsigned char c1, unsigned char c2)
{
    if (c0 == TELNET_IAC && c1 == TELNET_SB) {
        unsigned char opts[6];
        opts[0] = c0;
        opts[1] = c1;
        opts[2] = c2;
        opts[3] = TELNET_QUAL_SEND;
        opts[4] = TELNET_IAC;
        opts[5] = TELNET_SE;
        int n = write(pTIO->base.io.fd, opts, sizeof(opts));
        if (n != sizeof(opts)) {
            pTIO->base.io.bIOerr = TRUE;
        }
    } else {
        unsigned char opts[3];
        opts[0] = c0;
        opts[1] = c1;
        opts[2] = c2;
        int n = write(pTIO->base.io.fd, opts, sizeof(opts));
        if (n != sizeof(opts)) {
            pTIO->base.io.bIOerr = TRUE;
        }
    }
}

static void __raw_putch(cli_io_telnet_t *pTIO, char c)
{
    int n = write(pTIO->base.io.fd, &c, 1);
    if (n < 0) {
        pTIO->base.io.bIOerr = TRUE;
    }
}

#define __raw_getch(_pIO_, _timeout_, _ch_) do {                                                                        \
    mesa_rc _rc_;                                                                                                       \
    T_NG(VTSS_TRACE_GRP_TELNET, "Telnet timeout %d", _timeout_);                                                        \
    _rc_ = cli_io_getch(_pIO_, _timeout_, _ch_);                                                                        \
    if (_rc_ != VTSS_OK) {                                                                                              \
        T_NG(VTSS_TRACE_GRP_TELNET, "Telnet err %s (%d)", error_txt(_rc_), _rc_);                                       \
        return _rc_;                                                                                                    \
    }                                                                                                                   \
    T_NG(VTSS_TRACE_GRP_TELNET, "Telnet got char '%c' (%u)", ((*_ch_ > 31) && (*_ch_ < 127)) ? *_ch_ : '?', (u8)*_ch_); \
} while (0)

static BOOL __write_buf(cli_io_telnet_t *pTIO, const char *buf, unsigned length)
{
    if (length && !pTIO->base.io.bIOerr) {
        int n = write(pTIO->base.io.fd, buf, length);
        if (n != length) {
            pTIO->base.io.bIOerr = TRUE;
        }
    }
    return pTIO->base.io.bIOerr;
}

static void __write_crlf(cli_io_telnet_t *pTIO, const char *buf, unsigned length)
{
    char *newline;
    while (length && (newline = (char *) memchr(buf, '\n', length)) != NULL) {
        unsigned blk = newline - buf;
        if (__write_buf(pTIO, buf, blk)) {
            return;
        }
        if (__write_buf(pTIO, "\r\n", 2)) {
            return;
        }
        buf += (blk + 1);    // string\n
        length -= (blk + 1);
    }
    (void) __write_buf(pTIO, buf, length);
}

/* Real Telnet IO layer */
static void cli_io_telnet_init(cli_iolayer_t *pIO)
{
    cli_io_telnet_t *pTIO = (cli_io_telnet_t *) pIO;
    pIO->bIOerr = FALSE;
    pIO->bEcho = FALSE;
    pIO->authenticated = FALSE;
    if (!pTIO->trace_registered) {
        if (vtss_trace_io_register(pTIO->trace_layer, VTSS_MODULE_ID_CLI, &pTIO->trace_reg) == VTSS_OK) {
            pTIO->trace_registered = TRUE;
            T_DG(VTSS_TRACE_GRP_TELNET, "Telnet trace register successfully");
        } else {
            T_EG(VTSS_TRACE_GRP_TELNET, "Telnet unable to register trace!");
        }
    } else {
        // It may due to a unexpected disconnection during last valid connection.
        T_DG(VTSS_TRACE_GRP_TELNET, "Telnet trace already registered!");
    }
}

static void cli_io_telnet_putchar(cli_iolayer_t *pIO, char ch)
{
    // Translate \n => \r\n
    if (ch == '\n') {
        __raw_putch((cli_io_telnet_t *) pIO, '\r');
    }
    __raw_putch((cli_io_telnet_t *) pIO, ch);
}

static void cli_io_telnet_puts(cli_iolayer_t *pIO, const char *str)
{
    (void) __write_crlf((cli_io_telnet_t *)pIO, str, strlen(str));
}

static void cli_io_telnet_puts_len(cli_iolayer_t *pIO, const char *str, unsigned length)
{
    (void) __write_crlf((cli_io_telnet_t *)pIO, str, length);
}

static int cli_io_telnet_vprintf(cli_iolayer_t *pIO, const char *fmt, va_list ap)
{
    char buf[1024];
    int l;
    l = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    __write_crlf((cli_io_telnet_t *)pIO, buf, l);
    return l;
}

static int cli_io_telnet_getch(cli_iolayer_t *pIO, int timeout, char *ch)
{
    cli_io_telnet_t *pTIO = (cli_io_telnet_t *) pIO;
    char prev_ch, command, option;
    u8 resp;

    while (TRUE) {
        __raw_getch(pIO, timeout, ch);

        prev_ch = pTIO->prev_ch;
        pTIO->prev_ch = *ch;

        if ((prev_ch == CR) && (*ch == 0)) {
            /* BZ#19854, According to RFC1123(3.3.1), CR+LF and CR+NUL should be treated as End-of-Line */
            pTIO->prev_ch = *ch = LF;
        }

        if ((u8)*ch != TELNET_IAC) {
            return VTSS_OK;
        }

        // Mapping value 0x7F to backspace when terminal type is XTERM
        if ((u8)*ch == DEL && pIO->cDEL == CLI_DEL_KEY_LINUX) {
            *ch = CTLH;
        }

        // Telnet escape - get the command
        __raw_getch(pIO, timeout, &command);
        T_NG(VTSS_TRACE_GRP_TELNET, "Telnet got command %u", (u8)command);

        switch ((u8)command) {
        case TELNET_IAC:
            // The other special case - escaped escape
            *ch = command;
            return VTSS_OK;

        case TELNET_IP:
            // Just in case the other end needs synchronizing
            send_options(pTIO, TELNET_IAC, TELNET_WONT, TELNET_OPT_TIMING_MARK);
            *ch = 0x03; // Special case for ^C == Interrupt Process
            return VTSS_OK;

        case TELNET_DO:
            // Telnet DO option
            __raw_getch(pIO, timeout, &option);
            T_NG(VTSS_TRACE_GRP_TELNET, "Telnet got option %u", (u8)option);
            resp = TELNET_WONT;     /* Default to WONT */
            switch ((u8)option) {
            case TELNET_OPT_ECHO:      /* Will echo */
                pTIO->base.io.bEcho = TRUE;
                T_DG(VTSS_TRACE_GRP_TELNET, "Telnet ECHO ON");
                /* we send "will echo" in initial state (telnet_opts) - no response required here */
                continue; /* Get next char */
            case TELNET_OPT_SUPPRESS_GO_AHEAD: /* Will Suppress */
                resp = TELNET_WILL;
                break;
            }
            T_DG(VTSS_TRACE_GRP_TELNET, "Telnet: DO %d -> %s", option, resp == TELNET_WILL ? "WILL" : "WONT");
            // Respond
            send_options(pTIO, TELNET_IAC, resp, option);
            continue; /* Get next char */

        case TELNET_SB:
            // Telnet Subnegotiation option
            __raw_getch(pIO, timeout, &option);
            T_NG(VTSS_TRACE_GRP_TELNET, "Telnet got option %u", (u8)option);
            switch ((u8)option) {
            case TELNET_OPT_TERMINAL_TYPE:  /* Terminal type */
                __raw_getch(pIO, timeout, &option);
                switch ((u8)option) {
                case TELNET_QUAL_IS: /* Terminal type is ... */
                    char client_ttype[TELNET_TERMINAL_TYPE_NAME_MAX];
                    int ttype_idx = 0;
                    do {
                        __raw_getch(pIO, timeout, &option);
                        if (ttype_idx < TELNET_TERMINAL_TYPE_NAME_MAX) {
                            client_ttype[ttype_idx++] = option;
                        } else {
                            break;
                        }
                    } while ((u8)option != TELNET_SE);
                    client_ttype[ttype_idx] = '\0';
                    strcpy(pTIO->client_ttype, client_ttype);
                    T_NG(VTSS_TRACE_GRP_TELNET, "Telnet got terminal type %s", client_ttype);
                    if (strstr(client_ttype, "xterm") || strstr(client_ttype, "XTERM")) {
                        pIO->cBS = CLI_BS_KEY_LINUX;
                        pIO->cDEL = CLI_DEL_KEY_LINUX;
                    } else {
                        /* VTSS CLI engine is based on VT100 (BS:0x08 DEL:0x7F) */
                        pIO->cBS = CLI_BS_KEY_WINDOWS;
                        pIO->cDEL = CLI_DEL_KEY_WINDOWS;
                    }
                    break;
                }
                break;

            }
            continue; /* Get next char */

        case TELNET_WILL:
            // Telnet WILL option
            __raw_getch(pIO, timeout, &option);
            T_NG(VTSS_TRACE_GRP_TELNET, "Telnet got option %u", (u8)option);
            resp = TELNET_DONT;     /* Default to WONT */
            switch ((u8)option) {
            case TELNET_OPT_SUPPRESS_GO_AHEAD: /* Do Suppress */
                resp = TELNET_DO;
                break;
            case TELNET_OPT_TERMINAL_TYPE: /* Do Terminal type */
                resp = TELNET_SB;
                break;
            }
            T_DG(VTSS_TRACE_GRP_TELNET, "Telnet: WILL %d -> %s", option, resp == TELNET_DO ? "DO" : "DONT");
            // Respond
            send_options(pTIO, TELNET_IAC, resp, option);
            continue; /* Get next char */
        case TELNET_WONT:
        case TELNET_DONT:
            __raw_getch(pIO, timeout, &option);
            T_NG(VTSS_TRACE_GRP_TELNET, "Telnet got option %u", (u8)option);
            continue; /* Get next char */
        default:
            continue; /* Get next char */
        }
    }
}

static void cli_io_telnet_flush(cli_iolayer_t *pIO)
{
}

static void cli_io_telnet_close(cli_iolayer_t *pIO)
{
    cli_io_telnet_t *pTIO = (cli_io_telnet_t *) pIO;

    if (pIO->fd >= 0) {
        close(pIO->fd);
        pIO->fd = -1;
        pIO->bIOerr = TRUE;
        pIO->client_ip.type = MESA_IP_TYPE_NONE;
        pIO->client_port = 0;
#ifdef VTSS_SW_OPTION_AUTH
        pIO->agent_id = 0;
#endif
        pTIO->valid = FALSE;
        if (pTIO->trace_registered) {
            (void)vtss_trace_io_unregister(&pTIO->trace_reg);
            pTIO->trace_registered = FALSE;
            T_DG(VTSS_TRACE_GRP_TELNET, "Telnet session close successfully");
        }
    }
}

#ifdef VTSS_SW_OPTION_AUTH
BOOL cli_io_telnet_login(struct cli_iolayer *pIO)
{
    return cli_io_login(pIO, VTSS_APPL_AUTH_AGENT_TELNET, CLI_PASSWD_CHAR_TIMEOUT);
}
#endif /* VTSS_SW_OPTION_AUTH */

static cli_io_telnet_t cli_io_telnet[CLI_TELNET_MAX_CLIENT];


static cli_io_telnet_t cli_io_telnet_default = {
    /*.base = */{
        /*.io = */{
            /*.cli_init =                */cli_io_telnet_init,
            /*.cli_getch =               */cli_io_telnet_getch,
            /*.cli_vprintf =             */cli_io_telnet_vprintf,
            /*.cli_putchar =             */cli_io_telnet_putchar,
            /*.cli_puts =                */cli_io_telnet_puts,
            /*.cli_flush =               */cli_io_telnet_flush,
            /*.cli_close =               */cli_io_telnet_close,
#if defined(VTSS_SW_OPTION_AUTH)
            /*.cli_login =               */cli_io_telnet_login,
#else
            /*.cli_login =               */NULL,
#endif
            /*.fd =                      */ -1,
            /*.char_timeout =            */CLI_COMMAND_CHAR_TIMEOUT,
            /*.bIOerr                    */FALSE,
            /*.bEcho                     */FALSE,
            /*.cDEL =                    */CLI_DEL_KEY_LINUX, /* Assume telnet from Linux */
            /*.cBS  =                    */CLI_BS_KEY_LINUX,  /* Assume telnet from Linux */
            /*.priv_lvl =                */15,
            /*.authenticated             */FALSE,
#ifdef VTSS_SW_OPTION_ICLI
            /*.icli_session_id =         */0,
            /*.session_way =             */CLI_WAY_TELNET,
#endif /* VTSS_SW_OPTION_ICLI */
        },
    },
};

/*
 * Telnet trace layer
 */

static int telnet_trace_get_child_index(void)
{
    int child_index;
    vtss_handle_t handle;

    handle = vtss_thread_self();
    for (child_index = 0; child_index < CLI_TELNET_MAX_CLIENT; child_index++) {
        if (handle == cli_telnet_child_handle[child_index]) {
            return child_index;
        }
    }
    return -1;
}

static void telnet_trace_putchar(struct _vtss_trace_io_t *pIO, char ch)
{
    int child_index = telnet_trace_get_child_index();
    if (child_index >= 0) {
        cli_io_telnet_putchar(&cli_io_telnet[child_index].base.io, ch);
    } else {
        /* Calling trace macro from other threads (not telnet or ssh) */
        for (child_index = 0; child_index < CLI_TELNET_MAX_CLIENT; child_index++) {
	    /* Modified by yongshangjiang for dup printf when multi telnet sessions */
            if (cli_io_telnet[child_index].trace_reg == pIO->reg_id) {
                (void) cli_io_telnet_putchar(&cli_io_telnet[child_index].base.io, ch);
            }
        }
    }
}

static int telnet_trace_vprintf(struct _vtss_trace_io_t *pIO, const char *fmt, va_list ap)
{
    int child_index = telnet_trace_get_child_index();
    if (child_index >= 0) {
        return cli_io_telnet_vprintf(&cli_io_telnet[child_index].base.io, fmt, ap);
    } else {
        /* Calling trace macro from other threads (not telnet or ssh) */
        for (child_index = 0; child_index < CLI_TELNET_MAX_CLIENT; child_index++) {
	    /* Modified by yongshangjiang for dup printf when multi telnet sessions */
            if (cli_io_telnet[child_index].trace_reg == pIO->reg_id) {
                (void) cli_io_telnet_vprintf(&cli_io_telnet[child_index].base.io, fmt, ap);
            }
        }
    }
    return 1;
}

static void telnet_trace_write_string(struct _vtss_trace_io_t *pIO, const char *str)
{
    int child_index = telnet_trace_get_child_index();
    if (child_index >= 0) {
        cli_io_telnet_puts(&cli_io_telnet[child_index].base.io, str);
    } else {
        /* Calling trace macro from other threads (not telnet or ssh) */
        for (child_index = 0; child_index < CLI_TELNET_MAX_CLIENT; child_index++) {
	    /* Modified by yongshangjiang for dup printf when multi telnet sessions */
	    //if (cli_io_telnet[child_index].base.io.fd >= 0) {
            if (cli_io_telnet[child_index].trace_reg == pIO->reg_id) {
                (void) cli_io_telnet_puts(&cli_io_telnet[child_index].base.io, str);
            }
        }
    }
}

static void telnet_trace_write_string_len(struct _vtss_trace_io_t *pIO, const char *str, unsigned length)
{
    int child_index = telnet_trace_get_child_index();
    if (child_index >= 0) {
        cli_io_telnet_puts_len(&cli_io_telnet[child_index].base.io, str, length);
    } else {
        /* Calling trace macro from other threads (not telnet or ssh) */
        for (child_index = 0; child_index < CLI_TELNET_MAX_CLIENT; child_index++) {
	    /* Modified by yongshangjiang for dup printf when multi telnet sessions */
	    //if (cli_io_telnet[child_index].base.io.fd >= 0) {
            if (cli_io_telnet[child_index].trace_reg == pIO->reg_id) {
                (void) cli_io_telnet_puts_len(&cli_io_telnet[child_index].base.io, str, length);
            }
        }
    }
}

static void telnet_trace_flush(struct _vtss_trace_io_t *pIO)
{
    int child_index = telnet_trace_get_child_index();
    if (child_index >= 0) {
        cli_io_telnet_flush(&cli_io_telnet[child_index].base.io);
    } else {
        /* Calling trace macro from other threads (not telnet or ssh) */
        for (child_index = 0; child_index < CLI_TELNET_MAX_CLIENT; child_index++) {
	    /* Modified by yongshangjiang for dup printf when multi telnet sessions */
	    //if (cli_io_telnet[child_index].base.io.fd >= 0) {
            if (cli_io_telnet[child_index].trace_reg == pIO->reg_id) {
                (void) cli_io_telnet_flush(&cli_io_telnet[child_index].base.io);
            }
        }
    }
}

static vtss_trace_io_t telnet_trace_layer[CLI_TELNET_MAX_CLIENT] = {
    {
        .trace_putchar = telnet_trace_putchar,
        .trace_vprintf = telnet_trace_vprintf,
        .trace_write_string = telnet_trace_write_string,
        .trace_write_string_len = telnet_trace_write_string_len,
        .trace_flush = telnet_trace_flush
    },
    {
        .trace_putchar = telnet_trace_putchar,
        .trace_vprintf = telnet_trace_vprintf,
        .trace_write_string = telnet_trace_write_string,
        .trace_write_string_len = telnet_trace_write_string_len,
        .trace_flush = telnet_trace_flush
    },
    {
        .trace_putchar = telnet_trace_putchar,
        .trace_vprintf = telnet_trace_vprintf,
        .trace_write_string = telnet_trace_write_string,
        .trace_write_string_len = telnet_trace_write_string_len,
        .trace_flush = telnet_trace_flush
    },
    {
        .trace_putchar = telnet_trace_putchar,
        .trace_vprintf = telnet_trace_vprintf,
        .trace_write_string = telnet_trace_write_string,
        .trace_write_string_len = telnet_trace_write_string_len,
        .trace_flush = telnet_trace_flush
    }
};

/*
 * CLI Initialization
 */

static void cli_telnet_create_child_thread(int ix)
{
    sprintf(cli_telnet_child_name[ix], "Telnet CLI %01d", ix + 1);

    // Create a child thread, so we can run the scheduler and have time 'pass'
    vtss_thread_create(VTSS_THREAD_PRIO_ABOVE_NORMAL,            // Priority
                       cli_thread,                               // entry
                       (vtss_addrword_t)&cli_io_telnet[ix].base, // entry parameter
                       cli_telnet_child_name[ix],                // Name
                       nullptr,                                  // Stack
                       0,                                        // Size
                       &cli_telnet_child_handle[ix],             // Handle
                       &cli_telnet_child_data[ix]                // Thread data structure
                      );

    //    vtss_thread_resume(cli_telnet_child_handle[ix]);             // Start it
}

static void cli_telnet_port_open_close(void)
{
#ifdef VTSS_SW_OPTION_AUTH
    vtss_appl_auth_authen_agent_conf_t c;
    if (vtss_appl_auth_authen_agent_conf_get(VTSS_APPL_AUTH_AGENT_TELNET, &c) != VTSS_RC_OK) {
        T_WG(VTSS_TRACE_GRP_TELNET, "vtss_appl_auth_authen_agent_conf_get(telnet) failed");
    } else {
        if (c.method[0] == VTSS_APPL_AUTH_AUTHEN_METHOD_NONE) {
            vtss_flag_maskbits(&cli_telnet_parent_flag, ~CLI_TELNET_FLAG_RUNNING);
            T_DG(VTSS_TRACE_GRP_TELNET, "Event clear CLI_TELNET_FLAG_RUNNING");
        } else {
            vtss_flag_setbits(&cli_telnet_parent_flag, CLI_TELNET_FLAG_RUNNING);
            T_DG(VTSS_TRACE_GRP_TELNET, "Event set CLI_TELNET_FLAG_RUNNING");
        }
    }
#else
    vtss_flag_setbits(&cli_telnet_parent_flag, CLI_TELNET_FLAG_RUNNING);
    T_DG(VTSS_TRACE_GRP_TELNET, "Event set CLI_TELNET_FLAG_RUNNING");
#endif /* VTSS_SW_OPTION_AUTH */
}

#define CLI_TELNET_BUF_SIZE     64

static void cli_telnet(vtss_addrword_t data)
{
    int                     s = -1;
    int                     conn = -1;
    socklen_t               client_len;
    struct sockaddr_in      client_addr, local;
    int                     i,
                            one = 1;
    int                     found_empty;
    fd_set                  rfds;
    i32                     rc;
    i32                     fdmax;
#ifdef VTSS_SW_OPTION_IPV6
    int                     s6 = -1;
    int                     conn_v6 = -1;
    socklen_t               client_len_v6;
    struct sockaddr_in6     client_addr_v6, local_v6;
#endif /* VTSS_SW_OPTION_IPV6 */
    vtss_flag_value_t       received_flags;
    BOOL                    is_running;
    mesa_bool_t             is_just_start = true;

    msg_wait(MSG_WAIT_UNTIL_MASTER_UP_POST, VTSS_MODULE_ID_CLI);
    cli_telnet_port_open_close();
    while (TRUE) {
        received_flags = vtss_flag_wait(&cli_telnet_parent_flag, CLI_TELNET_FLAG_RUNNING, VTSS_FLAG_WAITMODE_OR);
        is_running = (received_flags & CLI_TELNET_FLAG_RUNNING) ? TRUE : FALSE;
        T_DG(VTSS_TRACE_GRP_TELNET, "Opening telnet sockets");

        /* Add by yongshangjiang for Bug#1973 */
        if (is_just_start) {
            T_DG(VTSS_TRACE_GRP_TELNET, "System just start, waiting for 10s to telnet");
            VTSS_OS_MSLEEP(10000);
            is_just_start = false;
        }

        /* for IPv4 */
        s = vtss_socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            PEXIT("IPv4 CLI telnet stream socket");
        }
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
            PEXIT("IPv4 CLI telnet setsockopt SO_REUSEADDR");
        }
        if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one))) {
            PEXIT("IPv4 CLI telnet setsockopt SO_REUSEPORT");
        }
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_port = htons(CLI_TELNET_PORT);
        local.sin_addr.s_addr = INADDR_ANY;
        while (bind(s, (struct sockaddr *) &local, sizeof(local)) < 0) {
            T_DG(VTSS_TRACE_GRP_TELNET, "bind error IPv4, sleeping");
            VTSS_OS_MSLEEP(3000);
        }
        (void)listen(s, CLI_TELNET_MAX_CLIENT);
        FD_ZERO(&rfds);
        fdmax = s;

#ifdef VTSS_SW_OPTION_IPV6
        /* for IPv6 */
        s6 = vtss_socket(AF_INET6, SOCK_STREAM, 0);
        if (s6 < 0) {
            PEXIT("IPv6 CLI telnet stream socket");
        }
        if (setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one))) {
            PEXIT("IPv6 CLI telnet setsockopt IPV6_V6ONLY");
        }
        if (setsockopt(s6, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
            PEXIT("IPv6 CLI telnet setsockopt SO_REUSEADDR");
        }
        if (setsockopt(s6, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one))) {
            PEXIT("IPv6 CLI telnet setsockopt SO_REUSEPORT");
        }
        memset(&local_v6, 0, sizeof(local_v6));
        local_v6.sin6_family = AF_INET6;
        local_v6.sin6_port = htons(CLI_TELNET_PORT);
        while (bind(s6, (struct sockaddr *) &local_v6, sizeof(struct sockaddr_in6)) < 0) {
            T_DG(VTSS_TRACE_GRP_TELNET, "bind error IPv6, sleeping");
            VTSS_OS_MSLEEP(3000);
        }
        (void)listen(s6, CLI_TELNET_MAX_CLIENT);
        fdmax = MAX(s, s6);
#endif /* VTSS_SW_OPTION_IPV6 */

        while (is_running) {
            /* Disable wrong lint warnings for FD_SET() and FD_ISSET() in this block */
            /*lint --e{573,661,662} */
            FD_SET(s, &rfds);
#ifdef VTSS_SW_OPTION_IPV6
            FD_SET(s6, &rfds);
#endif /* VTSS_SW_OPTION_IPV6 */
            struct timeval tv = {3, 0};
            rc = select(fdmax + 1, &rfds, NULL, NULL, &tv);
            if ((rc > 0) && (FD_ISSET(s, &rfds))) {
                /* for IPv4 */
                client_len = sizeof(client_addr);
                if ((conn = vtss_accept(s, (struct sockaddr *)&client_addr, &client_len)) < 0) {
                    PEXIT("accept");
                }
                T_IG(VTSS_TRACE_GRP_TELNET, "connection(%d) from %s:%d", conn, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

                /* Notice if connection break */
                if (setsockopt(conn, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one))) {
                    PEXIT("setsockopt");
                }

                if (telnet_security_mode) {
                    const char *buf = "This device's Telnet is disabled, please use the SSH instead of Telnet.\r\n";
                    T_IG(VTSS_TRACE_GRP_TELNET, "Extra connection(%d) from %s:%d", conn,
                         inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    write(conn, buf, strlen(buf));
                    VTSS_OS_MSLEEP(50);  /* Allow to drain */
                    close(conn);
                    conn = -1;
                } else {
                    /* Found empty entry */
                    found_empty = 0;
                    for (i = 0; i < CLI_TELNET_MAX_CLIENT; i++) {
                        if (!cli_io_telnet[i].valid) {
                            cli_iolayer_t *pIO = &cli_io_telnet[i].base.io;

                            found_empty = 1;
                            cli_io_telnet[i].valid = TRUE;
                            cli_io_telnet[i].base.io.fd = conn;
                            cli_io_telnet[i].listen_fd = s;

                            /* cli_io_telnet_init() will register trace */
			    /* Modified by yongshangjiang for dup printf when multi telnet sessions */
                            //cli_io_telnet[i].trace_layer = &telnet_trace_layer;
			    cli_io_telnet[i].trace_layer = &telnet_trace_layer[i];

                            /* Send initial options */
                            write(conn, telnet_opts, sizeof(telnet_opts));

                            /* Save client address */
                            pIO->client_ip.type      = MESA_IP_TYPE_IPV4;
                            pIO->client_ip.addr.ipv4 = ntohl(client_addr.sin_addr.s_addr);
                            pIO->client_port         = ntohs(client_addr.sin_port);

                            /* Borrow thread - code only */
                            cli_telnet_create_child_thread(i);
                            break;
                        }
                    }

                    if (found_empty == 0) {
                        static char *buf;
                        T_IG(VTSS_TRACE_GRP_TELNET, "Extra connection(%d) from %s:%d", conn,
                             inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                        if ((VTSS_MALLOC_CAST(buf, CLI_TELNET_BUF_SIZE + 1))) {
                            int len = snprintf( buf, CLI_TELNET_BUF_SIZE,
                                                "Only %d connections allowed.\r\n",
                                                CLI_TELNET_MAX_CLIENT);
                            write(conn, buf, len);
                            VTSS_OS_MSLEEP(50);  /* Allow to drain */
                            VTSS_FREE(buf);
                        }
                        close(conn);
                        conn = -1;
                    }
                }
            }
#ifdef VTSS_SW_OPTION_IPV6
            else if ((rc > 0) && (FD_ISSET(s6, &rfds))) {
                /* for IPv6 */
                client_len_v6 = sizeof(client_addr_v6);
                if ((conn_v6 = vtss_accept(s6, (struct sockaddr *)&client_addr_v6, &client_len_v6)) < 0) {
                    PEXIT("accept");
                }

                if (telnet_security_mode) {
                    const char *buf = "This device's Telnet is disabled, please use the SSH instead of Telnet.\r\n";
                    write(conn_v6, buf, strlen(buf));
                    VTSS_OS_MSLEEP(50);  /* Allow to drain */
                    close(conn_v6);
                    conn_v6 = -1;
                } else {
                    /* Found empty entry */
                    found_empty = 0;
                    for (i = 0; i < CLI_TELNET_MAX_CLIENT; i++) {
                        if (!cli_io_telnet[i].valid) {
                            cli_iolayer_t *pIO = &cli_io_telnet[i].base.io;

                            found_empty = 1;
                            cli_io_telnet[i].valid = TRUE;
                            cli_io_telnet[i].base.io.fd = conn_v6;
                            cli_io_telnet[i].listen_fd = s6;

                            /* cli_io_telnet_init() will register trace */
			    /* Modified by yongshangjiang for dup printf when multi telnet sessions */
                            //cli_io_telnet[i].trace_layer = &telnet_trace_layer;
			    cli_io_telnet[i].trace_layer = &telnet_trace_layer[i];

                            /* Send initial options */
                            write(conn_v6, telnet_opts, sizeof(telnet_opts));

                            /* Save client address */
                            pIO->client_ip.type      = MESA_IP_TYPE_IPV6;
                            memcpy(pIO->client_ip.addr.ipv6.addr, client_addr_v6.sin6_addr.s6_addr, sizeof(mesa_ipv6_t));
                            pIO->client_port         = ntohs(client_addr_v6.sin6_port);

                            /* Borrow thread - code only */
                            cli_telnet_create_child_thread(i);
                            break;
                        }
                    }

                    if (!found_empty) {
                        static char *buf;
                        if ((VTSS_MALLOC_CAST(buf, CLI_TELNET_BUF_SIZE + 1))) {
                            int len = snprintf(buf, CLI_TELNET_BUF_SIZE,
                                               "Only %d connections allowed.\r\n",
                                               CLI_TELNET_MAX_CLIENT);
                            write(conn_v6, buf, len);
                            VTSS_OS_MSLEEP(50);  /* Allow to drain */
                            VTSS_FREE(buf);
                        }
                        close(conn_v6);
                        conn_v6 = -1;
                    }
                }
            }
            fdmax = MAX(s , s6);
#endif /* VTSS_SW_OPTION_IPV6 */
            received_flags = vtss_flag_peek(&cli_telnet_parent_flag);
            is_running = (received_flags & CLI_TELNET_FLAG_RUNNING) ? TRUE : FALSE;
            T_NG(VTSS_TRACE_GRP_TELNET, "Checking CLI_TELNET_FLAG_RUNNING is %i", is_running);
        }
        T_DG(VTSS_TRACE_GRP_TELNET, "Closing telnet sockets");
        if (s >= 0) {
            close(s);
            s = -1;
        }
#ifdef VTSS_SW_OPTION_IPV6
        if (s6 >= 0) {
            close(s6);
            s6 = -1;
        }
#endif /* VTSS_SW_OPTION_IPV6 */
    }
}

static void cli_telnet_do_close(mesa_restart_t restart)
{
    int i, active = 0;
    cli_telnet_port_open_close();
    for (i = 0; i < CLI_TELNET_MAX_CLIENT; i++) {
        if (cli_io_telnet[i].valid && cli_io_telnet[i].base.io.authenticated) {
            cli_io_telnet[i].base.io.bIOerr = TRUE; /* Force all sessions to terminate themselves */
            active++;
        }
    }
    if (active) {
        T_IG(VTSS_TRACE_GRP_TELNET, "%d Telnet session%s terminated!", active, (active > 1) ? "s" : "");
        VTSS_OS_MSLEEP(CLI_GETCH_WAKEUP * 2); /* Give the sessions a little time to terminate */
    }
    /*
     * We have previously called vtss_thread_delete() when we want to force a thread to be closed.
     * This will remove the thread on the scheduler list (and make it impossible to query the thread for e.g stack usage).
     * It will NOT free any memory that is assigned to the thread, as it is statically allocated.
     * It is perfectly ok to recreate a cli thread using the existing handle.
     */
}

void cli_telnet_close(void)
{
    cli_telnet_do_close(MESA_RESTART_COLD /* Unused */);
}

void cli_telnet_start(void)
{
    int i;

    // Set default configuration
    for (i = 0; i < CLI_TELNET_MAX_CLIENT; i++) {
        memset(&cli_io_telnet[i], 0, sizeof(cli_io_telnet[i]));
        cli_io_telnet[i] = cli_io_telnet_default;
    }

    vtss_flag_init(&cli_telnet_parent_flag);

    // Get warning about system resets
    control_system_reset_register(cli_telnet_do_close);

	#if 1 //modify by sps 有异常
    // Create a main thread, so we can run the scheduler and have time 'pass'
    vtss_thread_create(VTSS_THREAD_PRIO_DEFAULT,                // Priority
                       (vtss_thread_entry_f *)cli_telnet,       // entry
                       0,                                       // entry parameter
                       "Telnet CLI Main",                       // Name
                       nullptr,                                 // Stack
                       0,                                       // Size
                       &cli_telnet_parent_thread_handle,        // Handle
                       &cli_telnet_parent_thread_data           // Thread data structure
                      );

    //    vtss_thread_resume(cli_telnet_parent_thread_handle);        // Start it
	#endif 
}

#ifdef TELNET_SECURITY_SUPPORTED
/* Set TELNET security mode. When secrity mode is enabled,
   we should use the SSH instead of Telnet and disconnect all existing telnet sessions */
void cli_io_telnet_set_security_mode(mesa_bool_t security_mode)
{
    telnet_security_mode = security_mode;
    if (security_mode) {
        cli_telnet_close(); //disconnect all existing telnet sessions
    }
}

mesa_bool_t cli_io_telnet_get_security_mode()
{
    return telnet_security_mode;
}

#endif /* TELNET_SECURITY_SUPPORTED */

