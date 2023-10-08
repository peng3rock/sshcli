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

#include "cli_io_api.h"  /* For CLI_STACK_SIZE */
#include "critd_api.h"
#include "cli_trace_def.h"
#include "mgmt_api.h"
#include "sysutil_api.h" /* For VTSS_SYS_USERNAME_LEN */
#include <sys/param.h>
#include <fcntl.h>
#include <sys/socket.h>

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

#include <termios.h> /* For terminal raw mode */

void err_sys(const char *x)
{
    perror(x);
    exit(1);
}

static void cli_io_serial_init(cli_iolayer_t *pIO)
{
    pIO->bIOerr = FALSE;
    pIO->authenticated = FALSE;

    struct termios raw_mode;

    memset(&raw_mode, 0, sizeof(raw_mode));
    tcgetattr(STDIN_FILENO, &raw_mode);
    cfmakeraw(&raw_mode);
    raw_mode.c_oflag |= OPOST;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw_mode);
}

static int cli_io_serial_getch(cli_iolayer_t *pIO, int timeout, char *ch)
{
    int rc;
    T_N("Serial timeout %d", timeout);
    pIO->fd = STDIN_FILENO;
    rc = cli_io_getch(pIO, timeout, ch);
    if (rc == VTSS_OK) {
        T_N("Serial got char '%c' (%u)", ((*ch > 31) && (*ch < 127)) ? *ch : '?', (u8)*ch);
    } else {
        T_N("Serial err %s (%d)", error_txt(rc), rc);
    }
    return rc;
}

static int cli_io_serial_vprintf(cli_iolayer_t *pIO, const char *fmt, va_list ap)
{
    int l = vprintf(fmt, ap);
    (void) fflush(stdout);
    return l;
}

static void cli_io_serial_putchar(cli_iolayer_t *pIO, char ch)
{
    putchar(ch);
    (void) fflush(stdout);
}

static void cli_io_serial_puts(cli_iolayer_t *pIO, const char *str)
{
    while (*str) {
        pIO->cli_putchar(pIO, *str++);
    }
}

static void cli_io_serial_flush(cli_iolayer_t *pIO)
{
    (void) fflush(stdout);
}

static void cli_io_serial_close(cli_iolayer_t *pIO)
{
    pIO->bIOerr = TRUE;
    pIO->client_ip.type = MESA_IP_TYPE_NONE;
    pIO->client_port = 0;
#ifdef VTSS_SW_OPTION_AUTH
    pIO->agent_id = 0;
#endif /* VTSS_SW_OPTION_AUTH */
}

#ifdef VTSS_APPL_AUTH_ENABLE_CONSOLE
static BOOL cli_io_serial_login(cli_iolayer_t *pIO)
{
    return cli_io_login(pIO, VTSS_APPL_AUTH_AGENT_CONSOLE, CLI_NO_CHAR_TIMEOUT);
}
#endif /*  VTSS_APPL_AUTH_ENABLE_CONSOLE */

static cli_io_t cli_io_serial = {
    /*.io = */{
        /*.cli_init = */                cli_io_serial_init,
        /*.cli_getch = */               cli_io_serial_getch,
        /*.cli_vprintf = */             cli_io_serial_vprintf,
        /*.cli_putchar = */             cli_io_serial_putchar,
        /*.cli_puts = */                cli_io_serial_puts,
        /*.cli_flush = */               cli_io_serial_flush,
        /*.cli_close = */               cli_io_serial_close,
#ifdef VTSS_APPL_AUTH_ENABLE_CONSOLE
        /*.cli_login = */               cli_io_serial_login,
#else
        /*.cli_login = */               0,
#endif /*  VTSS_APPL_AUTH_ENABLE_CONSOLE */
        /*.fd = */ -1,
        /*.char_timeout = */            CLI_NO_CHAR_TIMEOUT,
        /*.bIOerr = */                  0,
        /*.bEcho = */                   TRUE,
        /*.cDEL = */                    CLI_DEL_KEY_WINDOWS, /* Assume serial from Windows */
        /*.cBS  = */                    CLI_BS_KEY_WINDOWS,  /* Assume serial from Windows */
        /*.priv_lvl = */                15,
        /*.authenticated = */           0,
#ifdef VTSS_SW_OPTION_ICLI
        /*.icli_session_id = */         0,
        /*.session_way = */             CLI_WAY_CONSOLE,
#endif /* VTSS_SW_OPTION_ICLI */
    },
};

cli_io_t *vtss_appl_cli_console_io_get()
{
    return &cli_io_serial;
}

// Close the serial CLI session and force the user to login again
void cli_serial_close(void)
{
    if (cli_io_serial.io.authenticated) {
        cli_io_serial.io.bIOerr = TRUE; // Force a reauthentication
    }
}

cli_iolayer_t *cli_get_serial_io_handle(void)
{
    return &cli_io_serial.io;
}
