/* ipset.c is Copyright (c) 2013 Jason A. Donenfeld <Jason@zx2c4.com>. All
   Rights Reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dnsmasq.h"

#if defined(HAVE_NFSET) && defined(HAVE_LINUX_NETWORK)

#include <arpa/inet.h>
#include <errno.h>
#include <linux/version.h>
#include <nftables/libnftables.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>

#define MAX_TTL 4 * 60 * 60
#define MIN_TTL 30 * 60

struct nft_ctx *ctx = NULL;

const char nft_ipv4[] = "ipv4 ";
const char nft_ipv6[] = "ipv6 ";
const char nft_cmd_add[] = "add element %s { %s timeout %ds }";

#define CMD_BUFFER_SIZE 4096
char cmd_buffer[CMD_BUFFER_SIZE];

char addr_buffer[ADDRSTRLEN + 1];



static int start_with(const char *s, const char *prefix) {
  return strncmp(prefix, s, strlen(prefix)) == 0;
}

void nfset_init() {
  ctx = nft_ctx_new(NFT_CTX_DEFAULT);
  if (ctx == NULL) exit(EXIT_FAILURE);

  // Catch Command output and errors internally, don;t send to stdout or stderr
  nft_ctx_buffer_output(ctx);
  nft_ctx_buffer_error(ctx);
}

int is_nfset(const char* setname) {
  return start_with(setname, nft_ipv4) || start_with(setname, nft_ipv6);
}

int add_to_nfset(const char *setname, const union all_addr *ipaddr,
                 int flags, int remove, int ttl) {

  (void)remove; // Unused

  int sent = 0;
  int rc = 0;
  int priority = LOG_DEBUG;
  const char *out = NULL;
  const char *err = NULL;


  // Bound ttl into this range.
  ttl = ttl < MIN_TTL ? MIN_TTL : ttl;
  ttl = ttl > MAX_TTL ? MAX_TTL : ttl;

  if (flags & F_IPV4) {
    if (start_with(setname, nft_ipv4)) {
      const char *real_setname = setname + strlen(nft_ipv4);
      inet_ntop(AF_INET, ipaddr, addr_buffer, ADDRSTRLEN);
      snprintf(cmd_buffer, CMD_BUFFER_SIZE, nft_cmd_add, real_setname, addr_buffer, ttl);
      rc = nft_run_cmd_from_buffer(ctx, cmd_buffer);
      sent = 1;
    }
  } else if (flags & F_IPV6) {
    if (start_with(setname, nft_ipv6)) {
      const char *real_setname = setname + strlen(nft_ipv6);
      inet_ntop(AF_INET6, ipaddr, addr_buffer, ADDRSTRLEN);
      snprintf(cmd_buffer, CMD_BUFFER_SIZE, nft_cmd_add, real_setname, addr_buffer, ttl);
      rc = nft_run_cmd_from_buffer(ctx, cmd_buffer);
      sent = 1;
    }
  }

  if (sent == 1) {
    // Always get the command output and error, to clear it.
    out = nft_ctx_get_output_buffer(ctx);
    err = nft_ctx_get_error_buffer(ctx);

    // If we got any command output, increase our debug log to Info so its obvious.
    if (strlen(out)) {
      priority = LOG_INFO;
    }

    // If we get a bad status of error message, increase to error, so its really really obvious.
    if ((rc != 0) || (strlen(err))) {
      priority = LOG_ERR;
    }

    my_syslog(priority, _("nft set update `%s` : %d : %s : %s"), cmd_buffer, rc, out, err);
  }

  return 0;
}

#endif
