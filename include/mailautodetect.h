/* C ABI of mailautodetect's built-in provider table (cargo features "capi" + "ispdb"; src/capi.rs).
 * Answers are lent to the visitor for the duration of the call; the caller frees nothing. */
#ifndef MAILAUTODETECT_H
#define MAILAUTODETECT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UTF-8 bytes, not NUL-terminated. */
typedef struct mailautodetect_str {
  const char* ptr;
  size_t len;
} mailautodetect_str;

enum { MAILAUTODETECT_IMAP = 0, MAILAUTODETECT_SMTP = 1 };
enum { MAILAUTODETECT_SSL = 0, MAILAUTODETECT_STARTTLS = 1, MAILAUTODETECT_PLAIN = 2 };

typedef struct mailautodetect_server {
  uint8_t protocol; /* MAILAUTODETECT_IMAP / _SMTP */
  uint8_t socket;   /* MAILAUTODETECT_SSL / _STARTTLS / _PLAIN */
  uint16_t port;    /* IMAP 993/143, SMTP 465/587 */
  bool oauth2;
  mailautodetect_str host;     /* lower-case LDH, %EMAILDOMAIN% substituted */
  mailautodetect_str username; /* template or literal; empty if none */
} mailautodetect_server;

typedef struct mailautodetect_config {
  mailautodetect_str file;    /* the snapshot file that answered */
  mailautodetect_str matched; /* the table domain that matched */
  const mailautodetect_server* imap;
  size_t imap_len;
  const mailautodetect_server* smtp;
  size_t smtp_len;
} mailautodetect_config;

typedef void (*mailautodetect_visit)(void* ctx, const mailautodetect_config* config);

/* Direct lookup of a lower-case LDH domain. False (visit not called) when absent or not UTF-8. */
bool mailautodetect_ispdb_lookup(mailautodetect_str domain, mailautodetect_str email_domain,
                                  mailautodetect_visit visit, void* ctx);

/* Lookup by MX (Thunderbird's fetchConfigForMX): the MX host's registrable domain, then one label more. */
bool mailautodetect_ispdb_by_mx(mailautodetect_str mx_host, mailautodetect_str mx_registrable,
                                 mailautodetect_str email_domain, mailautodetect_visit visit, void* ctx);

#ifdef __cplusplus
}
#endif

#endif
