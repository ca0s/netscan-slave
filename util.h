#ifndef __H_UTIL__
#define __H_UTIL__

#include <stdint.h>
#include <netinet/in.h>
#include <libcidr.h>

uint64_t cidr_num_hosts (CIDR *cidr);
void ipv4_inc (struct in_addr *addr, uint8_t *mask);
void ipv4_sum (struct in_addr *addr, uint64_t n, uint8_t *mask);
uint64_t mcd (uint64_t a, uint64_t b);
uint64_t buscar_coprimo (uint64_t p);

char to_hex(char code);
char *url_encode(char *str);

int line_match (char *, char *);
void extract_cookie (char *str, char **ret);

void breakpoint ();

#endif
