#include <stdint.h>
#include <libcidr.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "head.h"
#include "util.h"

uint64_t cidr_num_hosts (CIDR *cidr)
{
	return (2 << (((cidr_get_proto (cidr) == CIDR_IPV4)? 31:127) - cidr_get_pflen (cidr))) - 2;
}

void ipv4_inc (struct in_addr *addr, uint8_t *mask)
{
	if (!addr)
		return;
		
	int i, n;

	uint8_t *ip = (uint8_t *) &addr->s_addr;
	
	for (i=3; ((ip[i] == (uint8_t) ~mask[i])) && (i >= 0); i--);
	
	if (mask[i] != 0xFF)
		ip[i]++;
	
	for (n = i + 1; n <= 3; n++)
		ip[n] = 0x00;
}

void ipv4_sum (struct in_addr *addr, uint64_t n, uint8_t *mask)
{
	while (n--)
		ipv4_inc (addr, mask);
}

uint64_t mcd (uint64_t a, uint64_t b)
{
	uint64_t r = 0;
	
	while (a % b) {
		r = a % b;
		a = b;
		b = r;
	}
	
	return b;
}

uint64_t buscar_coprimo (uint64_t p)
{
	uint64_t q = p / 2;
	
	while (q && mcd (p, q) != 1)
		q--;
	
	return q;
}

void breakpoint () {}

int line_match (char *line, char *pattern)
{
	char error[512];
	regex_t regex;
	int ret;
	int matches = 0;
	
	//printf ("Matching %s with\n%s\n", pattern, line);
	
	ret = regcomp (&regex, pattern, REG_EXTENDED|REG_NOSUB|REG_ICASE);
	if (!ret) {
		ret = regexec (&regex, line, 0, NULL, 0);
		if (!ret)
			matches = 1;
		else {
			regerror (ret, &regex, error, 512);
			//printf ("regexec: %s\n", error);
		}
	}
	else {
		regerror (ret, &regex, error, 512);
		//printf ("recgomp: %s\n", error);	
	}
	
	regfree (&regex);
	return matches;
}

/* Converts an integer value to its hex character*/
char to_hex(char code) {
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(char *str) {
  char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
  while (*pstr) {
    if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') 
      *pbuf++ = *pstr;
    else if (*pstr == ' ') 
      *pbuf++ = '+';
    else 
      *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}

void extract_cookie (char *str, char **ret)
{
	char *begin = NULL;
	char *end = NULL;
	char *res = NULL;
	int len;

	begin = strstr (str, "session=\"");
	if (begin) {
		begin += strlen ("session=\"");
		end = strchr (begin, '"');
		if (end) {
			len = end - begin;
			res = malloc (len+ 1);
			memcpy (res, begin, len);
			res[len] = 0x00;
			*ret = res;
		}
	}
}