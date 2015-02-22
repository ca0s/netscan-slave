#ifndef __H_IPSCAN__
#define __H_IPSCAN__

#include <stdint.h>
#include "head.h"

void *scanner (void *);
void get_ip_from_pool (struct t_data_s *, struct in_addr *, unsigned int *, unsigned int *);

unsigned int decrement_and_get (unsigned int *);
void pull_ip (struct in_addr *addr, unsigned int current, struct t_data_s *data);

#endif
