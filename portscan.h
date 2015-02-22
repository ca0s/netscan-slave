#ifndef __H_PORTSCAN__
#define __H_PORTSCAN__

#include "head.h"

void scan_port (int, struct sockaddr *, struct t_port_s *, struct t_host_s **);
int can_connect (int, struct sockaddr *);
char *recvline (int);
void set_socket_timeout (int, int, int);
int open_socket ();

struct t_host_s *new_host (struct in_addr *);
struct t_service_s *new_service (int, struct t_service_s *);

#endif
