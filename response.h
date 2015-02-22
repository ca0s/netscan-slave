#ifndef __H_RESPONSE__
#define __H_RESPONSE__

json_t *build_response (struct t_host_s **hosts, unsigned int n, char *id, unsigned int *up);
char *ip2str (uint32_t ip);
char *banner2str (struct t_list_s *banner);
char *proto2str (enum t_proto_e);

#endif
