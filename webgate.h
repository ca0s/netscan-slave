#ifndef __H_WEBGATE__
#define __H_WEBGATE__

#include <sys/socket.h>
#include <netinet/in.h>
#include "strings.h"
#include "list.h"

struct t_http_header_s {
	char *header;
	char *value;
};

struct t_http_header_s *new_http_header (char *header, char *value);
void free_http_header (void *vheader);

struct t_string_s *send_data (struct sockaddr_in *dest, char *data,
								unsigned int len, struct t_list_s **);

struct t_string_s *send_post (struct sockaddr_in *dest, char *path,
						struct t_list_s *heads, char *data, struct t_list_s **);
struct t_string_s *send_get (struct sockaddr_in *dest, char *path, char *, struct t_list_s **);

int send_results (char *, json_t *results, char *cookie);
char *do_auth (char *master, char *user, char *pass);

struct t_list_s *get_targets_list (char *json, unsigned int *count, char **id);
struct t_list_s *get_targets (char *master, unsigned int n, unsigned int *count,
								char **id, char *cookie);

#endif
