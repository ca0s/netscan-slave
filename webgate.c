#define _GNU_SOURCE		// asprintf
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <jansson.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "webgate.h"
#include "portscan.h"
#include "util.h"

struct t_string_s *send_data (struct sockaddr_in *dest, char *data, unsigned int len,
												struct t_list_s **headers_back)
{
	int sock;
	int delay = 1;
	int i = 0;
	struct t_string_s *res = string_new ();
	static char *buf;
	char *head_value;

	//printf ("Sending:\n%s\n", data);

	if (headers_back) {
		*headers_back = new_list ();
	}
	
	sock = socket (AF_INET, SOCK_STREAM, 0);
	while (!can_connect (sock, (struct sockaddr *) dest)) {
		close (sock);
		if (delay < 300) {
			delay*=2;
		}
		sleep (delay);
		sock = socket (AF_INET, SOCK_STREAM, 0);
	}
	
	while (i < len) {
		i += send (sock, data + i, len - i, 0);
	}

	i = 0;
	while (strlen ((buf = recvline (sock))) > 0) {
		if (i) {
			string_cat_data (res, buf, strlen (buf));
		} else if (buf[0] == '\r') {
			i = 1;
		} else if (headers_back) {
			head_value = strchr (buf, ':');
			if (head_value) {
				*head_value = 0x00;
				head_value++;
				while (*head_value == ' ') {
					head_value++;
				}
				append_list_element (
					headers_back,
					new_http_header (buf, head_value),
					LIST_ASSIGN,
					0);
			}
		}
	}
	
	close (sock);
	return res;
}

struct t_string_s *send_get (struct sockaddr_in *dest, char *path,
								char *cookie,
								struct t_list_s **headers_back)
{
	char *buf = NULL;
	int i;
	struct t_string_s *res;
	
	i = asprintf (&buf, "GET /%s HTTP/1.0%s%s\r\n\r\n",
						path,
						(cookie)?"\r\nCookie: ":"",
						(cookie)?cookie:"");
	res = send_data (dest, buf, i, headers_back);

	free (buf);
	return res;
}

struct t_string_s *send_post (struct sockaddr_in *dest, char *path,
						struct t_list_s *heads, char *data,
						struct t_list_s **headers_back)
{
	char *buf = NULL;
	struct t_string_s *str, *res;
	int i;
	
	i = asprintf (&buf, "POST /%s HTTP/1.0\r\n", path);
	str = string_new ();
	string_set (str, buf, i);
	free (buf);
	
	while (heads) {
		if (heads->data) {
			i = asprintf (&buf, "%s: %s\r\n", 
							((struct t_http_header_s *)heads->data)->header, 
							((struct t_http_header_s *)heads->data)->value);
			string_cat_data (str, buf, i);
			free (buf);
		}
		heads = heads->next;
	}

	string_cat_data (str, data, strlen (data));
	
	res = send_data (dest, str->data, str->len, headers_back);
	string_free (str);
	return res;
}

struct t_list_s *get_targets_list (char *json, unsigned int *count, char **job_id)
{
	struct t_list_s *targets = NULL;
	json_t *root;
	json_t *ips;
	json_t *ip;
	json_t *val;
	json_t *id;
	size_t i, n;
	char *ipstr;
	char *job_id_tmp;
	unsigned int c = 0;
	
	root = json_loads (json, 0, NULL);
	if (root) {
		id = json_object_get (root, "ID");
		if (id && json_is_string (id)) {
			json_unpack (id, "s", &job_id_tmp);
			*job_id = malloc (strlen (job_id_tmp) + 1);
			strcpy (*job_id, job_id_tmp);
			ips = json_object_get (root, "IPs");
			if (ips) {
				n = json_array_size (ips);
				if (n > 0) {
					for (i = 0; i < n; i++) {
						ip = json_array_get (ips, i);
						if (ip) {
							val = json_object_get (ip, "Address");
							if (val) {
								if (json_is_string (val)) {
									json_unpack (val, "s", &ipstr);
									append_list_element (&targets, ipstr, LIST_COPY, strlen (ipstr) + 1);
									++c;
								}
							}
						}
					}
				}
			}
		}
		json_decref (root);
	} else {
		printf ("Error: invalid JSON\n");
	}
	//printf ("Got %u IPs\n", c);
	if (count) {
		*count = c;
	}
	return targets;
}

struct t_list_s *get_targets (char *master, unsigned int n, unsigned int *count, char **id, char *cookie)
{
	struct t_list_s *targets = NULL;
	struct t_string_s *retstr = NULL;
	char *reqstr = NULL;
	struct sockaddr_in sa;

	printf ("Getting targets from %s...\n", master);
	
	sa = (struct sockaddr_in) {
		.sin_port = htons (5000),
		.sin_family = AF_INET
	};

	if (inet_pton (AF_INET, master, &sa.sin_addr) <= 0) {
		printf ("\terror\n");
		return NULL;
	}
	
	asprintf (&reqstr, "get/%u", n);
	retstr = send_get (&sa, reqstr, cookie, NULL);
	
	targets = get_targets_list (retstr->data, count, id);
	
	free (reqstr);
	string_free (retstr);
	return targets;
}

char *do_auth (char *master, char *user, char *pass)
{
	struct t_list_s *headers = NULL;
	char *data, /**urlencoded,*/ *datalen;
	struct t_string_s *res;
	struct sockaddr_in sa;
	struct t_list_s *headers_back = NULL;
	struct t_list_s *tmp;
	char *cookie = NULL;
	int len;
	
	sa = (struct sockaddr_in) {
		.sin_port = htons (5000),
		.sin_family = AF_INET
	};

	inet_pton (AF_INET, master, &sa.sin_addr);

	asprintf (&data, "\r\nusername=%s&password=%s", user, pass);
	//urlencoded = url_encode (data);

	headers = new_list ();
	append_list_element (
		&headers,
		new_http_header ("Content-type", "application/x-www-form-urlencoded"),
		LIST_ASSIGN,
		0);
	append_list_element (
		&headers,
		new_http_header ("Accept", "text/plain"),
		LIST_ASSIGN,
		0);
	asprintf (&datalen, "%u", (unsigned int) strlen (data) - 2);
	append_list_element (
		&headers,
		new_http_header ("Content-length", datalen),
		LIST_ASSIGN,
		0);

	printf ("Authenticating with master... ");
	res = send_post (&sa, "login/", headers, data, &headers_back);
	printf ("%s\n", res->data);

	tmp = headers_back;
	while (tmp && 1) {
		if (tmp->data && !strcmp ( ((struct t_http_header_s *)tmp->data)->header, "Set-Cookie")) {
			//extract_cookie (((struct t_http_header_s *)tmp->data)->value, &cookie);
			len = strlen (((struct t_http_header_s *)tmp->data)->value);
			cookie = malloc (len);
			memcpy (cookie, ((struct t_http_header_s *)tmp->data)->value, len-1);
			cookie[len-1] = 0x00;
			break;
		}
		tmp = tmp->next;
	}

	printf (" got cookie: %s\n", cookie);

	free (data);
	//free (urlencoded);
	free (datalen);
	string_free (res);
	free_list_cb (headers, free_http_header);
	free_list_cb (headers_back, free_http_header);

	return cookie;
}

int send_results (char *master, json_t *results, char *cookie)
{
	struct t_list_s *headers;
	struct t_string_s *res;
	char *json_txt;
	//char *urlencoded;
	char *data;
	char *datalen;
	struct sockaddr_in sa;
	
	sa = (struct sockaddr_in) {
		.sin_port = htons (5000),
		.sin_family = AF_INET
	};

	inet_pton (AF_INET, master, &sa.sin_addr);
	
	json_txt = json_dumps (results, 0);
	//urlencoded = url_encode (json_txt);
	//asprintf (&data, "\r\n%s", urlencoded);	
	asprintf (&data, "\r\n%s", json_txt);

	headers = new_list ();
	append_list_element (
		&headers,
		new_http_header ("Content-type", "application/json"),
		LIST_ASSIGN,
		0);
	append_list_element (
		&headers,
		new_http_header ("Accept", "text/plain"),
		LIST_ASSIGN,
		0);
	asprintf (&datalen, "%u", (unsigned int) strlen (data) - 2);
	append_list_element (
		&headers,
		new_http_header ("Content-length", datalen),
		LIST_ASSIGN,
		0);
	append_list_element (
		&headers,
		new_http_header ("Cookie", cookie),
		LIST_ASSIGN,
		0);
	
	printf ("Sending results... ");
	res = send_post (&sa, "save/", headers, data, NULL);
	printf ("%s\n", res->data);
	
	string_free (res);
	free_list_cb (headers, free_http_header);
	free (data);
	free (json_txt);
	//free (urlencoded);
	free (datalen);
	
	return 0;
}

struct t_http_header_s *new_http_header (char *header, char *value)
{
	struct t_http_header_s *new = malloc (sizeof (struct t_http_header_s));
	int lh = strlen (header);
	int lv = strlen (value);
	
	new->header = malloc (lh + 1);
	memcpy (new->header, header, lh);
	new->header[lh] = 0x00;
	
	new->value = malloc (lv + 1);
	memcpy (new->value, value, lv);
	new->value[lv] = 0x00;
	
	return new;
}

void free_http_header (void *vheader)
{
	struct t_http_header_s *header = vheader;
	free (header->header);
	free (header->value);
	free (header);
}
