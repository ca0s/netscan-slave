#include <stdio.h>
#include <jansson.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "head.h"
#include "list.h"
#include "util.h"
#include "response.h"

/*
 * Crea un objeto JSON con toda la información recopilada.
 * Para evitar leaks, importante usar _set_new y _append_new,
 * de ese modo las referencias de los elementos se pasan de un "padre"
 * a otro, en lugar de incrementarse.
 * */
json_t *build_response (struct t_host_s **hosts, unsigned int n, char *job_id, unsigned int *n_up)
{
	json_t *jroot, *jarray, *jhost, *jssoo, *jservices, *jservice, *jid;
	json_t *jclient, *jnips;
	struct t_service_s *service;
	char *banner;
	int nips = n;
	unsigned int up = 0;
	
	jarray = json_array ();
	while (n--) {
		if (hosts[n]) {
			jhost = json_object ();
			
			json_object_set_new (jhost, "Address", json_string (ip2str (hosts[n]->ip.num)));
			json_object_set_new (jhost, "Country", json_string ("XX"));	// XXXXXXXXXXXXXXX
			
			jssoo = json_object ();
			json_object_set_new (jssoo, "type", json_integer (hosts[n]->ssoo.type));
			json_object_set_new (jssoo, "version", json_integer (hosts[n]->ssoo.version.full));
			json_object_set_new (jhost, "ssoo", jssoo);
			
			jservices = json_array ();
			for (service = hosts[n]->services; service; service = service->next) {
				jservice = json_object ();
				json_object_set_new (jservice, "port", json_integer (service->port));
				json_object_set_new (jservice, "proto", json_string (proto2str (service->proto)));
				banner = banner2str (service->banner);
				json_object_set_new (jservice, "banner", json_string (banner));
				free (banner);
				json_array_append_new (jservices, jservice);
			}
			json_object_set_new (jhost, "Services", jservices);
			
			json_array_append_new (jarray, jhost);
			up++;
		}
	}
	
	jid = json_string (job_id);
	jclient = json_string ("ca0s");
	jnips = json_integer (nips);
	
	jroot = json_object ();
	json_object_set_new (jroot, "Results", jarray);
	json_object_set_new (jroot, "ID", jid);
	json_object_set_new (jroot, "Client", jclient);
	json_object_set_new (jroot, "NIPs", jnips);
	
	*n_up = up;
	return jroot;
}

char *ip2str (uint32_t ip)
{
	static char str[INET_ADDRSTRLEN];
	inet_ntop (AF_INET, &ip, str, INET_ADDRSTRLEN);
	return str;
}

char *banner2str (struct t_list_s *banner)
{
	char *str;
	struct t_list_s *tmp;
	unsigned int len = 0;
	
	for (tmp = banner; tmp; tmp = tmp->next) {
		if (tmp->data)
			len += strlen (tmp->data);
	}
	
	++len;
	str = malloc (len);
	memset (str, 0, len);
	
	for (tmp = banner; tmp; tmp = tmp->next) {
		if (tmp->data)
			strcat (str, tmp->data);
	}	
	
	return str;
}

char *proto2str (enum t_proto_e proto)
{
	static char *protocols[] = {
		"HTTP", "FTP", "IRC", "SSH", "UNK"
	};
	
	return protocols[proto];
}
