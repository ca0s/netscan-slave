#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>
#include <libcidr.h>
#include <string.h>
#include <jansson.h>
#include <signal.h>
#include <time.h>

#include "head.h"
#include "ipscan.h"
#include "portscan.h"
#include "list.h"
#include "util.h"
#include "response.h"
#include "webgate.h"

#define MAX_TIME 2
#define N_THREADS 400

void free_result (struct t_host_s **res, unsigned int n);
struct in_addr *get_addresses (struct t_list_s *list, unsigned int n);
struct t_list_s *cidr_list (char *range, unsigned int *n);
void sig_stop (int);

unsigned int stop = 0;

pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;

int main (int argc, char *argv[])
{
	unsigned int i, n;
	pthread_t threads[N_THREADS];
	pthread_cond_t threads_running = PTHREAD_COND_INITIALIZER;
	pthread_cond_t manager_running = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t manager_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;
	unsigned int n_running = 0;
	struct t_data_s t_data;
	unsigned int current = 0;
	struct t_host_s **res = NULL;
	json_t *json_res = NULL;
	struct t_list_s *targets = NULL;
	struct in_addr *target_addrs = NULL;
	int satellite = 0;
	char *job_id;
	uint64_t scanned = 0;
	time_t begin, end;
	unsigned int up, tup = 0;
	char *cookie;
	
	char buf[INET_ADDRSTRLEN];
	struct t_service_s *tmp = NULL;
	
	if (argc < 3) {
		fprintf (stderr, 	"%s MODO [MASTER / CIDR]\n"
							"\tMODO:\n"
							"\t\tl\tEscaner local. Espera CIDR\n"
							"\t\ts\tEscaner distribuido. Espera MASTER\n"
							"\tMASTER\tServidor maestro al que conectar\n"
							"\tCIDR\tRango CIDR a escanear\n", argv[0]);
		return -1;
	}

	signal (SIGINT, sig_stop);
	signal (SIGPIPE, SIG_IGN);
	
	switch (argv[1][0]) {
		case 'l':
			targets = cidr_list (argv[2], &n);
			break;
		case 's':
			satellite = 1;
			cookie = do_auth (argv[2], AUTH_USER, AUTH_PASS);
			if (!cookie) {
				printf ("Error: invalid login\n");
				return -1;
			}
			printf ("Authenticated\n");
			break;
		default:
			return -1;
	}

	t_data = (struct t_data_s) {
		.manager_mutex = &manager_mutex,
		.threads_mutex = &threads_mutex,
		.manager_running = &manager_running,
		.threads_running = &threads_running,
		.stop = &stop,
		.current = &current,
		.n_running = &n_running
	};
	
	time (&begin);

	for (i = 0; i < N_THREADS; i++) {
		pthread_create (&threads[i], NULL, scanner, &t_data);
	}

	do {
		if (satellite) {
			targets = get_targets (argv[2], (unsigned int) 800, &n, &job_id, cookie);
			if (!targets) {
				break;
			}
			printf ("Job ID: %s\nIPs: %i\n", job_id, n);
		} else {
			stop = 1;
		}
		//dump_list (targets);
		target_addrs = get_addresses (targets, n);
		
		res = malloc (n * sizeof (struct t_host_s *));
		memset (res, 0, n * sizeof (struct t_host_s *));
		
		current = n;
		t_data.list = target_addrs;
		t_data.res = res;

		// Lanzamos a correr a los hilos
		n_running = N_THREADS;
		pthread_cond_broadcast (&threads_running);
		// Y esperamos a que acaben su tarea
		pthread_mutex_lock (&manager_mutex);
		while (n_running > 0) {
			pthread_cond_wait (&manager_running, &manager_mutex);
		}
		pthread_mutex_unlock (&manager_mutex);
		
		if (!satellite) {
			for (i = 0; i < n; i++) {
				if (res[i]) {
					tup++;
					inet_ntop (AF_INET, &res[i]->ip, buf, INET_ADDRSTRLEN);
					printf ("Host: %s\n", buf);
					for (tmp = res[i]->services; tmp; tmp = tmp->next) {
						printf ("\tPort: %i (%s)\n", tmp->port, proto2str (tmp->proto));
						//dump_list (tmp->banner);
					}
				}
			}
		}
		
		if (satellite) {
			json_res = build_response (res, n, job_id, &up);
			printf ("%u hosts found\n", up);
			send_results (argv[2], json_res, cookie);
			json_decref (json_res);
			tup += up;
		}
		
		free (target_addrs);
		free_list (targets);
		free_result (res, n);

		scanned += n;
	} while (satellite && !stop);
	
	pthread_cond_broadcast (&threads_running);
	for (i = 0; i < N_THREADS; i++) 
		pthread_join (threads[i], NULL);

	time (&end);
	printf ("Scanned %" PRIu64 " hosts in %f seconds (%u up)\n", scanned, difftime (end, begin), tup);

	return 0;
}

struct t_list_s *cidr_list (char *range, unsigned int *count)
{
	CIDR *cidr, *min;
	unsigned int i, n;
	uint8_t *mask;
	struct in_addr addr;
	char buf[INET_ADDRSTRLEN];
	struct t_list_s *list = NULL;
	
	cidr = cidr_from_str (range);
	if (!cidr) {
		perror ("cidr");
		return NULL;
	}
	
	min = cidr_addr_hostmin (cidr);
	n = cidr_num_hosts (cidr);	
	mask = cidr_get_mask (cidr);
	cidr_to_inaddr (min, &addr);	
	
	for (i = 0; i < n; i++) {
		inet_ntop (AF_INET, &addr, buf, INET_ADDRSTRLEN);
		append_list_element (&list, buf, LIST_COPY, strlen (buf) + 1);
		ipv4_inc (&addr, &mask[12]);
	}
	
	free (mask);
	cidr_free (cidr);
	cidr_free (min);
	
	*count = n;
	return list;
}

struct in_addr *get_addresses (struct t_list_s *list, unsigned int n)
{
	// Los hilos nunca llegan a escanear el elemento 0, desplazamos +1
	struct in_addr *res = malloc ((n + 1) * sizeof (struct in_addr));
	unsigned int i;
	
	for (i = 0; (i < n) && list; i++) {
		if (list->data) {
			inet_pton (AF_INET, list->data, &res[i + 1]);
		}
		list = list->next;
	}
	return res;
}

void free_result (struct t_host_s **res, unsigned int n)
{
	unsigned int i;
	struct t_service_s *s;
	
	for (i = 0; i < n; i++) {
		if (res[i]) {
			while (res[i]->services) {
				s = res[i]->services;
				res[i]->services = res[i]->services->next;
				if (s->banner)
					free_list (s->banner);
				free (s);
			}
			free (res[i]);
		}
	}
	free (res);
}

void sig_stop (int n)
{
	printf ("Got stop signal, waiting for threads to end\n");
	stop = 1;
}