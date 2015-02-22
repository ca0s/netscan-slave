#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "ipscan.h"
#include "portscan.h"
#include "head.h"

extern pthread_mutex_t pool_mutex;
extern struct t_port_s ports[];

/*
 * Los hilos ejecutan esto. Cogen IPs del pool hasta que no quedan.
 * Intenta conectar a cada puerto. Si puede, llama a scan_port para
 * determinar qué servicio corre en el.
 * */
void *scanner (void *args)
{
	struct t_data_s *data = args;
	struct sockaddr_in psa;
	struct in_addr addr;
	unsigned int current;
	int psock;
	int i;
	unsigned int stop = 0;
	char buf[256];
	int r;

	pthread_mutex_lock (data->threads_mutex);
	pthread_cond_wait (data->threads_running, data->threads_mutex);
	pthread_mutex_unlock (data->threads_mutex);	
	
	psa.sin_family = AF_INET;
	
	while (!stop) {
		get_ip_from_pool (data, &addr, &current, &stop);
		if(stop) {
			break;
		}

		psa.sin_addr.s_addr = addr.s_addr;
		
		inet_ntop (AF_INET, &addr.s_addr, buf, 256);
		
		for (i = 0; ports[i].port; i++) {
			if (ports[i].enabled) {
				psock = open_socket ();
				psa.sin_port = htons (ports[i].port);
				if (can_connect (psock, (struct sockaddr *) &psa)) {
					scan_port (psock, (struct sockaddr *)&psa, &ports[i], &data->res[current]);
				}
				close (psock);
			}
		}
	}
	// Al finalizar, él padre estará en un wait esperando a que todos acaben
	r = decrement_and_get (data->n_running);
	if (r == 0) {
		pthread_cond_signal (data->manager_running);
	}
	return NULL;
}

/*
 * Obtiene IPs del pool. Guarda el resultado en <addr>, y el número de
 * la IP actual en <current>.
 * Thread-safe
 * */
void get_ip_from_pool (struct t_data_s *data, struct in_addr *addr, unsigned int *current, unsigned int *stop)
{
	unsigned int r;

	*current = decrement_and_get (data->current);
	if (*current <= 0) {
		r = decrement_and_get (data->n_running);
		if (r == 0) {
			pthread_cond_signal (data->manager_running);
		}

		pthread_mutex_lock (data->threads_mutex);
		while (*current <= 0 && !*stop) {
			pthread_cond_wait (data->threads_running, data->threads_mutex);
			*current = decrement_and_get (data->current);
			*stop = *(data->stop);
		}
		pthread_mutex_unlock (data->threads_mutex);		
	}
	if(!*stop) {
		pull_ip (addr, *current, data);
	}
}

unsigned int decrement_and_get (unsigned int *n)
{
	unsigned int current;
	pthread_mutex_lock (&pool_mutex);
	if (*n > 0) {
		*n -= 1;
	}
	current = *n;
	pthread_mutex_unlock (&pool_mutex);
	return current;
}

void pull_ip (struct in_addr *addr, unsigned int current, struct t_data_s *data)
{
	pthread_mutex_lock (&pool_mutex);
	addr->s_addr = *((in_addr_t *)&data->list[current]);
	pthread_mutex_unlock (&pool_mutex);
}