#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "portscan.h"
#include "list.h"
#include "util.h"

/*
 * Los puertos declarados aquí serán escaneados. Al testear el servicio
 * que corre en él, se empezará por las acciones dadas por el campo
 * <prefered>
 * Ha de terminar en un elemento con <port> = 0
 * */
struct t_port_s ports[] = {
	{
		.port = 21,
		.prefered = PROTO_FTP,
		.enabled = 0
	},
	{
		.port = 22,
		.prefered = PROTO_SSH,
		.enabled = 0
	},
	{
		.port = 80,
		.prefered = PROTO_HTTP,
		.enabled = 1
	},
	{
		.port = 6667,
		.prefered = PROTO_IRC,
		.enabled = 0
	},
	{
		.port = 0
	}
};

/*
 * Define el comportamiento del escaner para cada protocolo. Las acciones
 * se realizan secuencialmente. Ver portscan.h para más info.
 * */
struct t_port_action_s actions[] = {
	{	// HTTP
		.msgs = { "HEAD / HTTP/1.0\r\n\r\n", NULL },
		.expected = { "^HTTP.*", NULL },
		.actions = {SEND, RECV, RECVALL, STOP },
		.proto	= PROTO_HTTP
	},
	{	// FTP
		.msgs = { NULL },
		.expected = { "^220.*", NULL },
		.actions = { RECV, RECVALL, STOP},
		.proto	= PROTO_FTP
	},
	{	// IRC
		.msgs = { "NICK herpaderpidontexist\r\n", NULL},
		.expected = { "^PING.*", NULL },
		.actions = { RECVALL, SEND, RECV, RECVALL, STOP},
		.proto	= PROTO_IRC
	},
	{	// SSH
		.msgs = { NULL },
		.expected = { "^SSH.*", NULL },
		.actions = { RECV, STOP },
		.proto	= PROTO_SSH
	},
	{	// Unknown - Si no nos cuadra nada, aceptamos y guardamos todo
		.msgs = { "idontknowwhatimdoing\r\n", NULL },
		.expected = { NULL },
		.actions = { RECVALL, SEND, RECVALL, STOP },
		.proto	= PROTO_UNKNOWN
	}
};

/*
 * Lleva a cabo las pruebas previamente establecidas. Para cada intento
 * vacía el banner, si es que ya se ha obtenido uno. Cuando el test da
 * positivo, se conserva el último banner obtenido.
 * */
int test_port_service (int sock, struct t_port_action_s *actions, struct t_service_s *svc)
{
	unsigned int m = 0, e = 0, a = 0;
	uint8_t ignore = 0, all = 0;
	char *line;
	
	if (svc->banner) {
		free_list (svc->banner);
		svc->banner = NULL;
	}
	
	while (actions->actions[a] != STOP) {
		ignore	= 0;
		all		= 0;
		switch (actions->actions[a]) {
			case SEND:
				send (sock, actions->msgs[m], strlen (actions->msgs[m]), 0);
				++m;
				break;
			case RECVALL:			// Implica RECVIGNORE + RECV
				all = 1;
			case RECVIGNORE:		// Implica RECV
				ignore = 1;
			case RECV:
				do {
					line = recvline (sock);
					
					if (!ignore && !line_match (line, actions->expected[e]))
						return 0;
						
					append_list_element (&svc->banner, line, LIST_COPY, strlen (line) + 1);
					
					if (!ignore)
						++e;
				} while (all && strlen (line) > 0);
				break;
			case STOP:
				break;
		}
		++a;
	}
	
	svc->proto = actions->proto;
	return 1;
}

/*
 * Hace el escaneo de un servicio. Primero hace las pruebas del protocolo
 * <prefered>, en caso de negativo realiza el resto.
 * */
void scan_port (int sock, struct sockaddr *addr, struct t_port_s *port, struct t_host_s **res)
{
	struct t_service_s *tmp, *new;
	unsigned int i = 0;
	
	// Si <*res> == NULL es que es el primer puerto que se escanea a
	// esta IP. Reservamos hueco para el en la matriz de hosts.
	if (!*res)
		*res = new_host (&((struct sockaddr_in *)addr)->sin_addr);
	
	// Hueco para este servicio en la lista.
	tmp = (*res)->services;
	new = new_service (port->port, tmp);
	(*res)->services = new;
	
	set_socket_timeout (sock, 1, 0);
	
	// Primero <prefered>
	if (test_port_service (sock, &actions[port->prefered], new)) {
		close (sock);
		return;
	}
	else {	// Luego el resto
		close (sock);
		sock = open_socket ();
		set_socket_timeout (sock, 4, 0);
		while (i <= PROTO_UNKNOWN) {
			if (i != port->prefered) {
				connect (sock, addr, sizeof (struct sockaddr));
				if (test_port_service (sock, &actions[i], new)) {
					close (sock);
					return;
				}
				close (sock);
				sock = open_socket ();
				set_socket_timeout (sock, 1, 0);
			}
			i++;
		}
		close (sock);
	}
}

int open_socket ()
{
	int sock;
	do {
		sock = socket (AF_INET, SOCK_STREAM, 0);
	} while (sock < 0 && !sleep (1));
	return sock;
}

/*
 * Intenta conectar a un par IP:Puerto, con límite de tiempo
 * */
int can_connect (int sock, struct sockaddr *c)
{
	fd_set set;
	unsigned long arg;
	unsigned int lon, opt;
	struct timeval to = (struct timeval) {
		.tv_sec = 4,
		.tv_usec = 0
	};
	
	arg = fcntl(sock, F_GETFL, NULL); 
	arg |= O_NONBLOCK; 
	fcntl(sock, F_SETFL, arg); 
	
	if (connect (sock, c, sizeof (struct sockaddr)) < 0) {
		if (errno == EINPROGRESS) { 
			FD_ZERO(&set); 
			FD_SET(sock, &set); 
			if (select(sock+1, NULL, &set, NULL, &to) > 0) { 
				lon = sizeof(int); 
				getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)(&opt), &lon); 
				if (opt) {
					return 0;
				}
			}
			else { 
				return 0;
			}
		}
		else {
			return 0;
		}
	}
	arg = fcntl(sock, F_GETFL, NULL); 
	arg &= (~O_NONBLOCK); 
	fcntl(sock, F_SETFL, arg); 
	
	return 1;
}

/*
 * Lee una linea de un socket. Devuelve puntero a buffer estático, si 
 * se llama varias veces y se quiere guardar todos los resultados, hay
 * que copiarlo. Ojo de no llamar a free () con un resultado de esta
 * función.
 * */
char *recvline (int sock)
{
	static char buffer[LINE_SIZE];
	int i = 0;
	int r;
	
	memset (buffer, 0, LINE_SIZE);
	do {
		r = recv (sock, &buffer[i], 1, 0);
		i += r;
	} while (i < LINE_SIZE && buffer[i-1] != '\n' && r > 0);
	
	buffer[i] = 0x00;
	
	return buffer;
}

/*
 * Crea un elemento del tipo t_host_s
 * Inicializa la información de IP con <addr>, el resto a su valor
 * neutro.
 * */
struct t_host_s *new_host (struct in_addr *addr)
{
	struct t_host_s *new = malloc (sizeof (struct t_host_s));
	
	new->ip.num = addr->s_addr;
	new->ssoo.type = UNKNOWN;
	new->ssoo.version.full = 0;
	new->services = NULL;
	
	return new;
}

/*
 * Crea un elemento del tipo t_service_s
 * Inicializa el puerto a <port> y el siguiente elemento de la lista a
 * <next>
 * */
struct t_service_s *new_service (int port, struct t_service_s *next)
{
	struct t_service_s *new = malloc (sizeof (struct t_service_s));
	
	new->port = port;
	new->proto = PROTO_UNKNOWN;
	new->banner = NULL;
	new->next = next;
	
	return new;
}

/*
 * Establece el timeout de <sock> a (sec, usec)
 * */
void set_socket_timeout (int sock, int sec, int usec)
{
	struct timeval tv = {
		.tv_sec		= sec,
		.tv_usec	= usec
	};
	
	setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
	setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof (tv));
}
