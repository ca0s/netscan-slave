#ifndef __H_STRUCTS__
#define __H_STRUCTS__

#define AUTH_USER "user"
#define AUTH_PASS "password"

#define LINE_SIZE	1024

/*
 * Tipo de servicios escaneables.
 * Deben ir en el mismo orden que la declaración de la matriz <actions>
 * en portscan.c
 * */
enum t_proto_e {
	PROTO_HTTP = 0, PROTO_FTP, PROTO_IRC, PROTO_SSH, PROTO_UNKNOWN
};

/*
 * Tipo de acciones realizables en test_port_service () [portscan.c]
 * STOP:	finaliza la prueba. Colocar _siempre_ al final de una matriz 
 * 			de acciones
 * SEND:	enviar el siguiente elemento del campo <msgs>
 * RECV:	recibir una sola linea y comparar con el siguiente elemento
 * 			de <expected>
 * RECVIGNORE:
 * 			recibir una sola linea e ignorarla
 * RECVALL:	recibir todo lo que llegue al socket, ignorándolo
 * 
 * "Ignorando" significa que no se compara con nada del campo <expected>
 * pero SÍ será guardado en <banner>
 * */
enum t_action_e {
	STOP, SEND, RECV, RECVIGNORE, RECVALL
};

/*
 * Estructura para definir las acciones a realizar en los tests de servicio.
 * <msgs>:		elementos a enviar en un comando SEND
 * <expected>:	ante un comando RECV, comparar el mensaje con el miembro
 * 				correspondiente de <expected>
 * <actions>:	comandos a realizar. Terminar siempre con END
 * */
struct t_port_action_s {	// Los miembros de la matriz deben estar en el orden de t_proto_e
	char						*msgs[8];
	char						*expected[8];
	enum t_action_e				actions[8];
	enum t_proto_e				proto;
};

/*
 * Definición de un puerto. 
 * <prefered> contiene la primera acción a realizar al testearlo.
 * */
struct t_port_s {
	int							port;
	enum t_proto_e				prefered;
	char						enabled;
};

/*
 * Tipos de SSOO. De momento ni idea de como determinarlo.
 * */
enum t_ssoo_e {
	UNKNOWN, WIN32, WIN64, LIN32, LIN64, UNIX, SOLARIS, OSX
};

/*
 * Definición de la versión de SSOO. De momento, ni idea de como determinarla.
 * Algunos SSOO usan una versión tipo 1.2.3, otros un número. De ahí
 * la union.
 * */
union t_ssooversion_u {
	uint8_t						part[4];
	uint32_t					full;	
};

/*
 * Definición de la información de un SSOO. contiene los dos tipos anteriores.
 * */
struct t_ssoo_s {
	enum t_ssoo_e				type;
	union t_ssooversion_u		version;
};

/*
 * Información de un servicio. Contiene puerto, protocolo, banner
 * (cada elemento de la lista es una linea) y el siguiente.
 * */
struct t_service_s {
	uint16_t					port;
	enum t_proto_e				proto;
	struct t_list_s				*banner;
	struct t_service_s			*next;
};

/*
 * IPv4. Usable en forma numérica y por campos.
 * */
union t_ip_u {
	uint8_t						fields[4];
	uint32_t					num;
};	

/*
 * Información de un host. Habrá un array de este tipo, un elemento por
 * cada host escaneado. Así nos ahorramos problemas de sincronización
 * entre hilos.
 * */
struct t_host_s {
	union t_ip_u				ip;
	struct t_ssoo_s				ssoo;
	struct t_service_s			*services;
};

/*
 * Datos que recibe un hilo
 * */
struct t_data_s {
	struct in_addr				*list;		// Primera dirección del rango
	unsigned int				*current;	// Cuántas IPs llevamos escaneadas
	unsigned int				*stop;		// Para parar los hilos
	struct t_host_s				**res;		// Para guardar los resultados

	pthread_cond_t				*manager_running;
	pthread_cond_t				*threads_running;
	pthread_mutex_t				*manager_mutex;
	pthread_mutex_t				*threads_mutex;
	unsigned int				*n_running;
};


#endif
