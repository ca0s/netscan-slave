/*
 * Implementación de lista básica. 
 * Operaciones para crear, añadir al final y liberarla entera.
 * dump_list es para testear.
 * */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "list.h"

// Puede petar si el miembro <data> de un elemento no fue malloc'eado
void free_list (struct t_list_s *head)
{
	struct t_list_s *tmp;
	
	while (head) {
		if (head->data)
			free (head->data);
		tmp = head->next;
		free (head);
		head = tmp;
	}
}

void free_list_cb (struct t_list_s *head, void (*callback)(void *))
{
	struct t_list_s *tmp;
	
	while (head) {
		if (head->data)
			callback (head->data);
		tmp = head->next;
		free (head);
		head = tmp;
	}	
}

/*
 * Soporta dos modos de adición.
 * LIST_ASSIGN	añade el puntero pasado en <element> al campo <next> del
 * 				miembro.
 * LIST_COPY	reserva <len> bytes y copia en ellos <element>. Añade el
 * 				puntero resultante al campo <next> del miembro.
 * */
void append_list_element (struct t_list_s **list, void *element, enum t_addmode_e mode, uint64_t len)
{
	struct t_list_s *tmp;
	
	if (!list)
		return;

	if (!*list) {
		*list = new_list_element_ex (element, mode, len);
	} else {
		tmp = *list;
		while (tmp->next) {
			tmp = tmp->next;
		}
		tmp->next = new_list_element_ex (element, mode, len);
	}
}

struct t_list_s *new_list ()
{
	struct t_list_s *new = malloc (sizeof (struct t_list_s));
	
	new->data = NULL;
	new->next = NULL;
	
	return new;
}

struct t_list_s *new_list_element (void *element)
{
	struct t_list_s *new = malloc (sizeof (struct t_list_s));
	
	new->data = element;
	new->next = NULL;
	
	return new;
}

struct t_list_s *new_list_element_ex (void *element, enum t_addmode_e mode, uint64_t len) {
	struct t_list_s *new = malloc (sizeof (struct t_list_s));
	char *data = NULL;
	
	if (mode == LIST_ASSIGN) {
		new->data = element;
	}
	else if (mode == LIST_COPY) {
		data = malloc (len);
		memcpy (data, element, len);
		new->data = data;
	}
	
	new->next = NULL;
	return new;
}	

void dump_list (struct t_list_s *head)
{
	while (head) {
		if (head->data)
			printf ("%s\n", (char *)head->data);
		head = head->next;
	}
}
