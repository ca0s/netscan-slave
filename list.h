#ifndef __H_LIST__
#define __H_LIST__

#include <stdint.h>

enum t_addmode_e {
	LIST_ASSIGN, LIST_COPY
};

struct t_list_s {
	void *data;
	struct t_list_s *next;
};

struct t_list_s *new_list ();
void free_list (struct t_list_s *);
void free_list_cb (struct t_list_s *, void (*callback)(void *));
void append_list_element (struct t_list_s **, void *, enum t_addmode_e, uint64_t);
struct t_list_s *new_list_element_ex (void *element, enum t_addmode_e mode, uint64_t len);
struct t_list_s *new_list_element (void *);
void dump_list (struct t_list_s *);

#endif
