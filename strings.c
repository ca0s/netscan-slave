#include <stdlib.h>
#include <string.h>
#include "strings.h"

struct t_string_s *string_new ()
{
	struct t_string_s *new = malloc (sizeof (struct t_string_s));
	new->len = 0;
	new->data = NULL;	
	return new;
}

void string_free (struct t_string_s *str)
{
	if (str->data) {
		free (str->data);
	}
	free (str);
}

void string_set (struct t_string_s *str, char *data, unsigned int l)
{
	if (str->data) {
		free (str->data);
	}
	
	str->data = malloc (l + 1);
	str->len = l;
	memcpy (str->data, data, l);
	str->data[l] = 0x00;
}

void string_set_n (struct t_string_s *str, char *data, unsigned int l)
{
	if (str->data) {
		free (str->data);
	}
	
	str->data = malloc (l+1);
	str->data[l] = 0x00;
	str->len = l;
}

void string_copy (struct t_string_s *dst, struct t_string_s *src)
{
	if (!src->data)
		return;
	
	if (dst->data) {
		free (dst->data);
	}
	
	dst->data = malloc (src->len + 1);
	memcpy (dst->data, src->data, src->len + 1);
	dst->len = src->len;
}

void string_cat (struct t_string_s *dst, struct t_string_s *src)
{
	if (!dst->data) {
		string_copy (dst, src);
		return;
	}
	
	dst->data = realloc (dst->data, dst->len + src->len + 1);
	dst->len += src->len;
	memcpy (dst->data + dst->len, src->data, src->len + 1);
}
	
void string_cat_data (struct t_string_s *dst, char *data, unsigned int l)
{
	if (!dst->data) {
		string_set (dst, data, l);
		return;
	}
	
	dst->data = realloc (dst->data, dst->len + l + 1);
	memcpy (dst->data + dst->len, data, l);
	dst->data[dst->len + l] = 0x00;
	dst->len += l;
}
