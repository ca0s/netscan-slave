#ifndef __H_STRINGS__
#define __H_STRINGS__

struct t_string_s {
	unsigned int len;
	char *data;
};

struct t_string_s *string_new ();
void string_free (struct t_string_s *str);
void string_set (struct t_string_s *str, char *data, unsigned int l);
void string_set_n (struct t_string_s *str, char *data, unsigned int l);
void string_copy (struct t_string_s *dst, struct t_string_s *src);
void string_cat (struct t_string_s *dst, struct t_string_s *src);
void string_cat_data (struct t_string_s *dst, char *data, unsigned int l);

#endif
