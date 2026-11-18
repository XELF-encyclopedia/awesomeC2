#ifndef C2_JSON_H
#define C2_JSON_H
#include "common.h"

typedef enum { JNULL = 0, JBOOL, JNUM, JSTR, JARR, JOBJ } jtype;

typedef struct json {
    jtype        t;
    char        *key;      /* set when this node is a member of an object */
    char        *s;        /* string value */
    double       num;
    int          b;
    struct json *child;    /* first child (array element / object member) */
    struct json *next;     /* sibling */
} json;

json       *json_parse(const char *txt, size_t len);
void        json_free(json *j);
json       *json_obj_get(const json *obj, const char *key);
json       *json_at(const json *arr, int idx);
int         json_len(const json *arr_or_obj);
const char *json_str(const json *j, const char *defv);
long long   json_int(const json *j, long long defv);
int         json_bool(const json *j, int defv);
double      json_num(const json *j, double defv);

/* convenience */
const char *json_obj_str(const json *obj, const char *key, const char *defv);
long long   json_obj_int(const json *obj, const char *key, long long defv);
int         json_obj_bool(const json *obj, const char *key, int defv);

#endif
