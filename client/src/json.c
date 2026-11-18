#include "json.h"
#include "util.h"

typedef struct {
    const char *p;
    const char *end;
    int depth;
} jp_t;

static void skip_ws(jp_t *p)
{
    while (p->p < p->end && (*p->p == ' ' || *p->p == '\t' || *p->p == '\r' || *p->p == '\n')) p->p++;
}

static json *jnew(jtype t)
{
    json *j = (json *)xcalloc(1, sizeof(json));
    j->t = t;
    return j;
}

void json_free(json *j)
{
    while (j) {
        json *next = j->next;
        json_free(j->child);
        free(j->key);
        free(j->s);
        free(j);
        j = next;
    }
}

static int parse_string(jp_t *p, char **out)
{
    buf_t b;
    buf_init(&b);
    if (p->p >= p->end || *p->p != '"') return -1;
    p->p++;
    while (p->p < p->end && *p->p != '"') {
        unsigned char c = (unsigned char)*p->p++;
        if (c == '\\') {
            if (p->p >= p->end) { buf_free(&b); return -1; }
            c = (unsigned char)*p->p++;
            switch (c) {
            case '"': buf_append(&b, "\"", 1); break;
            case '\\': buf_append(&b, "\\", 1); break;
            case '/': buf_append(&b, "/", 1); break;
            case 'b': buf_append(&b, "\b", 1); break;
            case 'f': buf_append(&b, "\f", 1); break;
            case 'n': buf_append(&b, "\n", 1); break;
            case 'r': buf_append(&b, "\r", 1); break;
            case 't': buf_append(&b, "\t", 1); break;
            case 'u': {
                unsigned cp = 0;
                int i;
                if (p->end - p->p < 4) { buf_free(&b); return -1; }
                for (i = 0; i < 4; i++) {
                    int v;
                    char h = p->p[i];
                    if (h >= '0' && h <= '9') v = h - '0';
                    else if (h >= 'a' && h <= 'f') v = h - 'a' + 10;
                    else if (h >= 'A' && h <= 'F') v = h - 'A' + 10;
                    else { buf_free(&b); return -1; }
                    cp = (cp << 4) | (unsigned)v;
                }
                p->p += 4;
                if (cp < 0x80) buf_append(&b, &cp, 1);
                else if (cp < 0x800) {
                    unsigned char t[2];
                    t[0] = (unsigned char)(0xC0 | (cp >> 6));
                    t[1] = (unsigned char)(0x80 | (cp & 0x3F));
                    buf_append(&b, t, 2);
                } else {
                    unsigned char t[3];
                    t[0] = (unsigned char)(0xE0 | (cp >> 12));
                    t[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
                    t[2] = (unsigned char)(0x80 | (cp & 0x3F));
                    buf_append(&b, t, 3);
                }
                break;
            }
            default: buf_free(&b); return -1;
            }
        } else {
            buf_append(&b, &c, 1);
        }
    }
    if (p->p >= p->end) { buf_free(&b); return -1; }
    p->p++; /* closing quote */
    buf_append(&b, "", 1);
    *out = (char *)b.data;
    return 0;
}

static json *parse_value(jp_t *p);

static json *parse_array(jp_t *p)
{
    json *arr = jnew(JARR);
    json **tail = &arr->child;
    p->p++; /* [ */
    skip_ws(p);
    if (p->p < p->end && *p->p == ']') { p->p++; return arr; }
    for (;;) {
        json *v = parse_value(p);
        if (!v) { json_free(arr); return NULL; }
        *tail = v;
        tail = &v->next;
        skip_ws(p);
        if (p->p < p->end && *p->p == ',') { p->p++; skip_ws(p); continue; }
        if (p->p < p->end && *p->p == ']') { p->p++; return arr; }
        json_free(arr);
        return NULL;
    }
}

static json *parse_object(jp_t *p)
{
    json *obj = jnew(JOBJ);
    json **tail = &obj->child;
    p->p++; /* { */
    skip_ws(p);
    if (p->p < p->end && *p->p == '}') { p->p++; return obj; }
    for (;;) {
        char *key = NULL;
        json *v;
        if (parse_string(p, &key) != 0) { json_free(obj); return NULL; }
        skip_ws(p);
        if (p->p >= p->end || *p->p != ':') { free(key); json_free(obj); return NULL; }
        p->p++;
        skip_ws(p);
        v = parse_value(p);
        if (!v) { free(key); json_free(obj); return NULL; }
        v->key = key;
        *tail = v;
        tail = &v->next;
        skip_ws(p);
        if (p->p < p->end && *p->p == ',') { p->p++; skip_ws(p); continue; }
        if (p->p < p->end && *p->p == '}') { p->p++; return obj; }
        json_free(obj);
        return NULL;
    }
}

static json *parse_value(jp_t *p)
{
    skip_ws(p);
    if (p->p >= p->end) return NULL;
    if (++p->depth > 64) return NULL;
    switch (*p->p) {
    case '{': { json *j = parse_object(p); p->depth--; return j; }
    case '[': { json *j = parse_array(p); p->depth--; return j; }
    case '"': {
        char *s = NULL;
        json *j;
        if (parse_string(p, &s) != 0) { p->depth--; return NULL; }
        j = jnew(JSTR);
        j->s = s;
        p->depth--;
        return j;
    }
    case 't':
        if (p->end - p->p >= 4 && !memcmp(p->p, "true", 4)) { p->p += 4; p->depth--; { json *j = jnew(JBOOL); j->b = 1; return j; } }
        break;
    case 'f':
        if (p->end - p->p >= 5 && !memcmp(p->p, "false", 5)) { p->p += 5; p->depth--; { json *j = jnew(JBOOL); j->b = 0; return j; } }
        break;
    case 'n':
        if (p->end - p->p >= 4 && !memcmp(p->p, "null", 4)) { p->p += 4; p->depth--; return jnew(JNULL); }
        break;
    default: {
        char *endp = NULL;
        char tmp[64];
        size_t n = 0;
        while (p->p < p->end && n < sizeof(tmp) - 1 &&
               (*p->p == '-' || *p->p == '+' || *p->p == '.' || *p->p == 'e' || *p->p == 'E' ||
                (*p->p >= '0' && *p->p <= '9'))) {
            tmp[n++] = *p->p++;
        }
        tmp[n] = 0;
        if (!n) break;
        {
            json *j = jnew(JNUM);
            j->num = strtod(tmp, &endp);
            if (endp == tmp) { json_free(j); break; }
            p->depth--;
            return j;
        }
    }
    }
    p->depth--;
    return NULL;
}

json *json_parse(const char *txt, size_t len)
{
    jp_t p;
    json *j;
    if (!txt) return NULL;
    p.p = txt;
    p.end = txt + (len ? len : strlen(txt));
    p.depth = 0;
    j = parse_value(&p);
    if (!j) return NULL;
    return j;
}

json *json_obj_get(const json *obj, const char *key)
{
    json *c;
    if (!obj || obj->t != JOBJ) return NULL;
    for (c = obj->child; c; c = c->next) {
        if (c->key && !strcmp(c->key, key)) return c;
    }
    return NULL;
}

json *json_at(const json *arr, int idx)
{
    json *c;
    int i = 0;
    if (!arr || arr->t != JARR) return NULL;
    for (c = arr->child; c; c = c->next, i++) if (i == idx) return c;
    return NULL;
}

int json_len(const json *arr)
{
    int n = 0;
    json *c;
    if (!arr) return 0;
    for (c = arr->child; c; c = c->next) n++;
    return n;
}

const char *json_str(const json *j, const char *defv)
{
    return (j && j->t == JSTR && j->s) ? j->s : defv;
}

long long json_int(const json *j, long long defv)
{
    return (j && j->t == JNUM) ? (long long)j->num : defv;
}

int json_bool(const json *j, int defv)
{
    return (j && j->t == JBOOL) ? j->b : defv;
}

double json_num(const json *j, double defv)
{
    return (j && j->t == JNUM) ? j->num : defv;
}

const char *json_obj_str(const json *obj, const char *key, const char *defv)
{
    return json_str(json_obj_get(obj, key), defv);
}
long long json_obj_int(const json *obj, const char *key, long long defv)
{
    return json_int(json_obj_get(obj, key), defv);
}
int json_obj_bool(const json *obj, const char *key, int defv)
{
    return json_bool(json_obj_get(obj, key), defv);
}
