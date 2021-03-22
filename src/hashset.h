#include <ngx_core.h>

typedef struct
{
    size_t hash;
    const char *value;
    size_t next;
} hashset_entry_t;

typedef struct
{
    size_t capacity;
    size_t *buckets;
    hashset_entry_t *entries;
    size_t nentries;
} hashset_t;

ngx_flag_t hashset_add(hashset_t *set, const char *item);
ngx_flag_t hashset_contains(hashset_t *set, const char *item);