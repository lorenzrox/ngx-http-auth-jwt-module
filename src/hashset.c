#include "hashset.h"

size_t fnv1a_hash(const char *cp);

size_t fnv1a_hash(const char *cp)
{
    size_t hash = 0x811c9dc5;
    while (*cp)
    {
        hash ^= (unsigned char)*cp++;
        hash *= 0x01000193;
    }
    return hash;
}

ngx_int_t hashset_init(hashset_t *set, size_t capacity)
{
    if (capacity > (size_t)-1)
    {
        return NGX_ERROR;
    }

    set->nentries = 0;
    set->capacity = capacity;

    if (capacity > 1024)
    {
        set->buckets = (size_t *)malloc(capacity * sizeof(size_t));
        set->entries = (hashset_entry_t *)malloc(capacity * sizeof(hashset_entry_t));
    }
    else
    {
        set->buckets = (size_t *)alloca(capacity * sizeof(size_t));
        set->entries = (hashset_entry_t *)alloca(capacity * sizeof(hashset_entry_t));
    }

    if (set->buckets == NULL || set->entries == NULL)
    {
        return NGX_ERROR;
    }

    memset(set->buckets, 0, capacity * sizeof(size_t));
    memset(set->entries, 0, capacity * sizeof(hashset_entry_t));
    return NGX_OK;
}

void hashset_destroy(hashset_t *set)
{
    if (set->capacity > 1024)
    {
        if (set->buckets != NULL)
        {
            free(set->buckets);
            set->buckets = NULL;
        }

        if (set->entries != NULL)
        {
            free(set->entries);
            set->entries = NULL;
        }
    }
    else
    {
        set->buckets = NULL;
        set->entries = NULL;
    }

    set->nentries = 0;
    set->capacity = 0;
}

ngx_flag_t hashset_contains(hashset_t *set, const char *item)
{
    size_t hash, index;
    hashset_entry_t *entry;

    hash = fnv1a_hash(item);
    index = set->buckets[hash % set->capacity] - 1;

    while (index < set->capacity)
    {
        entry = &set->entries[index];
        if (entry->hash == hash && ngx_strcasecmp((u_char *)entry->value, (u_char *)item) == 0)
        {
            return 1;
        }

        index = entry->next;
    }

    return 0;
}

ngx_flag_t hashset_add(hashset_t *set, const char *item)
{
    size_t hash, bucket_index;
    size_t *bucket;
    hashset_entry_t *entry;

    //we don't need the set to grow
    if (set->nentries == set->capacity)
    {
        return 0;
    }

    hash = fnv1a_hash(item);
    bucket = &set->buckets[hash % set->capacity];
    bucket_index = *bucket - 1;

    while (bucket_index < set->capacity)
    {
        entry = &set->entries[bucket_index];
        if (entry->hash == hash && ngx_strcasecmp((u_char *)entry->value, (u_char *)item) == 0)
        {
            return 0;
        }

        bucket_index = entry->next;
    }

    entry = &set->entries[set->nentries];
    entry->hash = hash;
    entry->value = item;
    entry->next = *bucket - 1;
    *bucket = ++set->nentries;
    return 1;
}