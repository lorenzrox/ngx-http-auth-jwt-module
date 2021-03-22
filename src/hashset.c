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