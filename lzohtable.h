#ifndef LZOHTABLE_H
#define LZOHTABLE_H

#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>

typedef void (*lzohtable_print_helper)(
    size_t count,
    size_t len,
    size_t idx,
    size_t probe,
    size_t key_size,
    size_t value_size,
    const void *key,
    const void *value
);
typedef void (*lzohtable_clean_up)(void *key, void *value, void *extra);

typedef struct lzohtable_allocator_ctx{
    jmp_buf *err_buf;
    void    *real_ctx;
}LZOHTableAllocatorCtx;

typedef struct lzohtable_allocator{
    LZOHTableAllocatorCtx ctx;
    void *(*alloc)(const LZOHTableAllocatorCtx *ctx, size_t size);
    void *(*realloc)(const LZOHTableAllocatorCtx *ctx, void *ptr, size_t old_size, size_t new_size);
    void (*dealloc)(const LZOHTableAllocatorCtx *ctx, void *ptr, size_t size);
}LZOHTableAllocator;

typedef struct lzohtable_key_value{
    size_t key_size;
    size_t value_size;
    void   *key;
    void   *value;
}LZOHTableKeyValue;

typedef uint64_t              lzohtable_hash_t;
typedef struct lzohtable      LZOHTable;

typedef struct lzohtable_iterator{
    size_t            counter;
    size_t            current;
    LZOHTableKeyValue key_value;
    const LZOHTable   *table;
}LZOHTableIterator;

#define LZOHTABLE_LOAD_FACTOR(_table)(((float)(_table)->n) / ((float)(_table)->m))

LZOHTable *lzohtable_create(const LZOHTableAllocator *allocator, size_t m, float lfth);
void lzohtable_destroy_help(LZOHTable *table, const void *extra, lzohtable_clean_up clean_up_helper);
#define LZOHTABLE_DESTROY(_table)(lzohtable_destroy_help((_table), NULL, NULL))

size_t lzohtable_m(const LZOHTable *table);
size_t lzohtable_n(const LZOHTable *table);
float lzohtable_lfth(const LZOHTable *table);
void lzohtable_print(const LZOHTable *table, lzohtable_print_helper print_helper);

void lzohtable_iterator(const LZOHTable *table, LZOHTableIterator *iterator);
int lzohtable_iterator_has_next(const LZOHTableIterator *iterator);
LZOHTableKeyValue *lzohtable_iterator_next(LZOHTableIterator *iterator);

int lzohtable_lookup(const LZOHTable *table, size_t key_size, const void *key, void **out_value);
void lzohtable_clear_help(LZOHTable *table, const void *extra, lzohtable_clean_up clean_up_helper);
#define LZOHTABLE_CLEAR(_table)(lzohtable_clear_help((_table), NULL, NULL))

int lzohtable_put_x(
    LZOHTable *table,
    char cpy_k,
    char cpy_v,
    size_t key_size,
    const void *key,
    size_t value_size,
    const void *value,
    lzohtable_hash_t *out_hash
);
#define LZOHTABLE_PUT(_table, _key_size, _key, _value, _out_hash)                     (lzohtable_put_x(_table, 0, 0, _key_size, _key, 0, _value, _out_hash))
#define LZOHTABLE_PUT_CPY_K(_table, _key_size, _key, _value, _out_hash)               (lzohtable_put_x(_table, 1, 0, _key_size, _key, 0, _value, _out_hash))
#define LZOHTABLE_PUT_CPY_V(_table, _key_size, _key, _value_size, _value, _out_hash)  (lzohtable_put_x(_table, 0, 1, _key_size, _key, _value_size, _value, _out_hash))
#define LZOHTABLE_PUT_CPY_KV(_table, _key_size, _key, _value_size, _value, _out_hash) (lzohtable_put_x(_table, 1, 1, _key_size, _key, _value_size, _value, _out_hash))

void lzohtable_remove_help(
    LZOHTable *table,
    size_t key_size,
    const void *key,
    const void *extra,
    lzohtable_clean_up clean_up_helper
);
#define LZOHTABLE_REMOVE(_table, _size, _key)(lzohtable_remove_help((_table), (_size), (_key), NULL, NULL))

#endif