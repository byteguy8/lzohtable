#include "lzohtable.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>

typedef struct lzohtable_slot{
    unsigned char    used;

    size_t           probe;
    lzohtable_hash_t hash;

    char             kcpy;
    char             vcpy;
    size_t           key_size;
    size_t           value_size;

    void             *key;
    void             *value;
}LZOHTableSlot;

typedef struct lzohtable{
    size_t                   n;          // count of distinct elements
    size_t                   m;          // count of slots
    float                    lfth;       // load factor threshold
    LZOHTableSlot            *slots;
    const LZOHTableAllocator *allocator;
}LZOHTable;

static inline void *lzalloc(const LZOHTableAllocator *allocator, size_t size){
    return allocator ? allocator->alloc(&allocator->ctx, size) : malloc(size);
}

static inline void *lzrealloc(const LZOHTableAllocator *allocator, void *ptr, size_t old_size, size_t new_size){
    return allocator ? allocator->realloc(&allocator->ctx, ptr, old_size, new_size) : realloc(ptr, new_size);
}

static inline void lzdealloc(const LZOHTableAllocator *allocator, void *ptr, size_t size){
    allocator ? allocator->dealloc(&allocator->ctx, ptr, size) : free(ptr);
}

#define MEMORY_ALLOC(_allocator, _type, _count)                         ((_type *)lzalloc((_allocator), sizeof(_type) * (_count)))
#define MEMORY_REALLOC(_allocator, _ptr, _type, _old_count, _new_count) ((type *)(lzrealloc((_allocator), (_ptr), sizeof(_type) * (_old_count), sizeof(_type) * (_new_count))))
#define MEMORY_DEALLOC(_allocator, _ptr, _type, _count)                 (lzdealloc((_allocator), (_ptr), sizeof(_type) * (_count)))

#define SLOT_SIZE sizeof(LZOHTableSlot)

static inline int is_power_of_two(uintptr_t x){
    return (x & (x - 1)) == 0;
}

static inline lzohtable_hash_t fnv_1a_hash(size_t key_size, const uint8_t *key){
    const uint64_t prime = 0x00000100000001b3;
    const uint64_t basis = 0xcbf29ce484222325;
    uint64_t hash = basis;

    for (size_t i = 0; i < key_size; i++){
        hash ^= key[i];
        hash *= prime;
    }

    return hash;
}

static LZOHTableSlot* robin_hood_lookup(const void *key, size_t key_size, LZOHTable *table, size_t *out_idx){
    size_t m = table->m;
    LZOHTableSlot *slots = table->slots;
    lzohtable_hash_t hash = fnv_1a_hash(key_size, key);
    size_t i = hash & (m - 1);
    size_t probe = 0;

    while (1){
        LZOHTableSlot slot = slots[i];

        if(!slot.used){
            break;
        }

        if(slot.probe < probe){
            break;
        }

        if(key_size == slot.key_size && memcmp(key, slot.key, key_size) == 0){
            if(out_idx){
                *out_idx = i;
            }

            return slots + i;
        }

        i = (i + 1) & (m - 1);
        probe++;
    }

    return NULL;
}

static int robin_hood_insert(
    LZOHTableSlot *slots,
    LZOHTableSlot moving_slot,
    size_t m,
    char *out_vcpy,
    size_t *out_old_value_size,
    void **out_old_value
){
    size_t count = 0;
    size_t i = moving_slot.hash & (m - 1);;

    while(count < m){
        LZOHTableSlot current_slot = slots[i];

        if(current_slot.used){
            if(moving_slot.key_size == current_slot.key_size &&
               memcmp(moving_slot.key, current_slot.key, moving_slot.key_size) == 0
            ){
                if(out_vcpy){
                    *out_vcpy = current_slot.vcpy;
                }

                if(out_old_value){
                    *out_old_value = current_slot.value;
                }

                if(out_old_value_size){
                    *out_old_value_size = current_slot.value_size;
                }

                LZOHTableSlot *final_slot = slots + i;

                final_slot->value_size = moving_slot.value_size;
                final_slot->value = moving_slot.value;

                return 2;
            }

            if(moving_slot.probe > current_slot.probe){
                LZOHTableSlot rich_slot = current_slot;

                *(slots + i) = moving_slot;
                moving_slot = rich_slot;
            }

            count++;
            moving_slot.probe++;
            i = (i + 1) & (m - 1);

            continue;
        }

        *(slots + i) = moving_slot;

        return 3;
    }

    return 1;
}

static LZOHTableSlot *create_slots(const LZOHTableAllocator *allocator, size_t m){
    assert(is_power_of_two(m));

    LZOHTableSlot *slots = MEMORY_ALLOC(allocator, LZOHTableSlot, m);

    if(!slots){
        return NULL;
    }

    memset(slots, 0, SLOT_SIZE * m);

    return slots;
}

static inline void destroy_slots(const LZOHTableAllocator *allocator, size_t m, LZOHTableSlot *slots){
    MEMORY_DEALLOC(allocator, slots, LZOHTableSlot, m);
}

static LZOHTableSlot *grow_slots(const LZOHTableAllocator *allocator, size_t old_m, size_t *out_new_m){
    assert(is_power_of_two(old_m));

    size_t new_m = old_m * 2;
    LZOHTableSlot *new_slots = MEMORY_ALLOC(allocator, LZOHTableSlot, new_m);

    if(!new_slots){
        return NULL;
    }

    memset(new_slots, 0, SLOT_SIZE * new_m);

    if(out_new_m){
        *out_new_m = new_m;
    }

    return new_slots;
}

int copy_paste_slots(LZOHTable *table){
    size_t new_m;
    size_t old_m = table->m;
    LZOHTableSlot *old_slots = table->slots;
    const LZOHTableAllocator *allocator = table->allocator;
    LZOHTableSlot *new_slots = grow_slots(allocator, old_m, &new_m);

    if(!new_slots){
        return 1;
    }

    for (size_t i = 0; i < old_m; i++){
        LZOHTableSlot old_slot = old_slots[i];

        if(!old_slot.used){
            continue;
        }

        LZOHTableSlot moving_slot = (LZOHTableSlot){
            .used       = 1,
            .hash       = old_slot.hash,
            .probe      = 0,
            .kcpy       = old_slot.kcpy,
            .vcpy       = old_slot.vcpy,
            .key_size   = old_slot.key_size,
            .value_size = old_slot.value_size,
            .key        = old_slot.key,
            .value      = old_slot.value
        };

        robin_hood_insert(
            new_slots,
            moving_slot,
            new_m,
            NULL,
            NULL,
            NULL
        );
    }

    destroy_slots(allocator, old_m, old_slots);

    table->m = new_m;
    table->slots = new_slots;

    return 0;
}

LZOHTable *lzohtable_create(const LZOHTableAllocator *allocator, size_t m, float lfth){
    LZOHTableSlot *slots = create_slots(allocator, m);
    LZOHTable *table = MEMORY_ALLOC(allocator, LZOHTable, 1);

    if(!slots || !table){
        destroy_slots(allocator, m, slots);
        MEMORY_DEALLOC(allocator, table, LZOHTable, 1);

        return NULL;
    }

    table->n = 0;
    table->m = m;
    table->lfth = lfth;
    table->slots = slots;
    table->allocator = allocator;

    return table;
}

void lzohtable_destroy_help(LZOHTable *table, const void *extra, lzohtable_clean_up clean_up_helper){
    if(!table){
        return;
    }

    const LZOHTableAllocator *allocator = table->allocator;

    lzohtable_clear_help(table, extra, clean_up_helper);
    destroy_slots(allocator, table->m, table->slots);
    MEMORY_DEALLOC(allocator, table, LZOHTable, 1);
}

inline size_t lzohtable_m(const LZOHTable *table){
    return table->m;
}

inline size_t lzohtable_n(const LZOHTable *table){
    return table->n;
}

inline float lzohtable_lfth(const LZOHTable *table){
    return table->lfth;
}

void lzohtable_print(const LZOHTable *table, lzohtable_print_helper print_helper){
    size_t count = 1;
    size_t n = table->n;
    size_t m = table->m;

    for (size_t i = 0; i < m; i++){
        LZOHTableSlot slot = table->slots[i];

        if(slot.used){
            print_helper(
                count++,
                n,
                i,
                slot.probe,
                slot.key_size,
                slot.value_size,
                slot.key,
                slot.value
            );
        }
    }
}

inline void lzohtable_iterator(const LZOHTable *table, LZOHTableIterator *iterator){
    *iterator = (LZOHTableIterator){
        .counter   = 0,
        .current   = 0,
        .key_value = {
            .key_size   = 0,
            .value_size = 0,
            .key        = NULL,
            .value      = NULL,
        },
        .table    = table
    };
}

inline int lzohtable_iterator_has_next(const LZOHTableIterator *iterator){
    return iterator->counter < iterator->table->n;
}

LZOHTableKeyValue *lzohtable_iterator_next(LZOHTableIterator *iterator){
    const LZOHTable *table = iterator->table;
    const LZOHTableSlot *slots = table->slots;
    size_t counter = iterator->counter;
    size_t m = table->m;

    if(counter >= table->n){
        return NULL;
    }

    size_t i = iterator->current;
    LZOHTableKeyValue key_value = {0};

    while (i < m){
        LZOHTableSlot slot = slots[i++];

        if(!slot.used){
            continue;
        }

        counter++;

        key_value = (LZOHTableKeyValue){
            .key_size   = slot.key_size,
            .value_size = slot.value_size,
            .key        = slot.key,
            .value      = slot.value
        };

        break;
    }

    iterator->counter = counter;
    iterator->current = i;
    iterator->key_value = key_value;

    return &iterator->key_value;
}

int lzohtable_lookup(const LZOHTable *table, size_t key_size, const void *key, void **out_value){
    lzohtable_hash_t hash = fnv_1a_hash(key_size, key);
    size_t i = hash & (table->m - 1);
    size_t m = table->m;
    size_t probe = 0;

    while (1){
        LZOHTableSlot slot = table->slots[i];

        if(!slot.used){
            break;
        }

        if(slot.probe < probe){
            break;
        }

        if(key_size == slot.key_size && memcmp(key, slot.key, key_size) == 0){
            if(out_value){
                *out_value = slot.value;
            }

            return 1;
        }

        i = (i + 1) & (m - 1);
        probe++;
    }

    return 0;
}

void lzohtable_clear_help(LZOHTable *table, const void *extra, lzohtable_clean_up clean_up_helper){
    size_t m = table->m;
    LZOHTableSlot *slots = table->slots;
    const LZOHTableAllocator *allocator = table->allocator;

    for (size_t i = 0; i < m; i++){
        LZOHTableSlot *slot = &slots[i];

        if(slot->used){
            char kcpy = slot->kcpy;
            char vcpy = slot->vcpy;
            size_t slot_key_size = slot->key_size;
            size_t slot_value_size = slot->value_size;
            void *slot_key = slot->key;
            void *slot_value = slot->value;

            void *external_key = kcpy ? NULL : slot_key;
            void *external_value = vcpy ? NULL : slot_value;

            if(clean_up_helper){
                clean_up_helper(external_key, external_value, (void *)extra);
            }

            if(kcpy){
                MEMORY_DEALLOC(allocator, slot_key, char, slot_key_size);
            }

            if(vcpy){
                MEMORY_DEALLOC(allocator, slot_value, char, slot_value_size);
            }

            memset(slot, 0, SLOT_SIZE);
        }
    }

    table->n = 0;
}

int lzohtable_put_x(
    LZOHTable *table,
    char cpy_k,
    char cpy_v,
    size_t key_size,
    const void *key,
    size_t value_size,
    const void *value,
    lzohtable_hash_t *out_hash
){
    const LZOHTableAllocator *allocator = table->allocator;
    void *real_key = (void *)key;
    void *real_value = (void *)value;

    if(cpy_k){
        if(!(real_key = MEMORY_ALLOC(allocator, char, key_size))){
            goto ERROR;
        }

        memcpy(real_key, key, key_size);
    }

    if(cpy_v){
        if(!(real_value = MEMORY_ALLOC(allocator, char, value_size))){
            goto ERROR;
        }

        memcpy(real_value, value, value_size);
    }

    if(LZOHTABLE_LOAD_FACTOR(table) >= table->lfth && copy_paste_slots(table)){
        goto ERROR;
    }

    lzohtable_hash_t hash = fnv_1a_hash(key_size, real_key);
    LZOHTableSlot moving_slot = (LZOHTableSlot){
        .used       = 1,
        .hash       = hash,
        .probe      = 0,
        .kcpy       = cpy_k,
        .vcpy       = cpy_v,
        .key_size   = key_size,
        .value_size = value_size,
        .key        = real_key,
        .value      = real_value
    };
    char old_vcpy;
    size_t old_value_size;
    void *old_value = NULL;

    switch (robin_hood_insert(table->slots, moving_slot, table->m, &old_vcpy, &old_value_size, &old_value)){
        case 2:{
            // The 'key' already exist
            MEMORY_DEALLOC(allocator, real_key, char, key_size);

            if(old_vcpy){
                MEMORY_DEALLOC(allocator, old_value, char, old_value_size);
            }

            break;
        }case 3:{
            // The 'key' did not exist (new 'register')
            table->n++;
            break;
        }default:{
            break;
        }
    }

    if(out_hash){
        *out_hash = hash;
    }

    goto OK;

ERROR:
    if(cpy_k){
        MEMORY_DEALLOC(allocator, real_key, char, key_size);
    }

    if(cpy_v){
        MEMORY_DEALLOC(allocator, real_value, char, value_size);
    }

    return 1;

OK:
    return 0;
}

void lzohtable_remove_help(
    LZOHTable *table,
    size_t key_size,
    const void *key,
    const void *extra,
    lzohtable_clean_up clean_up_helper
){
    size_t idx;
    LZOHTableSlot *slot = robin_hood_lookup(key, key_size, table, &idx);

    if(!slot){
        return;
    }

    size_t m = table->m;
    const LZOHTableAllocator *allocator = table->allocator;

    char kcpy = slot->kcpy;
    char vcpy = slot->vcpy;
    void *slot_key = slot->key;
    void *slot_value = slot->value;

    void *external_key = kcpy ? NULL : slot_key;
    void *external_value = vcpy ? NULL : slot_value;

    if(clean_up_helper){
        clean_up_helper(external_key, external_value, (void *)extra);
    }

    if(kcpy){
        MEMORY_DEALLOC(allocator, slot_key, char, slot->key_size);
    }

    if(vcpy){
        MEMORY_DEALLOC(allocator, slot_value, char, slot->value_size);
    }

    memset(slot, 0, SLOT_SIZE);

    size_t i = (idx + 1) & (m - 1);

    while(1){
        LZOHTableSlot *current_slot = &table->slots[i];

        if(current_slot->used){
            if(current_slot->probe == 0){
                break;
            }

            LZOHTableSlot *previous_slot = &table->slots[(i - 1) & (m - 1)];

            *previous_slot = *current_slot;
            previous_slot->probe--;

            memset(current_slot, 0, SLOT_SIZE);
        }else{
            break;
        }

        i = (i + 1) & (m - 1);
    }

    table->n--;
}