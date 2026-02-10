#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

/*
 * Extended fuzzer: exercises parse variants, all print paths,
 * duplication, comparison, type checking, value access, minify,
 * and GetArrayItem / GetObjectItem traversal.
 */
static void exercise_item(const cJSON *item)
{
    /* type checks */
    (void)cJSON_IsInvalid(item);
    (void)cJSON_IsFalse(item);
    (void)cJSON_IsTrue(item);
    (void)cJSON_IsBool(item);
    (void)cJSON_IsNull(item);
    (void)cJSON_IsNumber(item);
    (void)cJSON_IsString(item);
    (void)cJSON_IsArray(item);
    (void)cJSON_IsObject(item);
    (void)cJSON_IsRaw(item);

    /* value access */
    (void)cJSON_GetStringValue(item);
    (void)cJSON_GetNumberValue(item);
}

static void walk_tree(const cJSON *item, int depth)
{
    const cJSON *child = NULL;
    if (item == NULL || depth > 20) return;

    exercise_item(item);

    if (cJSON_IsArray(item) || cJSON_IsObject(item))
    {
        int arr_size = cJSON_GetArraySize(item);
        if (arr_size > 0 && arr_size < 50)
        {
            /* exercise GetArrayItem at boundaries */
            (void)cJSON_GetArrayItem(item, 0);
            (void)cJSON_GetArrayItem(item, arr_size - 1);
            (void)cJSON_GetArrayItem(item, arr_size); /* out of bounds */
            (void)cJSON_GetArrayItem(item, -1);       /* negative index */
        }
    }

    if (cJSON_IsObject(item))
    {
        /* exercise object lookups with first child's key */
        child = item->child;
        if (child != NULL && child->string != NULL)
        {
            (void)cJSON_GetObjectItem(item, child->string);
            (void)cJSON_GetObjectItemCaseSensitive(item, child->string);
            (void)cJSON_HasObjectItem(item, child->string);
        }
        /* lookup with key that probably doesn't exist */
        (void)cJSON_GetObjectItem(item, "__nonexistent__");
        (void)cJSON_HasObjectItem(item, "");
    }

    /* recurse into children */
    cJSON_ArrayForEach(child, item)
    {
        walk_tree(child, depth + 1);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    cJSON *json = NULL;
    cJSON *json2 = NULL;
    cJSON *dup = NULL;
    char *printed = NULL;
    const char *return_parse_end = NULL;
    unsigned char *copied = NULL;
    char *prealloc_buf = NULL;

    if (size < 2) return 0;
    if (data[size - 1] != '\0') return 0;

    /* --- Parse variants --- */

    /* cJSON_Parse (basic) */
    json = cJSON_Parse((const char*)data);
    if (json == NULL) return 0;

    /* Walk the parsed tree exercising all type/access functions */
    walk_tree(json, 0);

    /* --- Print variants --- */

    /* cJSON_Print (formatted) */
    printed = cJSON_Print(json);
    if (printed != NULL) free(printed);

    /* cJSON_PrintUnformatted */
    printed = cJSON_PrintUnformatted(json);
    if (printed != NULL) free(printed);

    /* cJSON_PrintBuffered with varying prebuffer sizes */
    printed = cJSON_PrintBuffered(json, 1, 1);
    if (printed != NULL) free(printed);
    printed = cJSON_PrintBuffered(json, 1, 0);
    if (printed != NULL) free(printed);
    printed = cJSON_PrintBuffered(json, 256, 1);
    if (printed != NULL) free(printed);

    /* cJSON_PrintPreallocated - small buffer (may fail, that's fine) */
    prealloc_buf = (char*)malloc(64);
    if (prealloc_buf != NULL)
    {
        (void)cJSON_PrintPreallocated(json, prealloc_buf, 64, 1);
        (void)cJSON_PrintPreallocated(json, prealloc_buf, 64, 0);
        /* edge: very small buffer */
        (void)cJSON_PrintPreallocated(json, prealloc_buf, 1, 0);
        (void)cJSON_PrintPreallocated(json, prealloc_buf, 0, 0);
        free(prealloc_buf);
    }

    /* --- Duplicate --- */
    dup = cJSON_Duplicate(json, 1);
    if (dup != NULL)
    {
        /* Compare original with duplicate */
        (void)cJSON_Compare(json, dup, 1);
        (void)cJSON_Compare(json, dup, 0);

        /* Print the duplicate too */
        printed = cJSON_PrintUnformatted(dup);
        if (printed != NULL) free(printed);

        cJSON_Delete(dup);
    }

    /* Non-recursive duplicate */
    dup = cJSON_Duplicate(json, 0);
    if (dup != NULL)
    {
        (void)cJSON_Compare(json, dup, 1);
        cJSON_Delete(dup);
    }

    /* --- ParseWithLength --- */
    json2 = cJSON_ParseWithLength((const char*)data, size);
    if (json2 != NULL)
    {
        (void)cJSON_Compare(json, json2, 1);
        (void)cJSON_Compare(json, json2, 0);
        cJSON_Delete(json2);
    }

    /* ParseWithLengthOpts with return_parse_end */
    json2 = cJSON_ParseWithLengthOpts((const char*)data, size, &return_parse_end, 0);
    if (json2 != NULL)
    {
        cJSON_Delete(json2);
    }
    json2 = cJSON_ParseWithLengthOpts((const char*)data, size, &return_parse_end, 1);
    if (json2 != NULL)
    {
        cJSON_Delete(json2);
    }

    /* ParseWithOpts with return_parse_end */
    json2 = cJSON_ParseWithOpts((const char*)data, &return_parse_end, 0);
    if (json2 != NULL)
    {
        cJSON_Delete(json2);
    }
    json2 = cJSON_ParseWithOpts((const char*)data, &return_parse_end, 1);
    if (json2 != NULL)
    {
        cJSON_Delete(json2);
    }

    /* --- Minify --- */
    copied = (unsigned char*)malloc(size);
    if (copied != NULL)
    {
        memcpy(copied, data, size);
        cJSON_Minify((char*)copied);
        /* Parse the minified result */
        json2 = cJSON_Parse((const char*)copied);
        if (json2 != NULL)
        {
            (void)cJSON_Compare(json, json2, 0);
            cJSON_Delete(json2);
        }
        free(copied);
    }

    cJSON_Delete(json);

    return 0;
}

#ifdef __cplusplus
}
#endif
