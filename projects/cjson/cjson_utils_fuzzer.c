#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"
#include "../cJSON_Utils.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

/*
 * cJSON_Utils fuzzer: exercises JSON Pointer (RFC 6901),
 * JSON Patch (RFC 6902), Merge Patch (RFC 7386),
 * Sort, and FindPointer.
 *
 * Input format: two null-terminated JSON strings concatenated.
 * [json1\0json2\0]
 * json1 = target object
 * json2 = used as: pointer path, patch array, or second object for diff
 */

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    cJSON *obj1 = NULL;
    cJSON *obj2 = NULL;
    cJSON *result = NULL;
    cJSON *dup1 = NULL;
    cJSON *dup2 = NULL;
    char *pointer_result = NULL;
    const char *str1 = NULL;
    const char *str2 = NULL;
    size_t len1;

    const void *null_pos;

    if (size < 4) return 0;

    /* Find the first null byte to split the two strings */
    null_pos = memchr(data, '\0', size);
    if (null_pos == NULL) return 0;

    str1 = (const char*)data;
    len1 = (size_t)((const uint8_t*)null_pos - data);
    if (len1 == 0 || len1 >= size - 2) return 0;

    str2 = str1 + len1 + 1;
    /* str2 must also be null-terminated within bounds */
    if (memchr(str2, '\0', size - len1 - 1) == NULL) return 0;
    if (str2[0] == '\0') return 0;

    /* Parse both JSON strings */
    obj1 = cJSON_Parse(str1);
    if (obj1 == NULL) return 0;

    obj2 = cJSON_Parse(str2);

    /* --- JSON Pointer (RFC 6901) --- */
    /* Use str2 as a JSON Pointer path into obj1 */
    result = cJSONUtils_GetPointer(obj1, str2);
    (void)result;
    result = cJSONUtils_GetPointerCaseSensitive(obj1, str2);
    (void)result;

    /* --- Sort --- */
    /* Duplicate before sorting since sort modifies in place */
    dup1 = cJSON_Duplicate(obj1, 1);
    if (dup1 != NULL)
    {
        cJSONUtils_SortObject(dup1);
        cJSON_Delete(dup1);
    }
    dup1 = cJSON_Duplicate(obj1, 1);
    if (dup1 != NULL)
    {
        cJSONUtils_SortObjectCaseSensitive(dup1);
        cJSON_Delete(dup1);
    }

    /* --- FindPointerFromObjectTo --- */
    if (obj1->child != NULL)
    {
        pointer_result = cJSONUtils_FindPointerFromObjectTo(obj1, obj1->child);
        if (pointer_result != NULL) free(pointer_result);
    }
    /* Find pointer to self */
    pointer_result = cJSONUtils_FindPointerFromObjectTo(obj1, obj1);
    if (pointer_result != NULL) free(pointer_result);

    if (obj2 != NULL)
    {
        /* --- JSON Patch (RFC 6902) --- */
        /* Try obj2 as a patch array */
        dup1 = cJSON_Duplicate(obj1, 1);
        if (dup1 != NULL)
        {
            (void)cJSONUtils_ApplyPatches(dup1, obj2);
            cJSON_Delete(dup1);
        }
        dup1 = cJSON_Duplicate(obj1, 1);
        if (dup1 != NULL)
        {
            (void)cJSONUtils_ApplyPatchesCaseSensitive(dup1, obj2);
            cJSON_Delete(dup1);
        }

        /* --- Generate Patches (diff) --- */
        dup1 = cJSON_Duplicate(obj1, 1);
        dup2 = cJSON_Duplicate(obj2, 1);
        if (dup1 != NULL && dup2 != NULL)
        {
            result = cJSONUtils_GeneratePatches(dup1, dup2);
            if (result != NULL) cJSON_Delete(result);
        }
        if (dup1 != NULL) cJSON_Delete(dup1);
        if (dup2 != NULL) cJSON_Delete(dup2);

        dup1 = cJSON_Duplicate(obj1, 1);
        dup2 = cJSON_Duplicate(obj2, 1);
        if (dup1 != NULL && dup2 != NULL)
        {
            result = cJSONUtils_GeneratePatchesCaseSensitive(dup1, dup2);
            if (result != NULL) cJSON_Delete(result);
        }
        if (dup1 != NULL) cJSON_Delete(dup1);
        if (dup2 != NULL) cJSON_Delete(dup2);

        /* --- Merge Patch (RFC 7386) --- */
        /* MergePatch takes ownership of target: it either returns a
         * (possibly modified) target or deletes it and returns a new
         * object, or returns NULL after deleting target internally.
         * So we must never free dup1 ourselves after the call. */
        dup1 = cJSON_Duplicate(obj1, 1);
        if (dup1 != NULL)
        {
            result = cJSONUtils_MergePatch(dup1, obj2);
            if (result != NULL) cJSON_Delete(result);
        }

        dup1 = cJSON_Duplicate(obj1, 1);
        if (dup1 != NULL)
        {
            result = cJSONUtils_MergePatchCaseSensitive(dup1, obj2);
            if (result != NULL) cJSON_Delete(result);
        }

        /* --- Generate Merge Patch --- */
        dup1 = cJSON_Duplicate(obj1, 1);
        dup2 = cJSON_Duplicate(obj2, 1);
        if (dup1 != NULL && dup2 != NULL)
        {
            result = cJSONUtils_GenerateMergePatch(dup1, dup2);
            if (result != NULL) cJSON_Delete(result);
        }
        if (dup1 != NULL) cJSON_Delete(dup1);
        if (dup2 != NULL) cJSON_Delete(dup2);

        dup1 = cJSON_Duplicate(obj1, 1);
        dup2 = cJSON_Duplicate(obj2, 1);
        if (dup1 != NULL && dup2 != NULL)
        {
            result = cJSONUtils_GenerateMergePatchCaseSensitive(dup1, dup2);
            if (result != NULL) cJSON_Delete(result);
        }
        if (dup1 != NULL) cJSON_Delete(dup1);
        if (dup2 != NULL) cJSON_Delete(dup2);

        /* --- AddPatchToArray --- */
        dup1 = cJSON_CreateArray();
        if (dup1 != NULL)
        {
            cJSONUtils_AddPatchToArray(dup1, "add", str2, obj2);
            cJSONUtils_AddPatchToArray(dup1, "remove", str2, NULL);
            cJSONUtils_AddPatchToArray(dup1, "replace", "/test", obj1);
            cJSON_Delete(dup1);
        }

        cJSON_Delete(obj2);
    }

    cJSON_Delete(obj1);

    return 0;
}

#ifdef __cplusplus
}
#endif
