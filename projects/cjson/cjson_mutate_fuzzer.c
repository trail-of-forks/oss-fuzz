#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

/*
 * Mutation fuzzer: parses JSON, then uses trailing fuzz bytes as
 * opcodes to drive a sequence of structural mutations on the tree:
 * AddItemToArray, AddItemToObject, InsertItemInArray, ReplaceItemInArray,
 * DetachItemFromArray, DeleteItemFromArray, DetachItemFromObject,
 * DeleteItemFromObject, ReplaceItemInObject, Add*ToObject helpers,
 * and creation functions.
 *
 * Input format: [json\0][opcode bytes...]
 * The json part is parsed, then each opcode byte selects a mutation.
 */

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    cJSON *root = NULL;
    cJSON *target = NULL;
    cJSON *item = NULL;
    cJSON *detached = NULL;
    char *printed = NULL;
    size_t json_len;
    size_t op_offset;
    size_t i;
    const void *null_pos;

    if (size < 4) return 0;

    /* Find first null byte within bounds to split JSON from opcodes */
    null_pos = memchr(data, '\0', size);
    if (null_pos == NULL) return 0;

    json_len = (size_t)((const uint8_t*)null_pos - data);
    if (json_len == 0 || json_len >= size - 1) return 0;

    root = cJSON_Parse((const char*)data);
    if (root == NULL) return 0;

    /* opcodes start after the JSON string's null terminator */
    op_offset = json_len + 1;

    for (i = op_offset; i < size; i++)
    {
        unsigned char op = data[i];

        /* Pick target: root itself if array/object, else skip */
        target = root;
        if (!cJSON_IsArray(target) && !cJSON_IsObject(target))
        {
            /* try to use root's child chain */
            if (target->child != NULL && (cJSON_IsArray(target->child) || cJSON_IsObject(target->child)))
            {
                target = target->child;
            }
            else
            {
                break;
            }
        }

        switch (op % 16)
        {
            case 0: /* AddItemToArray with new number */
                if (cJSON_IsArray(target))
                {
                    item = cJSON_CreateNumber((double)(op));
                    if (item != NULL) cJSON_AddItemToArray(target, item);
                }
                break;

            case 1: /* AddItemToObject with new string */
                if (cJSON_IsObject(target))
                {
                    item = cJSON_CreateString("fuzz_val");
                    if (item != NULL) cJSON_AddItemToObject(target, "fuzz_key", item);
                }
                break;

            case 2: /* InsertItemInArray */
                if (cJSON_IsArray(target))
                {
                    int arr_size = cJSON_GetArraySize(target);
                    item = cJSON_CreateTrue();
                    if (item != NULL)
                    {
                        if (!cJSON_InsertItemInArray(target, (int)(op % (unsigned char)(arr_size > 0 ? arr_size : 1)), item))
                        {
                            cJSON_Delete(item);
                        }
                    }
                }
                break;

            case 3: /* DetachItemFromArray */
                if (cJSON_IsArray(target))
                {
                    int arr_size = cJSON_GetArraySize(target);
                    if (arr_size > 0)
                    {
                        detached = cJSON_DetachItemFromArray(target, (int)(op % (unsigned char)arr_size));
                        if (detached != NULL) cJSON_Delete(detached);
                    }
                }
                break;

            case 4: /* DeleteItemFromArray */
                if (cJSON_IsArray(target))
                {
                    int arr_size = cJSON_GetArraySize(target);
                    if (arr_size > 0)
                    {
                        cJSON_DeleteItemFromArray(target, (int)(op % (unsigned char)arr_size));
                    }
                }
                break;

            case 5: /* ReplaceItemInArray */
                if (cJSON_IsArray(target))
                {
                    int arr_size = cJSON_GetArraySize(target);
                    if (arr_size > 0)
                    {
                        item = cJSON_CreateNull();
                        if (item != NULL)
                        {
                            if (!cJSON_ReplaceItemInArray(target, (int)(op % (unsigned char)arr_size), item))
                            {
                                cJSON_Delete(item);
                            }
                        }
                    }
                }
                break;

            case 6: /* DetachItemFromObject */
                if (cJSON_IsObject(target) && target->child != NULL && target->child->string != NULL)
                {
                    detached = cJSON_DetachItemFromObject(target, target->child->string);
                    if (detached != NULL) cJSON_Delete(detached);
                }
                break;

            case 7: /* DeleteItemFromObject */
                if (cJSON_IsObject(target) && target->child != NULL && target->child->string != NULL)
                {
                    cJSON_DeleteItemFromObject(target, target->child->string);
                }
                break;

            case 8: /* ReplaceItemInObject */
                if (cJSON_IsObject(target) && target->child != NULL && target->child->string != NULL)
                {
                    item = cJSON_CreateNumber(42.0);
                    if (item != NULL)
                    {
                        if (!cJSON_ReplaceItemInObject(target, target->child->string, item))
                        {
                            cJSON_Delete(item);
                        }
                    }
                }
                break;

            case 9: /* AddNullToObject / AddBoolToObject */
                if (cJSON_IsObject(target))
                {
                    (void)cJSON_AddNullToObject(target, "fz_null");
                    (void)cJSON_AddBoolToObject(target, "fz_bool", op % 2);
                }
                break;

            case 10: /* AddNumberToObject / AddStringToObject */
                if (cJSON_IsObject(target))
                {
                    (void)cJSON_AddNumberToObject(target, "fz_num", (double)op);
                    (void)cJSON_AddStringToObject(target, "fz_str", "fuzz");
                }
                break;

            case 11: /* AddObjectToObject / AddArrayToObject */
                if (cJSON_IsObject(target))
                {
                    (void)cJSON_AddObjectToObject(target, "fz_obj");
                    (void)cJSON_AddArrayToObject(target, "fz_arr");
                }
                break;

            case 12: /* AddItemToObjectCS */
                if (cJSON_IsObject(target))
                {
                    item = cJSON_CreateFalse();
                    if (item != NULL) cJSON_AddItemToObjectCS(target, "fz_cs", item);
                }
                break;

            case 13: /* AddRawToObject / AddTrueToObject / AddFalseToObject */
                if (cJSON_IsObject(target))
                {
                    (void)cJSON_AddRawToObject(target, "fz_raw", "[1,2]");
                    (void)cJSON_AddTrueToObject(target, "fz_true");
                    (void)cJSON_AddFalseToObject(target, "fz_false");
                }
                break;

            case 14: /* DetachItemFromObjectCaseSensitive / DeleteItemFromObjectCaseSensitive */
                if (cJSON_IsObject(target) && target->child != NULL && target->child->string != NULL)
                {
                    if (op % 2)
                    {
                        detached = cJSON_DetachItemFromObjectCaseSensitive(target, target->child->string);
                        if (detached != NULL) cJSON_Delete(detached);
                    }
                    else
                    {
                        cJSON_DeleteItemFromObjectCaseSensitive(target, target->child->string);
                    }
                }
                break;

            case 15: /* ReplaceItemInObjectCaseSensitive / ReplaceItemViaPointer */
                if (cJSON_IsObject(target) && target->child != NULL && target->child->string != NULL)
                {
                    item = cJSON_CreateRaw("{\"raw\":true}");
                    if (item != NULL)
                    {
                        if (op % 2)
                        {
                            if (!cJSON_ReplaceItemInObjectCaseSensitive(target, target->child->string, item))
                            {
                                cJSON_Delete(item);
                            }
                        }
                        else
                        {
                            if (!cJSON_ReplaceItemViaPointer(target, target->child, item))
                            {
                                cJSON_Delete(item);
                            }
                        }
                    }
                }
                break;
        }

        /* Safety: stop if tree gets too large */
        if (cJSON_GetArraySize(target) > 200)
        {
            break;
        }
    }

    /* Print the mutated tree to exercise printer on modified structures */
    printed = cJSON_PrintUnformatted(root);
    if (printed != NULL) free(printed);

    printed = cJSON_Print(root);
    if (printed != NULL) free(printed);

    cJSON_Delete(root);

    return 0;
}

#ifdef __cplusplus
}
#endif
