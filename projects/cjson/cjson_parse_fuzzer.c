#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

/*
 * Parse-focused fuzzer: specifically targets ParseWithLength variants
 * which do NOT require null-terminated input, enabling fuzzing of
 * buffer boundary handling. Also tests round-trip parse->print->parse
 * and partial parse scenarios.
 *
 * Unlike the original fuzzer, this does NOT require \0 termination,
 * so it reaches code paths handling unterminated buffers.
 */

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    cJSON *json = NULL;
    cJSON *json2 = NULL;
    cJSON *dup = NULL;
    char *printed = NULL;
    const char *return_parse_end = NULL;
    size_t sub_len;

    if (size < 1) return 0;

    /* --- ParseWithLength: no null termination required --- */
    json = cJSON_ParseWithLength((const char*)data, size);
    if (json == NULL)
    {
        /* Even on failure, exercise error reporting */
        (void)cJSON_GetErrorPtr();

        /* Try with opts to get parse end pointer */
        json = cJSON_ParseWithLengthOpts((const char*)data, size, &return_parse_end, 0);
        if (json == NULL)
        {
            /* Try requiring null termination (likely fails on non-terminated input) */
            json = cJSON_ParseWithLengthOpts((const char*)data, size, &return_parse_end, 1);
            if (json == NULL) return 0;
        }
    }

    /* --- Round-trip: print -> re-parse -> compare --- */
    printed = cJSON_PrintUnformatted(json);
    if (printed != NULL)
    {
        json2 = cJSON_Parse(printed);
        if (json2 != NULL)
        {
            /* Round-trip should produce equivalent JSON */
            (void)cJSON_Compare(json, json2, 1);
            cJSON_Delete(json2);
        }
        free(printed);
    }

    /* Round-trip with formatted print */
    printed = cJSON_Print(json);
    if (printed != NULL)
    {
        json2 = cJSON_Parse(printed);
        if (json2 != NULL)
        {
            (void)cJSON_Compare(json, json2, 0);
            cJSON_Delete(json2);
        }
        free(printed);
    }

    /* --- Partial length parsing --- */
    /* Parse with increasingly shorter lengths to stress boundary handling */
    if (size > 4)
    {
        sub_len = size / 2;
        json2 = cJSON_ParseWithLength((const char*)data, sub_len);
        if (json2 != NULL) cJSON_Delete(json2);

        sub_len = size - 1;
        json2 = cJSON_ParseWithLength((const char*)data, sub_len);
        if (json2 != NULL) cJSON_Delete(json2);

        /* Length of 0 */
        json2 = cJSON_ParseWithLength((const char*)data, 0);
        if (json2 != NULL) cJSON_Delete(json2);

        /* Length of 1 */
        json2 = cJSON_ParseWithLength((const char*)data, 1);
        if (json2 != NULL) cJSON_Delete(json2);
    }

    /* --- Duplicate with both modes --- */
    dup = cJSON_Duplicate(json, 1);
    if (dup != NULL)
    {
        char *p1 = cJSON_PrintUnformatted(json);
        char *p2 = cJSON_PrintUnformatted(dup);
        if (p1 != NULL) free(p1);
        if (p2 != NULL) free(p2);
        cJSON_Delete(dup);
    }

    /* --- PrintPreallocated with various sizes --- */
    {
        char small_buf[8];
        char medium_buf[256];
        (void)cJSON_PrintPreallocated(json, small_buf, (int)sizeof(small_buf), 0);
        (void)cJSON_PrintPreallocated(json, small_buf, (int)sizeof(small_buf), 1);
        (void)cJSON_PrintPreallocated(json, medium_buf, (int)sizeof(medium_buf), 0);
        (void)cJSON_PrintPreallocated(json, medium_buf, (int)sizeof(medium_buf), 1);
    }

    /* --- SetValuestring on string items --- */
    if (cJSON_IsString(json))
    {
        char *old = cJSON_SetValuestring(json, "fuzz_replacement");
        (void)old;
    }
    else if (cJSON_IsObject(json) || cJSON_IsArray(json))
    {
        cJSON *child = json->child;
        if (child != NULL && cJSON_IsString(child))
        {
            char *old = cJSON_SetValuestring(child, "fuzz_replacement");
            (void)old;
        }
    }

    /* --- SetNumberValue on number items --- */
    if (cJSON_IsNumber(json))
    {
        cJSON_SetNumberHelper(json, 3.14159);
        cJSON_SetNumberHelper(json, 0.0);
        cJSON_SetNumberHelper(json, -1e308);
        cJSON_SetNumberHelper(json, 1e308);
    }

    cJSON_Delete(json);

    return 0;
}

#ifdef __cplusplus
}
#endif
