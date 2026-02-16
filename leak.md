# OpenLDAP Schema Parser Memory Leak — Missing `LDAP_FREE(sval)` in X-Extension Error Path

## Summary

All 8 `ldap_str2*()` schema parsing functions in `libraries/libldap/schema.c` leak the
token string `sval` when an `X-` extension keyword is followed by an invalid (non-quoted)
value, causing `parse_qdescrs()` to fail. The allocated token is never freed before the
function returns NULL.

**File:** `libraries/libldap/schema.c`
**Commit tested:** `1885843be4` (OpenLDAP master, tag `LMDB_0.9.34-23312`)
**Last change to file:** `073232bbc7` (2024-03-26)
**Severity:** Memory leak (code quality bug)

## Root Cause

In each `ldap_str2*()` function, the main parsing loop calls `get_token(&ss, &sval)` which
allocates `sval` via `LDAP_MALLOC`. When `sval` is a bareword starting with `X-`, the code
enters the extension-handling branch:

```c
// schema.c, e.g. line 1795 in ldap_str2matchingrule()
} else if ( sval[0] == 'X' && sval[1] == '-' ) {
    ext_vals = parse_qdescrs(&ss, code);
    if ( !ext_vals ) {
        *errp = ss;
        ldap_matchingrule_free(mr);
        return NULL;           // BUG: sval is leaked here
    }
    if ( add_extension(&mr->mr_extensions, sval, ext_vals) ) {
        *code = LDAP_SCHERR_OUTOFMEM;
        *errp = ss;
        LDAP_FREE(sval);      // Correctly freed in this path
        ldap_matchingrule_free(mr);
        return NULL;
    }
```

When `parse_qdescrs()` returns NULL (because the next token is not a quoted string like
`'value'`), the function frees the parent struct and returns NULL — but `sval` (the `X-...`
token) is not freed. The `add_extension` failure path a few lines below correctly calls
`LDAP_FREE(sval)`, proving this is a missing cleanup, not a design choice.

## All 8 Affected Functions

| Line | Function | Leaked at |
|------|----------|-----------|
| 1598 | `ldap_str2syntax()` | line 1602 |
| 1798 | `ldap_str2matchingrule()` | line 1801 |
| 1997 | `ldap_str2matchingruleuse()` | line 2000 |
| 2386 | `ldap_str2attributetype()` | line 2389 |
| 2678 | `ldap_str2objectclass()` | line 2681 |
| 2941 | `ldap_str2contentrule()` | line 2944 |
| 3124 | `ldap_str2structurerule()` | line 3127 |
| 3345 | `ldap_str2nameform()` | line 3348 |

All 8 have identical structure: `LDAP_FREE(sval)` is missing in the `!ext_vals` error path
but present in the `add_extension` failure path immediately below.

## Proof of Concept

### Minimal C reproducer

```c
/*
 * PoC: OpenLDAP schema parser memory leak via X- extension error path
 *
 * Compile against OpenLDAP's libldap:
 *   cc -o schema_leak schema_leak.c -I/path/to/openldap/include \
 *      /path/to/libldap.a /path/to/liblber.a /path/to/liblutil.a
 *
 * Run under a leak detector:
 *   ASAN_OPTIONS=detect_leaks=1 ./schema_leak
 *   valgrind --leak-check=full ./schema_leak
 */
#include <stdio.h>
#include <ldap.h>
#include <ldap_schema.h>

int main(void) {
    int code;
    const char *errp;

    /*
     * Trigger: A schema definition with an X- extension keyword followed by
     * a non-quoted value. parse_qdescrs() expects 'quoted' or ( 'list' )
     * after the extension keyword, but gets a bare byte instead.
     *
     * The X- token "X-\x8d" is allocated by get_token() but never freed
     * when parse_qdescrs() fails.
     */

    /* --- Leak in ldap_str2objectclass --- */
    const char *oc_input = "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL X-BAD unquoted )";
    LDAPObjectClass *oc = ldap_str2objectclass(oc_input, &code, &errp, LDAP_SCHEMA_ALLOW_ALL);
    if (oc) ldap_objectclass_free(oc);  /* won't be reached — parse fails */

    /* --- Leak in ldap_str2attributetype --- */
    const char *at_input = "( 2.5.4.3 NAME 'cn' X-ORIGIN unquoted )";
    LDAPAttributeType *at = ldap_str2attributetype(at_input, &code, &errp, LDAP_SCHEMA_ALLOW_ALL);
    if (at) ldap_attributetype_free(at);

    /* --- Leak in ldap_str2matchingrule --- */
    const char *mr_input = "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-BAD unquoted )";
    LDAPMatchingRule *mr = ldap_str2matchingrule(mr_input, &code, &errp, LDAP_SCHEMA_ALLOW_ALL);
    if (mr) ldap_matchingrule_free(mr);

    /* --- Leak in ldap_str2syntax --- */
    const char *syn_input = "( 1.3.6.1.4.1.1466.115.121.1.15 X-BAD unquoted )";
    LDAPSyntax *syn = ldap_str2syntax(syn_input, &code, &errp, LDAP_SCHEMA_ALLOW_ALL);
    if (syn) ldap_syntax_free(syn);

    /* --- Amplification: call in a loop to leak unbounded memory --- */
    printf("Leaking in a loop (1000 iterations)...\n");
    for (int i = 0; i < 1000; i++) {
        oc = ldap_str2objectclass(oc_input, &code, &errp, LDAP_SCHEMA_ALLOW_ALL);
        if (oc) ldap_objectclass_free(oc);
    }
    printf("Done. Each iteration leaks the X-BAD token allocation.\n");

    return 0;
}
```

### Fuzzer-discovered minimal input

The fuzzer found this 5-byte input triggers the leak in `ldap_str2matchingrule`:

```
Hex:    73 28 58 2d 8d
ASCII:  s(X-\x8d
Base64: cyhYLY0=
```

Breakdown (with the harness's selector-byte prefix):
- Byte 0: `0x73` → selector byte (0x73 % 8 = 3 → `ldap_str2matchingrule`)
- Bytes 1-4: `(X-\x8d` → the schema string passed to the parser

The parser:
1. Sees `(` — valid left paren
2. Fails to parse a numeric OID (no digits after `(`)
3. With `LDAP_SCHEMA_ALLOW_ALL`, backtracks and enters the keyword loop
4. `get_token()` returns `TK_BAREWORD` with `sval = "X-\x8d"` (3 bytes allocated)
5. Enters the `X-` extension branch
6. `parse_qdescrs()` fails — next token after `X-\x8d` is `EOS`, not a quoted string
7. Returns NULL without calling `LDAP_FREE(sval)` — **3 bytes leaked**

### Where the affected code is called (server-side)

On the server side, the affected parser functions are called when processing schema
definitions via `cn=config`. An authenticated administrator modifying schema attributes
(`olcAttributeTypes`, `olcObjectClasses`, `olcDitContentRules`) with a malformed `X-`
extension will trigger the leak:

```bash
# Requires admin credentials to cn=config
ldapmodify -H ldap://target:389 -D "cn=admin,cn=config" -w secret <<EOF
dn: cn={0}core,cn=schema,cn=config
changetype: modify
add: olcObjectClasses
olcObjectClasses: ( 1.3.6.1.4.1.99999.1.1 NAME 'leakTest' SUP top STRUCTURAL X-LEAK unquoted )
EOF
```

Each such request leaks the `X-LEAK` token string (7 bytes). The operation fails
(returning `LDAP_INVALID_SYNTAX`), but the memory is already leaked before the error
is returned. Triggering requires authenticated admin access, and each iteration leaks
only a few bytes, so this is not a realistic DoS vector — it would take tens of millions
of iterations to leak a significant amount of memory.

## Impact

- **Client-side impact**: Any application using `libldap` to parse schema strings
  (e.g., from LDAP search results on `cn=subschema`) will leak memory if the schema
  contains malformed extensions. A malicious LDAP server returning crafted schema
  definitions to a client could trigger repeated leaks.
- **Server-side impact**: An authenticated admin with write access to `cn=config`
  can trigger the leak by sending malformed schema definitions. Each iteration leaks
  only a few bytes, so practical memory exhaustion would require sustained automated
  requests over a long period.
- **Long-running processes**: The leak accumulates across iterations since OpenLDAP's
  schema parser has no cleanup for this error path.

## Fix

Add `LDAP_FREE(sval);` before the `return NULL;` in the `!ext_vals` error path of each
of the 8 affected functions. For example, in `ldap_str2matchingrule()`:

```c
} else if ( sval[0] == 'X' && sval[1] == '-' ) {
    ext_vals = parse_qdescrs(&ss, code);
    if ( !ext_vals ) {
        *errp = ss;
        LDAP_FREE(sval);              // <-- ADD THIS LINE
        ldap_matchingrule_free(mr);
        return NULL;
    }
```

Apply the same one-line fix at all 8 locations listed above.
