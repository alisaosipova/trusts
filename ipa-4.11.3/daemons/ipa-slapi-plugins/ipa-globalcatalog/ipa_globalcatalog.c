/** BEGIN COPYRIGHT BLOCK
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 *
 * Authors:
 *   Filip Křepelka <filip.krepelka@redhat.com>
 *   Jan Cholasta <jcholast@redhat.com>
 *
 * Copyright (C) 2024  FreeIPA Contributors
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include <dirsrv/slapi-plugin.h>

#include "util.h"

#define IPA_GC_PLUGIN_DESC "IPA global catalog attribute synthesiser"
#define IPA_GC_PLUGIN_FEATURE "ipa-globalcatalog"

#define IPA_GC_ATTR_SAMACCOUNTNAME "sAMAccountName"
#define IPA_GC_ATTR_UPN "userPrincipalName"
#define IPA_GC_ATTR_OBJECTSID "objectSid"

#define IPA_GC_ATTR_UID "uid"
#define IPA_GC_ATTR_KRBPN "krbPrincipalName"
#define IPA_GC_ATTR_SID "ipaNTSecurityIdentifier"

struct ipa_gc_ctx {
    Slapi_ComponentId *plugin_id;
    Slapi_DN *base_sdn;
    char *basedn;
    char *realm;
    bool fallback_group_checked;
    bool fallback_group_available;
    char *fallback_group_dn;
    char *fallback_group_rid_str;
};

static int ipa_gc_post_add(Slapi_PBlock *pb);
static int ipa_gc_post_modify(Slapi_PBlock *pb);

Slapi_PluginDesc ipa_globalcatalog_plugin_desc = {
    IPA_GC_PLUGIN_FEATURE,
    "FreeIPA project",
    "FreeIPA/1.0",
    IPA_GC_PLUGIN_DESC
};

static void ipa_gc_ctx_free(struct ipa_gc_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->base_sdn != NULL) {
        slapi_sdn_free(&ctx->base_sdn);
    }
    slapi_ch_free_string(&ctx->basedn);
    slapi_ch_free_string(&ctx->realm);
    slapi_ch_free_string(&ctx->fallback_group_dn);
    slapi_ch_free_string(&ctx->fallback_group_rid_str);
    slapi_ch_free((void **)&ctx);
}

static bool ipa_gc_skip_operation(Slapi_PBlock *pb)
{
    int is_internal = 0;
    int is_replicated = 0;

    if (slapi_pblock_get(pb, SLAPI_IS_INTERNAL_OPERATION, &is_internal) != 0) {
        LOG_FATAL("Unable to determine whether operation is internal.\n");
        return true;
    }
    if (is_internal != 0) {
        return true;
    }

    if (slapi_pblock_get(pb, SLAPI_IS_REPLICATED_OPERATION, &is_replicated) != 0) {
        LOG_FATAL("Unable to determine whether operation is replicated.\n");
        return true;
    }
    if (is_replicated != 0) {
        return true;
    }

    return false;
}

static bool ipa_gc_value_equal(const char *existing, const char *wanted)
{
    if (existing == NULL && wanted == NULL) {
        return true;
    }
    if (existing == NULL || wanted == NULL) {
        return false;
    }

    return strcasecmp(existing, wanted) == 0;
}

static int ipa_gc_sid_string_to_berval(const char *sid_str, struct berval **bv_out)
{
    const char *pos;
    char *end = NULL;
    unsigned long revision;
    unsigned long long identifier_authority;
    uint32_t sub_authorities[15];
    size_t subauth_count = 0;
    unsigned char *buffer = NULL;
    struct berval *bv = NULL;
    size_t offset;

    if (sid_str == NULL || bv_out == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    if (strncasecmp(sid_str, "S-", 2) != 0) {
        return LDAP_INVALID_SYNTAX;
    }

    pos = sid_str + 2;
    errno = 0;
    revision = strtoul(pos, &end, 10);
    if (errno != 0 || pos == end || *end != '-') {
        return LDAP_INVALID_SYNTAX;
    }

    pos = end + 1;
    errno = 0;
    identifier_authority = strtoull(pos, &end, 10);
    if (errno != 0 || pos == end) {
        return LDAP_INVALID_SYNTAX;
    }

    while (*end == '-') {
        uint32_t subauth;

        if (subauth_count >= sizeof(sub_authorities) / sizeof(sub_authorities[0])) {
            return LDAP_INVALID_SYNTAX;
        }

        pos = end + 1;
        errno = 0;
        subauth = strtoul(pos, &end, 10);
        if (errno != 0 || pos == end) {
            return LDAP_INVALID_SYNTAX;
        }

        sub_authorities[subauth_count++] = subauth;
    }

    if (*end != '\0') {
        return LDAP_INVALID_SYNTAX;
    }

    buffer = (unsigned char *)slapi_ch_malloc(8 + subauth_count * 4);
    if (buffer == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    buffer[0] = (unsigned char)revision;
    buffer[1] = (unsigned char)subauth_count;

    buffer[2] = (identifier_authority >> 40) & 0xff;
    buffer[3] = (identifier_authority >> 32) & 0xff;
    buffer[4] = (identifier_authority >> 24) & 0xff;
    buffer[5] = (identifier_authority >> 16) & 0xff;
    buffer[6] = (identifier_authority >> 8) & 0xff;
    buffer[7] = identifier_authority & 0xff;

    offset = 8;
    for (size_t i = 0; i < subauth_count; i++) {
        buffer[offset] = sub_authorities[i] & 0xff;
        buffer[offset + 1] = (sub_authorities[i] >> 8) & 0xff;
        buffer[offset + 2] = (sub_authorities[i] >> 16) & 0xff;
        buffer[offset + 3] = (sub_authorities[i] >> 24) & 0xff;
        offset += 4;
    }

    bv = (struct berval *)slapi_ch_malloc(sizeof(struct berval));
    if (bv == NULL) {
        slapi_ch_free((void **)&buffer);
        return LDAP_OPERATIONS_ERROR;
    }

    bv->bv_val = (char *)buffer;
    bv->bv_len = 8 + subauth_count * 4;
    *bv_out = bv;

    return LDAP_SUCCESS;
}

static int ipa_gc_sid_string_to_rid(const char *sid_str, uint32_t *rid_out)
{
    const char *last_dash;
    char *end = NULL;
    unsigned long value;

    if (sid_str == NULL || rid_out == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    last_dash = strrchr(sid_str, '-');
    if (last_dash == NULL || last_dash[1] == '\0') {
        return LDAP_INVALID_SYNTAX;
    }

    errno = 0;
    value = strtoul(last_dash + 1, &end, 10);
    if (errno != 0 || end == NULL || *end != '\0' || value > UINT32_MAX) {
        return LDAP_INVALID_SYNTAX;
    }

    *rid_out = (uint32_t)value;

    return LDAP_SUCCESS;
}

static bool ipa_gc_enqueue_string_value(Slapi_Entry *entry,
                                        Slapi_Mods *mods,
                                        const char *attr,
                                        const char *value)
{
    bool changed = false;
    char *current = NULL;
    int mod_op = LDAP_MOD_ADD;

    if (value == NULL || value[0] == '\0') {
        return false;
    }

    current = slapi_entry_attr_get_charptr(entry, attr);
    if (current != NULL) {
        mod_op = LDAP_MOD_REPLACE;
    }

    if (!ipa_gc_value_equal(current, value)) {
        slapi_mods_add_string(mods, mod_op, attr, value);
        changed = true;
    }

    slapi_ch_free_string(&current);
    return changed;
}

static bool ipa_gc_enqueue_sid_value(Slapi_Entry *entry,
                                     Slapi_Mods *mods,
                                     const char *attr,
                                     const char *sid_value)
{
    struct berval *sid_bv = NULL;
    struct berval *vals[2] = {NULL, NULL};
    Slapi_Attr *existing = NULL;
    Slapi_Value *existing_value = NULL;
    const struct berval *existing_bv = NULL;
    int mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
    bool changed = false;
    int ret;

    if (sid_value == NULL || sid_value[0] == '\0') {
        return false;
    }

    ret = ipa_gc_sid_string_to_berval(sid_value, &sid_bv);
    if (ret != LDAP_SUCCESS) {
        LOG_FATAL("Unable to encode SID '%s' for GC entry (rc=%d).\n",
                  sid_value, ret);
        return false;
    }

    vals[0] = sid_bv;

    if (slapi_entry_attr_find(entry, attr, &existing) == 0 && existing != NULL) {
        if (slapi_attr_first_value(existing, &existing_value) != -1) {
            existing_bv = slapi_value_get_berval(existing_value);
        }
        if (existing_bv != NULL &&
            existing_bv->bv_len == sid_bv->bv_len &&
            memcmp(existing_bv->bv_val, sid_bv->bv_val, sid_bv->bv_len) == 0) {
            goto done;
        }
        mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    }

    slapi_mods_add_modbvps(mods, mod_op, attr, vals);
    changed = true;

done:
    if (sid_bv != NULL) {
        slapi_ch_free((void **)&sid_bv->bv_val);
        slapi_ch_free((void **)&sid_bv);
    }

    return changed;
}

static size_t ipa_gc_count_values(char **values)
{
    size_t count = 0;

    if (values == NULL) {
        return 0;
    }

    while (values[count] != NULL) {
        count++;
    }

    return count;
}

static char **ipa_gc_dup_array(char **values)
{
    size_t count;
    char **copy = NULL;

    if (values == NULL) {
        return NULL;
    }

    count = ipa_gc_count_values(values);
    if (count == 0) {
        return slapi_ch_calloc(1, sizeof(char *));
    }

    copy = slapi_ch_calloc(count + 1, sizeof(char *));
    if (copy == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        copy[i] = slapi_ch_strdup(values[i]);
        if (copy[i] == NULL) {
            for (size_t j = 0; j < i; j++) {
                slapi_ch_free_string(&copy[j]);
            }
            slapi_ch_free((void **)&copy);
            return NULL;
        }
    }

    copy[count] = NULL;
    return copy;
}

static void ipa_gc_free_string_array(char **values)
{
    if (values == NULL) {
        return;
    }

    for (size_t i = 0; values[i] != NULL; i++) {
        slapi_ch_free_string(&values[i]);
    }

    slapi_ch_free((void **)&values);
}

static int ipa_gc_compare_string_ptrs(const void *a, const void *b)
{
    const char *const *sa = (const char *const *)a;
    const char *const *sb = (const char *const *)b;

    return strcasecmp(*sa, *sb);
}

static bool ipa_gc_arrays_equal_case(char **a, char **b)
{
    char **copy_a = NULL;
    char **copy_b = NULL;
    size_t count_a;
    size_t count_b;
    bool equal = true;

    count_a = ipa_gc_count_values(a);
    count_b = ipa_gc_count_values(b);
    if (count_a != count_b) {
        return false;
    }

    if (count_a == 0) {
        return true;
    }

    copy_a = ipa_gc_dup_array(a);
    copy_b = ipa_gc_dup_array(b);
    if (copy_a == NULL || copy_b == NULL) {
        ipa_gc_free_string_array(copy_a);
        ipa_gc_free_string_array(copy_b);
        return false;
    }

    qsort(copy_a, count_a, sizeof(char *), ipa_gc_compare_string_ptrs);
    qsort(copy_b, count_b, sizeof(char *), ipa_gc_compare_string_ptrs);

    for (size_t i = 0; i < count_a; i++) {
        if (strcasecmp(copy_a[i], copy_b[i]) != 0) {
            equal = false;
            break;
        }
    }

    ipa_gc_free_string_array(copy_a);
    ipa_gc_free_string_array(copy_b);

    return equal;
}

static bool ipa_gc_enqueue_string_array(Slapi_Entry *entry,
                                        Slapi_Mods *mods,
                                        const char *attr,
                                        char **values)
{
    char **existing = NULL;
    bool changed = false;
    bool new_empty;
    bool existing_empty;

    existing = slapi_entry_attr_get_charray(entry, attr);
    new_empty = (values == NULL || values[0] == NULL);
    existing_empty = (existing == NULL || existing[0] == NULL);

    if (new_empty) {
        if (!existing_empty) {
            slapi_mods_add_string(mods, LDAP_MOD_DELETE, attr, NULL);
            changed = true;
        }
        goto done;
    }

    if (!existing_empty && ipa_gc_arrays_equal_case(existing, values)) {
        goto done;
    }

    slapi_mods_add_string(mods, LDAP_MOD_REPLACE, attr, values[0]);
    for (size_t i = 1; values[i] != NULL; i++) {
        slapi_mods_add_string(mods, LDAP_MOD_ADD, attr, values[i]);
    }
    changed = true;

done:
    if (existing != NULL) {
        slapi_ch_array_free(existing);
    }
    return changed;
}

static char *ipa_gc_strip_principal_instance(char *value)
{
    char *comma;

    if (value == NULL) {
        return NULL;
    }

    comma = strchr(value, '\n');
    if (comma != NULL) {
        *comma = '\0';
    }

    return value;
}

static char *ipa_gc_compute_sam(Slapi_Entry *entry)
{
    return slapi_entry_attr_get_charptr(entry, IPA_GC_ATTR_UID);
}

static char *ipa_gc_compute_sid(Slapi_Entry *entry)
{
    return slapi_entry_attr_get_charptr(entry, IPA_GC_ATTR_SID);
}

static char *ipa_gc_escape_filter_value(const char *value)
{
    size_t len;
    size_t size;
    char *escaped;
    size_t pos = 0;

    if (value == NULL) {
        return NULL;
    }

    len = strlen(value);
    size = len * 3 + 1;
    escaped = slapi_ch_malloc(size);
    if (escaped == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)value[i];

        if (ch == '*' || ch == '(' || ch == ')' || ch == '\\' || ch < 0x20 || ch >= 0x7f) {
            int written = snprintf(escaped + pos, size - pos, "\\%02X", ch);
            if (written < 0) {
                slapi_ch_free((void **)&escaped);
                return NULL;
            }
            pos += (size_t)written;
        } else {
            escaped[pos++] = (char)ch;
        }
    }

    escaped[pos] = '\0';
    return escaped;
}

static bool ipa_gc_entry_has_objectclass(Slapi_Entry *entry, const char *object_class)
{
    char **values = NULL;
    bool found = false;

    values = slapi_entry_attr_get_charray(entry, "objectClass");
    if (values == NULL) {
        return false;
    }

    for (size_t i = 0; values[i] != NULL; i++) {
        if (strcasecmp(values[i], object_class) == 0) {
            found = true;
            break;
        }
    }

    slapi_ch_array_free(values);
    return found;
}

static bool ipa_gc_is_user_entry(Slapi_Entry *entry)
{
    if (entry == NULL) {
        return false;
    }

    if (ipa_gc_entry_has_objectclass(entry, "ipaNTUserAttrs")) {
        return true;
    }

    if (ipa_gc_entry_has_objectclass(entry, "posixAccount")) {
        return true;
    }

    return false;
}

static bool ipa_gc_is_group_entry(Slapi_Entry *entry)
{
    if (entry == NULL) {
        return false;
    }

    if (ipa_gc_entry_has_objectclass(entry, "ipaNTGroupAttrs")) {
        return true;
    }

    if (ipa_gc_entry_has_objectclass(entry, "groupOfNames")) {
        return true;
    }

    return false;
}

static bool ipa_gc_enqueue_objectclass(Slapi_Entry *entry,
                                       Slapi_Mods *mods,
                                       const char *object_class)
{
    if (object_class == NULL) {
        return false;
    }

    if (ipa_gc_entry_has_objectclass(entry, object_class)) {
        return false;
    }

    slapi_mods_add_string(mods, LDAP_MOD_ADD, "objectClass", object_class);
    return true;
}

static int ipa_gc_lookup_memberof(struct ipa_gc_ctx *ctx,
                                  const Slapi_DN *target,
                                  char ***values_out)
{
    Slapi_PBlock *search_pb = NULL;
    Slapi_Entry **entries = NULL;
    char *escaped = NULL;
    char *filter = NULL;
    int ret = LDAP_SUCCESS;
    size_t count = 0;
    char **values = NULL;

    if (ctx == NULL || target == NULL || values_out == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    *values_out = NULL;

    escaped = ipa_gc_escape_filter_value(slapi_sdn_get_dn(target));
    if (escaped == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    filter = slapi_ch_smprintf(
        "(&(|(objectClass=ipaNTGroupAttrs)(objectClass=groupOfNames))"
        "(member=%s))",
        escaped);
    if (filter == NULL) {
        slapi_ch_free((void **)&escaped);
        return LDAP_OPERATIONS_ERROR;
    }

    search_pb = slapi_pblock_new();
    if (search_pb == NULL) {
        slapi_ch_free((void **)&escaped);
        slapi_ch_free((void **)&filter);
        return LDAP_OPERATIONS_ERROR;
    }

    slapi_search_internal_set_pb(search_pb, ctx->basedn, LDAP_SCOPE_SUBTREE,
                                 filter, NULL, 1, NULL, NULL,
                                 ctx->plugin_id, 0);

    ret = slapi_search_internal_pb(search_pb);
    if (ret != LDAP_SUCCESS) {
        goto done;
    }

    ret = slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                           &entries);
    if (ret != 0) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    if (entries == NULL) {
        ret = LDAP_SUCCESS;
        goto done;
    }

    while (entries[count] != NULL) {
        count++;
    }

    if (count == 0) {
        ret = LDAP_SUCCESS;
        goto done;
    }

    values = slapi_ch_calloc(count + 1, sizeof(char *));
    if (values == NULL) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    for (size_t i = 0; i < count; i++) {
        const char *dn = slapi_entry_get_dn_const(entries[i]);
        values[i] = slapi_ch_strdup(dn);
        if (values[i] == NULL) {
            ret = LDAP_OPERATIONS_ERROR;
            goto done;
        }
    }

    values[count] = NULL;
    *values_out = values;
    values = NULL;

done:
    if (values != NULL) {
        ipa_gc_free_string_array(values);
    }

    slapi_ch_free((void **)&escaped);
    slapi_ch_free((void **)&filter);
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);

    return ret;
}

static int ipa_gc_lookup_members(struct ipa_gc_ctx *ctx,
                                 const Slapi_DN *group_sdn,
                                 char ***values_out)
{
    Slapi_PBlock *search_pb = NULL;
    Slapi_Entry **entries = NULL;
    char *escaped = NULL;
    char *filter = NULL;
    int ret = LDAP_SUCCESS;
    size_t count = 0;
    char **values = NULL;

    if (ctx == NULL || group_sdn == NULL || values_out == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    *values_out = NULL;

    escaped = ipa_gc_escape_filter_value(slapi_sdn_get_dn(group_sdn));
    if (escaped == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    filter = slapi_ch_smprintf(
        "(&(|(objectClass=ipaNTUserAttrs)"
        "(objectClass=posixAccount)"
        "(objectClass=ipaNTGroupAttrs)"
        "(objectClass=groupOfNames))(memberOf=%s))",
        escaped);
    if (filter == NULL) {
        slapi_ch_free((void **)&escaped);
        return LDAP_OPERATIONS_ERROR;
    }

    search_pb = slapi_pblock_new();
    if (search_pb == NULL) {
        slapi_ch_free((void **)&escaped);
        slapi_ch_free((void **)&filter);
        return LDAP_OPERATIONS_ERROR;
    }

    slapi_search_internal_set_pb(search_pb, ctx->basedn, LDAP_SCOPE_SUBTREE,
                                 filter, NULL, 1, NULL, NULL,
                                 ctx->plugin_id, 0);

    ret = slapi_search_internal_pb(search_pb);
    if (ret != LDAP_SUCCESS) {
        goto done;
    }

    ret = slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                           &entries);
    if (ret != 0) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    if (entries == NULL) {
        ret = LDAP_SUCCESS;
        goto done;
    }

    while (entries[count] != NULL) {
        count++;
    }

    if (count == 0) {
        ret = LDAP_SUCCESS;
        goto done;
    }

    values = slapi_ch_calloc(count + 1, sizeof(char *));
    if (values == NULL) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    for (size_t i = 0; i < count; i++) {
        const char *dn = slapi_entry_get_dn_const(entries[i]);
        values[i] = slapi_ch_strdup(dn);
        if (values[i] == NULL) {
            ret = LDAP_OPERATIONS_ERROR;
            goto done;
        }
    }

    values[count] = NULL;
    *values_out = values;
    values = NULL;

done:
    if (values != NULL) {
        ipa_gc_free_string_array(values);
    }

    slapi_ch_free((void **)&escaped);
    slapi_ch_free((void **)&filter);
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);

    return ret;
}

static int ipa_gc_resolve_fallback_group(struct ipa_gc_ctx *ctx)
{
    Slapi_PBlock *search_pb = NULL;
    Slapi_Entry **entries = NULL;
    Slapi_Entry *group_entry = NULL;
    Slapi_DN *group_sdn = NULL;
    char *attrs[] = {"ipaNTFallbackPrimaryGroup", NULL};
    char *fallback_dn = NULL;
    char *group_sid = NULL;
    uint32_t rid;
    int ret;

    if (ctx->fallback_group_checked) {
        return ctx->fallback_group_available ? LDAP_SUCCESS : LDAP_NO_SUCH_OBJECT;
    }

    search_pb = slapi_pblock_new();
    if (search_pb == NULL) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    slapi_search_internal_set_pb(search_pb, ctx->basedn, LDAP_SCOPE_SUBTREE,
                                 "(objectClass=ipaNTDomainAttrs)", attrs, 0,
                                 NULL, NULL, ctx->plugin_id, 0);

    ret = slapi_search_internal_pb(search_pb);
    if (ret != LDAP_SUCCESS) {
        goto done;
    }

    ret = slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                           &entries);
    if (ret != 0) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    if (entries == NULL || entries[0] == NULL || entries[1] != NULL) {
        ret = LDAP_NO_SUCH_OBJECT;
        goto done;
    }

    fallback_dn = slapi_entry_attr_get_charptr(entries[0],
                                               "ipaNTFallbackPrimaryGroup");
    if (fallback_dn == NULL || fallback_dn[0] == '\0') {
        ret = LDAP_NO_SUCH_ATTRIBUTE;
        goto done;
    }

    group_sdn = slapi_sdn_new_dn_byval(fallback_dn);
    if (group_sdn == NULL) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ret = slapi_search_internal_get_entry(group_sdn, NULL, &group_entry,
                                          ctx->plugin_id);
    if (ret != LDAP_SUCCESS || group_entry == NULL) {
        ret = (ret != LDAP_SUCCESS) ? ret : LDAP_NO_SUCH_OBJECT;
        goto done;
    }

    group_sid = slapi_entry_attr_get_charptr(group_entry,
                                             IPA_GC_ATTR_SID);
    if (group_sid == NULL) {
        ret = LDAP_NO_SUCH_ATTRIBUTE;
        goto done;
    }

    ret = ipa_gc_sid_string_to_rid(group_sid, &rid);
    if (ret != LDAP_SUCCESS) {
        goto done;
    }

    ctx->fallback_group_dn = fallback_dn;
    fallback_dn = NULL;

    ctx->fallback_group_rid_str = slapi_ch_smprintf("%u", (unsigned int)rid);
    if (ctx->fallback_group_rid_str == NULL) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ctx->fallback_group_available = true;
    ret = LDAP_SUCCESS;

done:
    if (fallback_dn != NULL) {
        slapi_ch_free_string(&fallback_dn);
    }
    slapi_ch_free_string(&group_sid);
    slapi_entry_free(group_entry);
    slapi_sdn_free(&group_sdn);
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);

    if (!ctx->fallback_group_available) {
        slapi_ch_free_string(&ctx->fallback_group_dn);
        slapi_ch_free_string(&ctx->fallback_group_rid_str);
    }

    ctx->fallback_group_checked = true;
    return ret;
}

static const char *ipa_gc_primary_group_id(struct ipa_gc_ctx *ctx)
{
    int ret;

    if (ctx == NULL) {
        return NULL;
    }

    ret = ipa_gc_resolve_fallback_group(ctx);
    if (ret != LDAP_SUCCESS || !ctx->fallback_group_available) {
        return NULL;
    }

    return ctx->fallback_group_rid_str;
}

static char *ipa_gc_compute_upn(struct ipa_gc_ctx *ctx,
                                Slapi_Entry *entry,
                                const char *sam_account_name)
{
    char *principal = NULL;
    char *upn = NULL;

    principal = slapi_entry_attr_get_charptr(entry, IPA_GC_ATTR_KRBPN);
    principal = ipa_gc_strip_principal_instance(principal);
    if (principal != NULL && principal[0] != '\0') {
        return principal;
    }

    if (sam_account_name == NULL || ctx->realm == NULL) {
        return principal;
    }

    upn = slapi_ch_smprintf("%s@%s", sam_account_name, ctx->realm);
    slapi_ch_free_string(&principal);
    return upn;
}

static int ipa_gc_refresh_entry(struct ipa_gc_ctx *ctx, const Slapi_DN *target)
{
    Slapi_Entry *entry = NULL;
    Slapi_Mods *mods = NULL;
    Slapi_PBlock *mod_pb = NULL;
    char *sam_account_name = NULL;
    char *user_principal_name = NULL;
    char *sid = NULL;
    char **group_members = NULL;
    char **member_of = NULL;
    int result = LDAP_SUCCESS;
    int ret;
    bool changed = false;
    bool is_user;
    bool is_group;
    const char *primary_group_id = NULL;

    if (ctx->base_sdn != NULL &&
        !slapi_sdn_isparent(ctx->base_sdn, target) &&
        !slapi_sdn_issuffix(target, ctx->base_sdn)) {
        LOG_TRACE("Target entry %s not within GC base %s, skipping\n",
                  slapi_sdn_get_dn(target), slapi_sdn_get_dn(ctx->base_sdn));
        return LDAP_SUCCESS;
    }

    ret = slapi_search_internal_get_entry((Slapi_DN *)target, NULL,
                                          &entry, ctx->plugin_id);
    if (ret != LDAP_SUCCESS || entry == NULL) {
        LOG_FATAL("Unable to read entry %s for GC synthesis (rc=%d).\n",
                  slapi_sdn_get_dn(target), ret);
        return ret != LDAP_SUCCESS ? ret : LDAP_NO_SUCH_OBJECT;
    }

    mods = slapi_mods_new();
    if (mods == NULL) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    sam_account_name = ipa_gc_compute_sam(entry);
    user_principal_name = ipa_gc_compute_upn(ctx, entry, sam_account_name);
    sid = ipa_gc_compute_sid(entry);
    is_user = ipa_gc_is_user_entry(entry);
    is_group = ipa_gc_is_group_entry(entry);

    changed |= ipa_gc_enqueue_string_value(entry, mods,
                                           IPA_GC_ATTR_SAMACCOUNTNAME,
                                           sam_account_name);
    changed |= ipa_gc_enqueue_string_value(entry, mods, IPA_GC_ATTR_UPN,
                                           user_principal_name);
    changed |= ipa_gc_enqueue_sid_value(entry, mods, IPA_GC_ATTR_OBJECTSID,
                                        sid);

    if (is_user) {
        primary_group_id = ipa_gc_primary_group_id(ctx);
        if (primary_group_id != NULL) {
            changed |= ipa_gc_enqueue_string_value(entry, mods,
                                                   "primaryGroupID",
                                                   primary_group_id);
        }

        ret = ipa_gc_lookup_memberof(ctx, target, &member_of);
        if (ret != LDAP_SUCCESS) {
            LOG_FATAL("Unable to compute memberOf for %s (rc=%d).\n",
                      slapi_sdn_get_dn(target), ret);
            goto done;
        }

        if (member_of != NULL) {
            changed |= ipa_gc_enqueue_string_array(entry, mods,
                                                   "memberOf",
                                                   member_of);
        } else {
            changed |= ipa_gc_enqueue_string_array(entry, mods,
                                                   "memberOf",
                                                   NULL);
        }

        ipa_gc_free_string_array(member_of);
        member_of = NULL;
    }

    if (is_group) {
        changed |= ipa_gc_enqueue_objectclass(entry, mods, "group");
        changed |= ipa_gc_enqueue_string_value(entry, mods, "groupType",
                                               "-2147483646");

        ret = ipa_gc_lookup_members(ctx, target, &group_members);
        if (ret != LDAP_SUCCESS) {
            LOG_FATAL("Unable to compute members for group %s (rc=%d).\n",
                      slapi_sdn_get_dn(target), ret);
            goto done;
        }

        changed |= ipa_gc_enqueue_string_array(entry, mods, "member",
                                               group_members);

        ret = ipa_gc_lookup_memberof(ctx, target, &member_of);
        if (ret != LDAP_SUCCESS) {
            LOG_FATAL("Unable to compute memberOf for group %s (rc=%d).\n",
                      slapi_sdn_get_dn(target), ret);
            goto done;
        }

        if (member_of != NULL) {
            changed |= ipa_gc_enqueue_string_array(entry, mods,
                                                   "memberOf",
                                                   member_of);
        } else {
            changed |= ipa_gc_enqueue_string_array(entry, mods,
                                                   "memberOf",
                                                   NULL);
        }
    } else if (is_user) {
        changed |= ipa_gc_enqueue_objectclass(entry, mods, "user");
    }

    if (!changed) {
        ret = LDAP_SUCCESS;
        goto done;
    }

    mod_pb = slapi_pblock_new();
    if (mod_pb == NULL) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    slapi_modify_internal_set_pb_ext(mod_pb, (Slapi_DN *)target,
                                     slapi_mods_get_ldapmods_byref(mods),
                                     NULL, NULL, ctx->plugin_id, 0);

    ret = slapi_modify_internal_pb(mod_pb);
    if (ret != LDAP_SUCCESS) {
        LOG_FATAL("GC synthesis modify failed on %s (rc=%d).\n",
                  slapi_sdn_get_dn(target), ret);
        goto done;
    }

    ret = slapi_pblock_get(mod_pb, SLAPI_PLUGIN_INTOP_RESULT, &result);
    if (ret != 0 || result != LDAP_SUCCESS) {
        LOG_FATAL("GC synthesis modify returned error for %s (result=%d).\n",
                  slapi_sdn_get_dn(target), result);
        if (ret == 0) {
            ret = result;
        }
        goto done;
    }

    ret = LDAP_SUCCESS;

 done:
    slapi_pblock_destroy(mod_pb);
    slapi_mods_free(&mods);
    slapi_entry_free(entry);
    slapi_ch_free_string(&sam_account_name);
    slapi_ch_free_string(&user_principal_name);
    slapi_ch_free_string(&sid);
    ipa_gc_free_string_array(group_members);
    ipa_gc_free_string_array(member_of);
    return ret;
}

static int ipa_gc_post_common(Slapi_PBlock *pb)
{
    struct ipa_gc_ctx *ctx = NULL;
    Slapi_DN *target = NULL;
    int ret;

    if (ipa_gc_skip_operation(pb)) {
        return LDAP_SUCCESS;
    }

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &ctx);
    if (ret != 0 || ctx == NULL) {
        LOG_FATAL("Global catalog plugin missing private context.\n");
        return LDAP_OPERATIONS_ERROR;
    }

    ret = slapi_pblock_get(pb, SLAPI_TARGET_SDN, &target);
    if (ret != 0 || target == NULL) {
        LOG_FATAL("Global catalog plugin missing target DN.\n");
        return LDAP_OPERATIONS_ERROR;
    }

    return ipa_gc_refresh_entry(ctx, target);
}

static int ipa_gc_post_add(Slapi_PBlock *pb)
{
    return ipa_gc_post_common(pb);
}

static int ipa_gc_post_modify(Slapi_PBlock *pb)
{
    return ipa_gc_post_common(pb);
}

static int ipa_gc_close(Slapi_PBlock *pb)
{
    struct ipa_gc_ctx *ctx = NULL;

    if (slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &ctx) == 0) {
        ipa_gc_ctx_free(ctx);
    }

    return LDAP_SUCCESS;
}

static int ipa_gc_start(Slapi_PBlock *pb)
{
    struct ipa_gc_ctx *ctx = NULL;
    Slapi_Entry *config_entry = NULL;
    int ret;

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &ctx);
    if (ret != 0 || ctx == NULL) {
        LOG_FATAL("Global catalog start missing context.\n");
        return LDAP_OPERATIONS_ERROR;
    }

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &ctx->plugin_id);
    if (ret != 0 || ctx->plugin_id == NULL) {
        LOG_FATAL("Global catalog failed to obtain plugin identity.\n");
        return LDAP_OPERATIONS_ERROR;
    }

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_CONFIG_ENTRY, &config_entry);
    if (ret != 0 || config_entry == NULL) {
        LOG_FATAL("Global catalog configuration entry missing.\n");
        return LDAP_OPERATIONS_ERROR;
    }

    ctx->basedn = slapi_entry_attr_get_charptr(config_entry, "nsslapd-basedn");
    if (ctx->basedn != NULL) {
        ctx->base_sdn = slapi_sdn_new_dn_byval(ctx->basedn);
    }

    ctx->realm = slapi_entry_attr_get_charptr(config_entry, "ipaGCRealm");

    if (ctx->basedn == NULL || ctx->base_sdn == NULL) {
        LOG_FATAL("Global catalog configuration missing nsslapd-basedn.\n");
        return LDAP_OPERATIONS_ERROR;
    }

    if (ctx->realm == NULL) {
        LOG("Global catalog configuration missing ipaGCRealm; "
            "userPrincipalName fallback will be disabled.\n");
    }

    LOG("Global catalog plugin initialised for base %s.\n",
        slapi_sdn_get_dn(ctx->base_sdn));

    return LDAP_SUCCESS;
}

int ipa_globalcatalog_plugin_init(Slapi_PBlock *pb)
{
    struct ipa_gc_ctx *ctx = NULL;

    ctx = slapi_ch_calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         (void *)SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *)&ipa_globalcatalog_plugin_desc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                         (void *)ipa_gc_start) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                         (void *)ipa_gc_close) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_ADD_FN,
                         (void *)ipa_gc_post_add) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODIFY_FN,
                         (void *)ipa_gc_post_modify) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, ctx) != 0) {
        ipa_gc_ctx_free(ctx);
        return LDAP_OPERATIONS_ERROR;
    }

    return LDAP_SUCCESS;
}
