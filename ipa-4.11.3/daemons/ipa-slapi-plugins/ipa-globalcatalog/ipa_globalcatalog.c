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
#define IPA_GC_ATTR_OBJECTCLASS "objectClass"
#define IPA_GC_ATTR_GROUPTYPE "groupType"
#define IPA_GC_ATTR_PRIMARYGROUPID "primaryGroupID"

#define IPA_GC_ATTR_UID "uid"
#define IPA_GC_ATTR_KRBPN "krbPrincipalName"
#define IPA_GC_ATTR_SID "ipaNTSecurityIdentifier"

#define IPA_GC_OC_USER "user"
#define IPA_GC_OC_GROUP "group"

#define IPA_GC_GROUPTYPE_SECURITY_GLOBAL "-2147483646"

struct ipa_gc_ctx {
    Slapi_ComponentId *plugin_id;
    Slapi_DN *base_sdn;
    char *basedn;
    char *realm;
    uint32_t fallback_primary_group_rid;
    bool has_fallback_primary_group_rid;
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

static int ipa_gc_sid_string_get_rid(const char *sid_str, uint32_t *rid)
{
    char *end = NULL;
    const char *last_dash;
    unsigned long value;

    if (sid_str == NULL || rid == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    last_dash = strrchr(sid_str, '-');
    if (last_dash == NULL || *(last_dash + 1) == '\0') {
        return LDAP_INVALID_SYNTAX;
    }

    errno = 0;
    value = strtoul(last_dash + 1, &end, 10);
    if (errno != 0 || end == last_dash + 1 || *end != '\0' ||
        value > UINT32_MAX) {
        return LDAP_INVALID_SYNTAX;
    }

    *rid = (uint32_t)value;
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

static bool ipa_gc_enqueue_objectclass_value(Slapi_Entry *entry,
                                             Slapi_Mods *mods,
                                             const char *value)
{
    char **existing = NULL;
    bool present = false;

    if (value == NULL || value[0] == '\0') {
        return false;
    }

    existing = slapi_entry_attr_get_charray(entry, IPA_GC_ATTR_OBJECTCLASS);
    if (existing != NULL) {
        for (size_t i = 0; existing[i] != NULL; i++) {
            if (strcasecmp(existing[i], value) == 0) {
                present = true;
                break;
            }
        }
        slapi_ch_array_free(existing);
    }

    if (present) {
        return false;
    }

    slapi_mods_add_string(mods, LDAP_MOD_ADD, IPA_GC_ATTR_OBJECTCLASS, value);
    return true;
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

static bool ipa_gc_entry_has_objectclass(Slapi_Entry *entry, const char *value)
{
    char **classes = NULL;
    bool found = false;

    if (value == NULL || value[0] == '\0') {
        return false;
    }

    classes = slapi_entry_attr_get_charray(entry, IPA_GC_ATTR_OBJECTCLASS);
    if (classes != NULL) {
        for (size_t i = 0; classes[i] != NULL; i++) {
            if (strcasecmp(classes[i], value) == 0) {
                found = true;
                break;
            }
        }
        slapi_ch_array_free(classes);
    }

    return found;
}

static bool ipa_gc_entry_is_user(Slapi_Entry *entry)
{
    return ipa_gc_entry_has_objectclass(entry, "ipaNTUserAttrs") ||
           ipa_gc_entry_has_objectclass(entry, "posixAccount") ||
           ipa_gc_entry_has_objectclass(entry, "inetOrgPerson");
}

static bool ipa_gc_entry_is_group(Slapi_Entry *entry)
{
    return ipa_gc_entry_has_objectclass(entry, "ipaNTGroupAttrs") ||
           ipa_gc_entry_has_objectclass(entry, "posixGroup") ||
           ipa_gc_entry_has_objectclass(entry, "groupOfNames");
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

static char *ipa_gc_compute_primary_group_id(struct ipa_gc_ctx *ctx,
                                             Slapi_Entry *entry)
{
    (void)entry;

    if (ctx == NULL || !ctx->has_fallback_primary_group_rid) {
        return NULL;
    }

    return slapi_ch_smprintf("%u", ctx->fallback_primary_group_rid);
}

static int ipa_gc_load_domain_attrs(struct ipa_gc_ctx *ctx)
{
    static const char *attrs[] = {
        "ipaNTFallbackPrimaryGroup",
        NULL,
    };
    Slapi_PBlock *pb = NULL;
    Slapi_Entry **entries = NULL;
    Slapi_Entry *fallback_entry = NULL;
    Slapi_DN *fallback_sdn = NULL;
    char *fallback_dn = NULL;
    char *fallback_sid = NULL;
    uint32_t fallback_rid = 0;
    int result = LDAP_SUCCESS;
    int ret = LDAP_SUCCESS;

    if (ctx == NULL || ctx->basedn == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    ctx->has_fallback_primary_group_rid = false;

    pb = slapi_pblock_new();
    if (pb == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    slapi_search_internal_set_pb(pb, ctx->basedn, LDAP_SCOPE_SUBTREE,
                                 "(objectClass=ipaNTDomainAttrs)",
                                 (char **)attrs, 0, NULL, NULL,
                                 ctx->plugin_id, 0);

    ret = slapi_search_internal_pb(pb);
    if (ret != LDAP_SUCCESS) {
        goto done;
    }

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &result);
    if (ret != 0) {
        goto done;
    }
    if (result != LDAP_SUCCESS) {
        ret = result;
        goto done;
    }

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
    if (ret != 0) {
        goto done;
    }

    if (entries == NULL || entries[0] == NULL) {
        ret = LDAP_NO_SUCH_OBJECT;
        goto done;
    }

    fallback_dn = slapi_entry_attr_get_charptr(entries[0],
                                               "ipaNTFallbackPrimaryGroup");
    if (fallback_dn == NULL || fallback_dn[0] == '\0') {
        ret = LDAP_NO_SUCH_ATTRIBUTE;
        goto done;
    }

    fallback_sdn = slapi_sdn_new_dn_byval(fallback_dn);
    if (fallback_sdn == NULL) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ret = slapi_search_internal_get_entry(fallback_sdn, NULL, &fallback_entry,
                                          ctx->plugin_id);
    if (ret != LDAP_SUCCESS || fallback_entry == NULL) {
        goto done;
    }

    fallback_sid = slapi_entry_attr_get_charptr(fallback_entry,
                                                IPA_GC_ATTR_SID);
    if (fallback_sid == NULL) {
        ret = LDAP_NO_SUCH_ATTRIBUTE;
        goto done;
    }

    ret = ipa_gc_sid_string_get_rid(fallback_sid, &fallback_rid);
    if (ret != LDAP_SUCCESS) {
        goto done;
    }

    ctx->fallback_primary_group_rid = fallback_rid;
    ctx->has_fallback_primary_group_rid = true;
    ret = LDAP_SUCCESS;

done:
    slapi_ch_free_string(&fallback_sid);
    if (fallback_entry != NULL) {
        slapi_entry_free(fallback_entry);
    }
    if (fallback_sdn != NULL) {
        slapi_sdn_free(&fallback_sdn);
    }
    slapi_ch_free_string(&fallback_dn);
    if (pb != NULL) {
        slapi_free_search_results_internal(pb);
        slapi_pblock_destroy(pb);
    }

    if (ret != LDAP_SUCCESS) {
        ctx->has_fallback_primary_group_rid = false;
    }

    return ret;
}

static int ipa_gc_refresh_entry(struct ipa_gc_ctx *ctx, const Slapi_DN *target)
{
    Slapi_Entry *entry = NULL;
    Slapi_Mods *mods = NULL;
    Slapi_PBlock *mod_pb = NULL;
    char *sam_account_name = NULL;
    char *user_principal_name = NULL;
    char *sid = NULL;
    char *primary_group_id = NULL;
    int result = LDAP_SUCCESS;
    int ret;
    bool changed = false;

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
    primary_group_id = ipa_gc_compute_primary_group_id(ctx, entry);

    changed |= ipa_gc_enqueue_string_value(entry, mods,
                                           IPA_GC_ATTR_SAMACCOUNTNAME,
                                           sam_account_name);
    changed |= ipa_gc_enqueue_string_value(entry, mods, IPA_GC_ATTR_UPN,
                                           user_principal_name);
    changed |= ipa_gc_enqueue_sid_value(entry, mods, IPA_GC_ATTR_OBJECTSID,
                                        sid);
    if (ipa_gc_entry_is_user(entry)) {
        changed |= ipa_gc_enqueue_objectclass_value(entry, mods,
                                                    IPA_GC_OC_USER);
        changed |= ipa_gc_enqueue_string_value(entry, mods,
                                               IPA_GC_ATTR_PRIMARYGROUPID,
                                               primary_group_id);
    }
    if (ipa_gc_entry_is_group(entry)) {
        changed |= ipa_gc_enqueue_objectclass_value(entry, mods,
                                                    IPA_GC_OC_GROUP);
        changed |= ipa_gc_enqueue_string_value(entry, mods,
                                               IPA_GC_ATTR_GROUPTYPE,
                                               IPA_GC_GROUPTYPE_SECURITY_GLOBAL);
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
    slapi_ch_free_string(&primary_group_id);
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

    ret = ipa_gc_load_domain_attrs(ctx);
    if (ret != LDAP_SUCCESS) {
        LOG("Global catalog failed to determine fallback primary group RID; "
            "primaryGroupID synthesis will be disabled (rc=%d).\n", ret);
    } else {
        LOG("Global catalog configured fallback primary group RID %u.\n",
            ctx->fallback_primary_group_rid);
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
