/*
   Unix SMB/CIFS implementation.
   IPA helper functions for SAMBA
   Copyright (C) Sumit Bose <sbose@redhat.com> 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#pragma once

#include <talloc.h>
#include <libcli/auth/netlogon_creds.h>
#include <librpc/rpc/dcerpc.h>
#include <libcli/util/werror.h>
#include <gen_ndr/netlogon.h>

/* The following definitions come from passdb/pdb_ipa.c  */

NTSTATUS pdb_ipa_init(void);
WERROR ipasam_netlogon_enum_trusts(TALLOC_CTX *mem_ctx,
                                   uint32_t trust_flags,
                                   struct netr_DomainTrustList *trusts);

struct ipasam_netlogon_domain_info_entry {
        const char *netbios_name;
        const char *dns_domain_name;
        const char *dns_forest_name;
        struct GUID domain_guid;
        struct dom_sid domain_sid;
        uint32_t trust_flags;
        uint32_t parent_index;
        uint32_t trust_type;
        uint32_t trust_attributes;
};

struct ipasam_netlogon_domain_info {
        struct ipasam_netlogon_domain_info_entry primary_domain;
        uint32_t trusted_domain_count;
        struct ipasam_netlogon_domain_info_entry *trusted_domains;
        const char *dns_hostname;
        uint32_t workstation_flags;
        uint32_t supported_enc_types;
};

NTSTATUS ipasam_netlogon_logon_get_domain_info(TALLOC_CTX *mem_ctx,
                                               struct netlogon_creds_CredentialState *creds,
                                               enum dcerpc_AuthType auth_type,
                                               enum dcerpc_AuthLevel auth_level,
                                               uint32_t level,
                                               const union netr_WorkstationInfo *query,
                                               struct ipasam_netlogon_domain_info **info_out);
NTSTATUS ipasam_netlogon_server_password_get(TALLOC_CTX *mem_ctx,
                                             struct netlogon_creds_CredentialState *creds,
                                             enum dcerpc_AuthType auth_type,
                                             enum dcerpc_AuthLevel auth_level,
                                             struct netr_ServerPasswordGet *r);
NTSTATUS ipasam_netlogon_server_trust_passwords_get(TALLOC_CTX *mem_ctx,
                                                    struct netlogon_creds_CredentialState *creds,
                                                    enum dcerpc_AuthType auth_type,
                                                    enum dcerpc_AuthLevel auth_level,
                                                    struct netr_ServerTrustPasswordsGet *r);
