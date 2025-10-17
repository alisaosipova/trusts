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
#include <libcli/util/werror.h>
#include <util/data_blob.h>
#include <gen_ndr/netlogon.h>

/* The following definitions come from passdb/pdb_ipa.c  */

NTSTATUS pdb_ipa_init(void);
WERROR ipasam_netlogon_enum_trusts(TALLOC_CTX *mem_ctx,
                                   uint32_t trust_flags,
                                   struct netr_DomainTrustList *trusts);
NTSTATUS ipasam_netlogon_get_trust_secrets(TALLOC_CTX *mem_ctx,
                                           const char *domain,
                                           DATA_BLOB *incoming_secret,
                                           NTTIME *incoming_last_set,
                                           DATA_BLOB *outgoing_secret,
                                           NTTIME *outgoing_last_set);
uint32_t ipasam_netlogon_supported_enctypes(void);
