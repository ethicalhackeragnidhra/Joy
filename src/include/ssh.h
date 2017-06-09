/*
 *	
 * Copyright (c) 2016 Cisco Systems, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * 
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * ssh.h
 *
 * Secure Shell (SSH) protocol awareness for joy
 *
 */

#ifndef SSH_H
#define SSH_H

#include <stdio.h>   /* for FILE* */
#include <pcap.h>
#include "output.h"
#include "feature.h"
#include "utils.h"

#define ssh_usage "  ssh=1                      report ssh information\n"

#define ssh_filter(key) ((key->prot == 6) && (key->dp == 22 || key->sp == 22))

#define MAX_SSH_LEN 512
#define MAX_SSH_PACKET_LEN 35000 /* RFC 4253, Section 6.1. */
#define MAX_SSH_PAYLOAD_LEN 32768 /* RFC 4253, Section 6.1. */

typedef struct ssh {
    enum role role;
    char protocol[MAX_SSH_LEN];
    char kex_algos[MAX_SSH_LEN];
    char s_host_key_algos[MAX_SSH_LEN];
    char c_encryption_algos[MAX_SSH_LEN];
    char s_encryption_algos[MAX_SSH_LEN];
    char c_mac_algos[MAX_SSH_LEN];
    char s_mac_algos[MAX_SSH_LEN];
    char c_comp_algos[MAX_SSH_LEN];
    char s_comp_algos[MAX_SSH_LEN];
    char c_languages[MAX_SSH_LEN];
    char s_languages[MAX_SSH_LEN];
    unsigned char cookie[16];
    unsigned int c_kex_len;
    unsigned char c_kex[MAX_SSH_PAYLOAD_LEN];
    unsigned int s_kex_len;
    unsigned char s_kex[MAX_SSH_PAYLOAD_LEN];
    unsigned int s_hostkey_len;
    unsigned char s_hostkey[MAX_SSH_PAYLOAD_LEN];
    char s_hostkey_type[MAX_SSH_LEN];
    unsigned int s_signature_len;
    unsigned char s_signature[MAX_SSH_PAYLOAD_LEN];
    char s_signature_type[MAX_SSH_LEN];
} ssh_t;

declare_feature(ssh);

void ssh_init(struct ssh *ssh);

void ssh_update(struct ssh *ssh, 
                const struct pcap_pkthdr *header,
		const void *data, 
		unsigned int len, 
		unsigned int report_ssh);

void ssh_print_json(const struct ssh *w1, 
		    const struct ssh *w2,
		    zfile f);

void ssh_delete(struct ssh *ssh);

void ssh_unit_test();

#endif /* SSH_H */
