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
 * ssh.c
 *
 * Secure Shell (SSH) awareness for joy
 *
 */

#include <stdio.h>      /* for fprintf()           */
#include <stdlib.h>     /* for malloc, realloc, free */
#include <stdint.h>     /* for uint32_t            */
#include <arpa/inet.h>  /* for ntohl()             */
#include <string.h>     /* for memset()            */
#include "ssh.h"     
#include "p2f.h"        /* for zprintf_ ...        */


/*
 * from http://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml
 */
enum ssh_msg_type {
    SSH_MSG_DISCONNECT                 = 1,     
    SSH_MSG_IGNORE             = 2,     
    SSH_MSG_UNIMPLEMENTED         = 3,     
    SSH_MSG_DEBUG             = 4,     
    SSH_MSG_SERVICE_REQUEST         = 5,     
    SSH_MSG_SERVICE_ACCEPT         = 6,     
    SSH_MSG_KEXINIT             = 20,     
    SSH_MSG_NEWKEYS             = 21,     
    SSH_MSG_USERAUTH_REQUEST         = 50,     
    SSH_MSG_USERAUTH_FAILURE         = 51,     
    SSH_MSG_USERAUTH_SUCCESS         = 52,     
    SSH_MSG_USERAUTH_BANNER         = 53,     
    SSH_MSG_USERAUTH_INFO_REQUEST     = 60,     
    SSH_MSG_USERAUTH_INFO_RESPONSE    = 61,    
    SSH_MSG_GLOBAL_REQUEST         = 80,    
    SSH_MSG_REQUEST_SUCCESS         = 81,    
    SSH_MSG_REQUEST_FAILURE         = 82,    
    SSH_MSG_CHANNEL_OPEN             = 90,    
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,        
    SSH_MSG_CHANNEL_OPEN_FAILURE         = 92,    
    SSH_MSG_CHANNEL_WINDOW_ADJUST     = 93,     
    SSH_MSG_CHANNEL_DATA             = 94,    
    SSH_MSG_CHANNEL_EXTENDED_DATA     = 95,    
    SSH_MSG_CHANNEL_EOF             = 96,     
    SSH_MSG_CHANNEL_CLOSE         = 97,     
    SSH_MSG_CHANNEL_REQUEST         = 98,     
    SSH_MSG_CHANNEL_SUCCESS         = 99,     
    SSH_MSG_CHANNEL_FAILURE         = 100
};     

/*
 * from RFC 4253:
 *   Each packet is in the following format:
 *
 *    uint32    packet_length
 *    byte      padding_length
 *    byte[n1]  payload; n1 = packet_length - padding_length - 1
 *    byte[n2]  random padding; n2 = padding_length
 *    byte[m]   mac (Message Authentication Code - MAC); m = mac_length
 *
 */
struct ssh_packet { 
    uint32_t      packet_length;
    unsigned char padding_length;
    unsigned char payload;
} __attribute__((__packed__));    

unsigned int ssh_packet_parse(const void *pkt, unsigned int datalen, unsigned char *msg_code, unsigned int *total_length) {
    const struct ssh_packet *ssh_packet = pkt;
    uint32_t length;

    if (datalen < sizeof(struct ssh_packet)) {
    return 0;
    }

    length = ntohl(ssh_packet->packet_length);
    if (length > MAX_SSH_PAYLOAD_LEN) {
    return 0;   /* indicate parse error */
    }
    *total_length = length + 4;
    *msg_code = ssh_packet->payload;

    /* robustness check */
    length -= ssh_packet->padding_length - 5;
    if (length > MAX_SSH_PAYLOAD_LEN) {
      return 0;
    }

    return length;
}

unsigned int decode_uint32(const void *data) {
    const uint32_t *x = data;
  
    return ntohl(*x);
}

enum status decode_ssh_vector(const void **dataptr, unsigned int *datalen, struct vector *vector, unsigned maxlen) {
    const void *data = *dataptr;
    unsigned length;

    if (*datalen < 4) {
    fprintf(stderr, "ERROR: wanted %u, only have %u\n", 4, *datalen);
    return failure;
    }
    length = decode_uint32(data);
    *datalen -= 4;
    if (length > *datalen) {
    fprintf(stderr, "ERROR: wanted %u, only have %u\n", length, *datalen);
    return failure;
    }
    data += 4;

    /* robustness check */
    if (length > maxlen) {
      return failure;
    }

    vector_set(vector, data, length);
    
    data += length;
    *datalen -= length;
    *dataptr = data;
    return ok;
}

/*
 * from RFC 4253 Section 7.1
 * 
 *    Key exchange begins by each side sending the following packet:
 *
 *    byte         SSH_MSG_KEXINIT
 *    byte[16]     cookie (random bytes)
 *    name-list    kex_algorithms
 *    name-list    server_host_key_algorithms
 *    name-list    encryption_algorithms_client_to_server
 *    name-list    encryption_algorithms_server_to_client
 *    name-list    mac_algorithms_client_to_server
 *    name-list    mac_algorithms_server_to_client
 *    name-list    compression_algorithms_client_to_server
 *    name-list    compression_algorithms_server_to_client
 *    name-list    languages_client_to_server
 *    name-list    languages_server_to_client
 *    boolean      first_kex_packet_follows
 *    uint32       0 (reserved for future extension)
 *
 */
void ssh_parse_kexinit(struct ssh *ssh, const void *data, unsigned int datalen) {

    /* robustness check */
    if (ssh->kex_algos->len != 0) {
        return;
    }

    /* copy the cookie  */
    if (datalen < 16) {
    return;
    }
    memcpy(ssh->cookie, data, 16);
    data += 16;
    datalen -= 16;

    /* copy all name-list strings */
    if (decode_ssh_vector(&data, &datalen, ssh->kex_algos, MAX_SSH_STRING_LEN) == failure) {
    return;
    }
    if (decode_ssh_vector(&data, &datalen, ssh->s_host_key_algos, MAX_SSH_STRING_LEN) == failure) {
    return;
    }
    if (decode_ssh_vector(&data, &datalen, ssh->c_encryption_algos, MAX_SSH_STRING_LEN) == failure) {
    return;
    }
    if (decode_ssh_vector(&data, &datalen, ssh->s_encryption_algos, MAX_SSH_STRING_LEN) == failure) {
    return;
    }
    if (decode_ssh_vector(&data, &datalen, ssh->c_mac_algos, MAX_SSH_STRING_LEN) == failure) {
    return;
    }
    if (decode_ssh_vector(&data, &datalen, ssh->s_mac_algos, MAX_SSH_STRING_LEN) == failure) {
    return;
    }
    if (decode_ssh_vector(&data, &datalen, ssh->c_comp_algos, MAX_SSH_STRING_LEN) == failure) {
    return;
    }
    if (decode_ssh_vector(&data, &datalen, ssh->s_comp_algos, MAX_SSH_STRING_LEN) == failure) {
    return;
    }
    if (decode_ssh_vector(&data, &datalen, ssh->c_languages, MAX_SSH_STRING_LEN) == failure) {
    return;
    }
    if (decode_ssh_vector(&data, &datalen, ssh->s_languages, MAX_SSH_STRING_LEN) == failure) {
    return;
    }

    return;
}

void ssh_get_kex_algo(struct ssh *cli, struct ssh *srv) {
    char *cli_copy, *srv_copy;
    char *algo;
    char *sep = ",";
    unsigned len;

    cli_copy = vector_string(cli->kex_algos);
    srv_copy = vector_string(srv->kex_algos);

    for(algo = strtok(cli_copy, sep); algo; algo = strtok(NULL, sep)) {
        if (strstr(srv_copy, algo) != NULL) {
            break;
        }
    }
    if (algo == NULL) {
        algo = "";
    }
    len = strlen(algo);
    cli->kex_algo = malloc(len+1);
    strncpy(cli->kex_algo, algo, len+1); /* strncpy will null-terminate the string */
    srv->kex_algo = malloc(len+1);
    strncpy(srv->kex_algo, algo, len+1); /* strncpy will null-terminate the string */

    free(cli_copy);
    free(srv_copy);
    return;
}

/*
 * from RFC 4253, Section 8
 * decode e 
 */
void ssh_parse_kexdh_init(struct ssh *ssh, const void *data, unsigned int datalen) {

    /* copy client key exchange value */
    if (decode_ssh_vector(&data, &datalen, ssh->c_kex, MAX_SSH_PAYLOAD_LEN) == failure) {
    return;
    }

    ssh->role = role_client;
    return;
}

void ssh_parse_kexdh_reply(struct ssh *ssh, const void *data, unsigned int datalen) {
    const void *tmpptr;
    unsigned int tmplen;
    
    /* copy server public host key and certificates (K_S) */
    if (decode_ssh_vector(&data, &datalen, ssh->s_hostkey, MAX_SSH_PAYLOAD_LEN) == failure) {
    return;
    }
    /* copy host key type */
    tmpptr = ssh->s_hostkey->bytes;
    tmplen = ssh->s_hostkey->len;
    if (decode_ssh_vector(&tmpptr, &tmplen, ssh->s_hostkey_type, MAX_SSH_STRING_LEN) == failure) {
    return;
    }
    /* copy server key exchange value */
    if (decode_ssh_vector(&data, &datalen, ssh->s_kex, MAX_SSH_PAYLOAD_LEN) == failure) {
    return;
    }
    /* copy signature */
    if (decode_ssh_vector(&data, &datalen, ssh->s_signature, MAX_SSH_PAYLOAD_LEN) == failure) {
    return;
    }
    /* copy signature type */
    tmpptr = ssh->s_signature->bytes;
    tmplen = ssh->s_signature->len;
    if (decode_ssh_vector(&tmpptr, &tmplen, ssh->s_signature_type, MAX_SSH_STRING_LEN) == failure) {
    return;
    }

    ssh->role = role_server;
    return;
}

void ssh_parse_kex_dh_gex_request(struct ssh *ssh, const void *data, unsigned int datalen) {

    if (datalen < 4) {
        return;
    }
    ssh->c_gex_min = decode_uint32(data);
    if (datalen < 12) {
        /* old format */
        ssh->c_gex_n = ssh->c_gex_max = ssh->c_gex_min;
    } else {
        ssh->c_gex_n = decode_uint32(data+4);
        ssh->c_gex_max = decode_uint32(data+8);
    }

    return;
}

void ssh_parse_kex_dh_gex_group(struct ssh *ssh, const void *data, unsigned int datalen) {
    
    /* copy safe prime p */
    if (decode_ssh_vector(&data, &datalen, ssh->s_gex_p, MAX_SSH_PAYLOAD_LEN) == failure) {
    return;
    }

    /* copy generator g */
    if (decode_ssh_vector(&data, &datalen, ssh->s_gex_g, MAX_SSH_PAYLOAD_LEN) == failure) {
    return;
    }

    return;
}

/*
 * from RFC 4432, Section 4
 */
void ssh_parse_kexrsa_pubkey(struct ssh *ssh, const void *data, unsigned int datalen) {
    const void *tmpptr;
    unsigned int tmplen;
    
    /* copy server public host key and certificates (K_S) */
    if (decode_ssh_vector(&data, &datalen, ssh->s_hostkey, MAX_SSH_PAYLOAD_LEN) == failure) {
    return;
    }
    /* copy host key type */
    tmpptr = ssh->s_hostkey->bytes;
    tmplen = ssh->s_hostkey->len;
    if (decode_ssh_vector(&tmpptr, &tmplen, ssh->s_hostkey_type, MAX_SSH_STRING_LEN) == failure) {
    return;
    }
    /* copy K_T, the transient RSA public key */
    if (decode_ssh_vector(&data, &datalen, ssh->s_kex, MAX_SSH_PAYLOAD_LEN) == failure) {
    return;
    }

    ssh->role = role_server;
    return;
}

void ssh_parse_kexrsa_secret(struct ssh *ssh, const void *data, unsigned int datalen) {

    /* copy RSA-encrypted secret */
    if (decode_ssh_vector(&data, &datalen, ssh->c_kex, MAX_SSH_PAYLOAD_LEN) == failure) {
    return;
    }

    ssh->role = role_client;
    return;
}

void ssh_parse_kexrsa_done(struct ssh *ssh, const void *data, unsigned int datalen) {
    const void *tmpptr;
    unsigned int tmplen;

    /* copy signature */
    if (decode_ssh_vector(&data, &datalen, ssh->s_signature, MAX_SSH_PAYLOAD_LEN) == failure) {
    return;
    }
    /* copy signature type */
    tmpptr = ssh->s_signature->bytes;
    tmplen = ssh->s_signature->len;
    if (decode_ssh_vector(&tmpptr, &tmplen, ssh->s_signature_type, MAX_SSH_STRING_LEN) == failure) {
    return;
    }

    ssh->role = role_server;
    return;
}

/*
 * from https://tools.ietf.org/html/rfc4419
 */
#define SSH_MSG_KEX_DH_GEX_REQUEST_OLD  30
#define SSH_MSG_KEX_DH_GEX_REQUEST      34
#define SSH_MSG_KEX_DH_GEX_GROUP        31
#define SSH_MSG_KEX_DH_GEX_INIT         32
#define SSH_MSG_KEX_DH_GEX_REPLY        33
#define ssh_parse_kex_dh_gex_init ssh_parse_kexdh_init
#define ssh_parse_kex_dh_gex_reply ssh_parse_kexdh_reply
void ssh_gex_kex(struct ssh *cli, struct ssh *srv) {

    if (cli->kex_msgs_len > 0 && (cli->kex_msgs[0].msg_code == SSH_MSG_KEX_DH_GEX_REQUEST_OLD
                || cli->kex_msgs[0].msg_code == SSH_MSG_KEX_DH_GEX_REQUEST)) {
        ssh_parse_kex_dh_gex_request(cli, cli->kex_msgs[0].data->bytes, cli->kex_msgs[0].data->len);
    }
    if (srv->kex_msgs_len > 0 && srv->kex_msgs[0].msg_code == SSH_MSG_KEX_DH_GEX_GROUP) {
        ssh_parse_kex_dh_gex_group(srv, srv->kex_msgs[0].data->bytes, srv->kex_msgs[0].data->len);
    }
    if (cli->kex_msgs_len > 1 && cli->kex_msgs[1].msg_code == SSH_MSG_KEX_DH_GEX_INIT) {
        ssh_parse_kex_dh_gex_init(cli, cli->kex_msgs[1].data->bytes, cli->kex_msgs[1].data->len);
    }
    if (srv->kex_msgs_len > 1 && srv->kex_msgs[1].msg_code == SSH_MSG_KEX_DH_GEX_REPLY) {
        ssh_parse_kex_dh_gex_reply(srv, srv->kex_msgs[1].data->bytes, srv->kex_msgs[1].data->len);
    }
    return;
}

/*
 * from https://tools.ietf.org/html/rfc4253
 */
#define SSH_MSG_KEXDH_INIT  30
#define SSH_MSG_KEXDH_REPLY 31
void ssh_dh_kex(struct ssh *cli, struct ssh *srv) {

    if (cli->kex_msgs_len > 0 && cli->kex_msgs[0].msg_code == SSH_MSG_KEXDH_INIT) {
        ssh_parse_kexdh_init(cli, cli->kex_msgs[0].data->bytes, cli->kex_msgs[0].data->len);
    }
    if (srv->kex_msgs_len > 0 && srv->kex_msgs[0].msg_code == SSH_MSG_KEXDH_REPLY) {
        ssh_parse_kexdh_reply(srv, srv->kex_msgs[0].data->bytes, srv->kex_msgs[0].data->len);
    }
    return;
}

/*
 * from https://tools.ietf.org/html/rfc4462
 */
#define SSH_MSG_KEXGSS_INIT                       30
#define SSH_MSG_KEXGSS_CONTINUE                   31
#define SSH_MSG_KEXGSS_COMPLETE                   32
#define SSH_MSG_KEXGSS_HOSTKEY                    33
#define SSH_MSG_KEXGSS_ERROR                      34
#define SSH_MSG_KEXGSS_GROUPREQ                   40
#define SSH_MSG_KEXGSS_GROUP                      41
void ssh_gss_dh_kex(struct ssh *cli, struct ssh *srv) {
    /* TODO */
    return;
}

void ssh_gss_gex_kex(struct ssh *cli, struct ssh *srv) {
    /* TODO */
    return;
}

/*
 * from https://tools.ietf.org/html/rfc4432
 */
#define SSH_MSG_KEXRSA_PUBKEY  30
#define SSH_MSG_KEXRSA_SECRET  31
#define SSH_MSG_KEXRSA_DONE    32
void ssh_rsa_kex(struct ssh *cli, struct ssh *srv) {

    if (srv->kex_msgs_len > 0 && srv->kex_msgs[0].msg_code == SSH_MSG_KEXRSA_PUBKEY) {
        ssh_parse_kexrsa_pubkey(srv, srv->kex_msgs[0].data->bytes, srv->kex_msgs[0].data->len);
    } 
    if (cli->kex_msgs_len > 0 && cli->kex_msgs[0].msg_code == SSH_MSG_KEXRSA_SECRET) {
        ssh_parse_kexrsa_secret(cli, cli->kex_msgs[0].data->bytes, cli->kex_msgs[0].data->len);
    } 
    if (srv->kex_msgs_len > 1 && srv->kex_msgs[1].msg_code == SSH_MSG_KEXRSA_DONE) {
        ssh_parse_kexrsa_done(srv, srv->kex_msgs[1].data->bytes, srv->kex_msgs[1].data->len);
    } 
    return;
}

/*
 * from https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml
 */
void ssh_process(struct ssh *cli, struct ssh *srv) {

    if (cli == NULL || srv == NULL) {
        return;
    }

    ssh_get_kex_algo(cli, srv);

    /* process key exchange messages */
    if (strstr(cli->kex_algo, "diffie-hellman-group-exchange-sha1") 
            || strstr(cli->kex_algo, "diffie-hellman-group-exchange-sha256")) {
        ssh_gex_kex(cli, srv);
    } else if (strstr(cli->kex_algo, "diffie-hellman-group1-sha1")
            || strstr(cli->kex_algo, "diffie-hellman-group14-sha1")
            || strstr(cli->kex_algo, "ecdh-sha2-")
            || strstr(cli->kex_algo, "ecmqv-sha2-")
            || strstr(cli->kex_algo, "curve25519-sha256")) {
        ssh_dh_kex(cli, srv);
    } else if (strstr(cli->kex_algo, "gss-group1-sha1-")
            || strstr(cli->kex_algo, "gss-group14-sha1-")) {
        ssh_gss_dh_kex(cli, srv);
    } else if (strstr(cli->kex_algo, "gss-gex-sha1-")) {
        ssh_gss_gex_kex(cli, srv);
    } else if (strstr(cli->kex_algo, "rsa1024-sha1")
            || strstr(cli->kex_algo, "rsa2048-sha256")) {
        ssh_rsa_kex(cli, srv);
    } else {
        return;
    }
}

/*
 * start of ssh feature functions
 */

inline void ssh_init(struct ssh *ssh) {
    int i;

    ssh->role = role_unknown;
    ssh->protocol[0] = 0; /* null terminate string */
    memset(ssh->cookie, 0, sizeof(ssh->cookie));
    ssh->kex_algo = NULL;
    ssh->buffer                 = malloc(sizeof(struct vector)); vector_init(ssh->buffer);
    ssh->kex_algos              = malloc(sizeof(struct vector)); vector_init(ssh->kex_algos);
    ssh->s_host_key_algos       = malloc(sizeof(struct vector)); vector_init(ssh->s_host_key_algos);
    ssh->c_encryption_algos     = malloc(sizeof(struct vector)); vector_init(ssh->c_encryption_algos);
    ssh->s_encryption_algos     = malloc(sizeof(struct vector)); vector_init(ssh->s_encryption_algos);
    ssh->c_mac_algos            = malloc(sizeof(struct vector)); vector_init(ssh->c_mac_algos);
    ssh->s_mac_algos            = malloc(sizeof(struct vector)); vector_init(ssh->s_mac_algos);
    ssh->c_comp_algos           = malloc(sizeof(struct vector)); vector_init(ssh->c_comp_algos);
    ssh->s_comp_algos           = malloc(sizeof(struct vector)); vector_init(ssh->s_comp_algos);
    ssh->c_languages            = malloc(sizeof(struct vector)); vector_init(ssh->c_languages);
    ssh->s_languages            = malloc(sizeof(struct vector)); vector_init(ssh->s_languages);
    ssh->s_hostkey_type         = malloc(sizeof(struct vector)); vector_init(ssh->s_hostkey_type);
    ssh->s_signature_type       = malloc(sizeof(struct vector)); vector_init(ssh->s_signature_type);
    ssh->c_kex                  = malloc(sizeof(struct vector)); vector_init(ssh->c_kex);
    ssh->s_kex                  = malloc(sizeof(struct vector)); vector_init(ssh->s_kex);
    ssh->s_hostkey              = malloc(sizeof(struct vector)); vector_init(ssh->s_hostkey);
    ssh->s_signature            = malloc(sizeof(struct vector)); vector_init(ssh->s_signature);
    ssh->s_gex_p                = malloc(sizeof(struct vector)); vector_init(ssh->s_gex_p);
    ssh->s_gex_g                = malloc(sizeof(struct vector)); vector_init(ssh->s_gex_g);
    for (i = 0; i < MAX_SSH_KEX_MESSAGES; ++i) {
        ssh->kex_msgs[i].msg_code = 0;
        ssh->kex_msgs[i].data   = malloc(sizeof(struct vector)); vector_init(ssh->kex_msgs[i].data);
    }
    ssh->kex_msgs_len = 0;
    ssh->c_gex_min = 0;
    ssh->c_gex_n = 0;
    ssh->c_gex_max = 0;
    ssh->newkeys = 0;
}

void ssh_update(struct ssh *ssh, 
        const struct pcap_pkthdr *header,
        const void *data, 
        unsigned int len, 
        unsigned int report_ssh) {
    unsigned int length;
    unsigned int total_length;
    unsigned char msg_code;
    void *tmpptr;

    if (len == 0) {
    return;        /* skip zero-length messages */
    }
    
    if (report_ssh) {

    /* append application-layer data to buffer */
    vector_append(ssh->buffer, data, len);
    data = ssh->buffer->bytes;
    len = ssh->buffer->len;

    if (ssh->role == role_unknown) {
        /*
         * RFC 4253:
         * The server MAY send other lines of data before sending the version
         * string. Each line SHOULD be terminated by a Carriage Return and Line
         * Feed.  Such lines MUST NOT begin with "SSH-".
         */

        /* skip to version message */
        if ((tmpptr = strstr(data, "SSH-")) && len >= (tmpptr-data)+4) {
            len -= (tmpptr-data);
            data = tmpptr;
            copy_printable_string(ssh->protocol, sizeof(ssh->protocol), data, len);
        } else {
            return;
        }

        /* skip past version message */
        if ((tmpptr = strstr(data, "\n")) && len >= (tmpptr-data)+1) {
            tmpptr += 1; /* skip past the "\n" */
            len -= (tmpptr-data);
            data = tmpptr;
        } else {
            return;
        }
        ssh->role = role_client; /* ? */
    }

    while(len > 0) { /* parse all SSH packets in buffer */
        length = ssh_packet_parse(data, len, &msg_code, &total_length);
        if (length == 0 || total_length > len) {
            /* unable to parse SSH packet */
            break;
        }
        switch (msg_code) {
        case SSH_MSG_KEXINIT:

            ssh_parse_kexinit(ssh, data + sizeof(struct ssh_packet), length);
            break;
        case SSH_MSG_NEWKEYS:

            ssh->newkeys = 1;
            break;
        default:

            /* key exchange specific messages */
            if (msg_code >= 30 && msg_code <= 49) {
                if (ssh->kex_msgs_len < MAX_SSH_KEX_MESSAGES) {
                    ssh->kex_msgs[ssh->kex_msgs_len].msg_code = msg_code;
                    vector_set(ssh->kex_msgs[ssh->kex_msgs_len].data, data + sizeof(struct ssh_packet), length);
                    ssh->kex_msgs_len++;
                }
            }
            break;
        }

        /* skip to the next message in buffer */
        len -= total_length;
        data += total_length;
    }
    
    /* update or free buffer */
    if (len > 0) {
        vector_set(ssh->buffer, data, len);
    } else {
        vector_free(ssh->buffer);
    }

    }

}

void ssh_print_json(const struct ssh *x1, const struct ssh *x2, zfile f) {

    struct ssh *cli = NULL, *srv = NULL;
    char *ptr;
    if (x1->role == role_unknown) {
        return;
    }
    if (x1->role == role_client) {
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types-discards-qualifiers"
        cli = x1, srv = x2;
    } else { // x1->role == role_server
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types-discards-qualifiers"
        srv = x1;
    }
    ssh_process(cli, srv);
    zprintf(f, ",\"ssh\":{");
    if (cli != NULL) {
        zprintf(f, "\"cli\":{");
        zprintf(f, "\"protocol\":\"%s\"", cli->protocol);
        if (cli->cookie[0] != 0) {
            zprintf(f, ",\"cookie\":");
            zprintf_raw_as_hex(f, cli->cookie, sizeof(cli->cookie));
        }
        ptr = vector_string(cli->kex_algos); zprintf(f, ",\"kex_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(cli->s_host_key_algos); zprintf(f, ",\"s_host_key_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(cli->c_encryption_algos); zprintf(f, ",\"c_encryption_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(cli->s_encryption_algos); zprintf(f, ",\"s_encryption_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(cli->c_mac_algos); zprintf(f, ",\"c_mac_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(cli->s_mac_algos); zprintf(f, ",\"s_mac_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(cli->c_comp_algos); zprintf(f, ",\"c_comp_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(cli->s_comp_algos); zprintf(f, ",\"s_comp_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(cli->c_languages); zprintf(f, ",\"c_languages\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(cli->s_languages); zprintf(f, ",\"s_languages\":\"%s\"", ptr); free(ptr);
        if (cli->kex_algo != NULL) {
        zprintf(f, ",\"kex_algo\":\"%s\"", cli->kex_algo);
        }
        if (cli->c_kex->len > 0) {
        zprintf(f, ",\"c_kex\":");
        zprintf_raw_as_hex(f, cli->c_kex->bytes, cli->c_kex->len);
        }
        zprintf(f, ",\"newkeys\":\"%s\"", cli->newkeys? "true": "false");
        zprintf(f, "}");
    }
    if (srv != NULL) {
        if (cli != NULL) {
            zprintf(f, ",");
        }
        zprintf(f, "\"srv\":{");
        zprintf(f, "\"protocol\":\"%s\"", srv->protocol);
        if (srv->cookie[0] != 0) {
            zprintf(f, ",\"cookie\":");
            zprintf_raw_as_hex(f, srv->cookie, sizeof(srv->cookie));
        }
        ptr = vector_string(srv->kex_algos); zprintf(f, ",\"kex_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(srv->s_host_key_algos); zprintf(f, ",\"s_host_key_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(srv->c_encryption_algos); zprintf(f, ",\"c_encryption_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(srv->s_encryption_algos); zprintf(f, ",\"s_encryption_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(srv->c_mac_algos); zprintf(f, ",\"c_mac_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(srv->s_mac_algos); zprintf(f, ",\"s_mac_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(srv->c_comp_algos); zprintf(f, ",\"c_comp_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(srv->s_comp_algos); zprintf(f, ",\"s_comp_algos\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(srv->c_languages); zprintf(f, ",\"c_languages\":\"%s\"", ptr); free(ptr);
        ptr = vector_string(srv->s_languages); zprintf(f, ",\"s_languages\":\"%s\"", ptr); free(ptr);
        if (srv->s_hostkey->len > 0) {
        ptr = vector_string(srv->s_hostkey_type); zprintf(f, ",\"s_hostkey_type\":\"%s\"", ptr); free(ptr);
        zprintf(f, ",\"s_hostkey\":");
        zprintf_raw_as_hex(f, srv->s_hostkey->bytes, srv->s_hostkey->len);
        }
        if (srv->s_signature->len > 0) {
        ptr = vector_string(srv->s_signature_type); zprintf(f, ",\"s_signature_type\":\"%s\"", ptr); free(ptr);
        zprintf(f, ",\"s_signature\":");
        zprintf_raw_as_hex(f, srv->s_signature->bytes, srv->s_signature->len);
        }
        if (srv->kex_algo != NULL) {
        zprintf(f, ",\"kex_algo\":\"%s\"", srv->kex_algo);
        }
        if (srv->s_kex->len > 0) {
        zprintf(f, ",\"s_kex\":");
        zprintf_raw_as_hex(f, srv->s_kex->bytes, srv->s_kex->len);
        }
        if (srv->s_gex_p->len > 0 && srv->s_gex_g->len > 0) {
        zprintf(f, ",\"s_gex_p\":");
        zprintf_raw_as_hex(f, srv->s_gex_p->bytes, srv->s_gex_p->len);
        zprintf(f, ",\"s_gex_g\":");
        zprintf_raw_as_hex(f, srv->s_gex_g->bytes, srv->s_gex_g->len);
        }
        zprintf(f, ",\"newkeys\":\"%s\"", srv->newkeys? "true": "false");
        zprintf(f, "}");
    }
    zprintf(f, "}");
}

void ssh_delete(struct ssh *ssh) {
    int i;

    if (ssh->kex_algo != NULL) {
        free(ssh->kex_algo);
    }
    vector_free(ssh->buffer);             free(ssh->buffer);
    vector_free(ssh->kex_algos);          free(ssh->kex_algos);
    vector_free(ssh->s_host_key_algos);   free(ssh->s_host_key_algos);
    vector_free(ssh->c_encryption_algos); free(ssh->c_encryption_algos);
    vector_free(ssh->s_encryption_algos); free(ssh->s_encryption_algos);
    vector_free(ssh->c_mac_algos);        free(ssh->c_mac_algos);
    vector_free(ssh->s_mac_algos);        free(ssh->s_mac_algos);
    vector_free(ssh->c_comp_algos);       free(ssh->c_comp_algos);
    vector_free(ssh->s_comp_algos);       free(ssh->s_comp_algos);
    vector_free(ssh->c_languages);        free(ssh->c_languages);
    vector_free(ssh->s_languages);        free(ssh->s_languages);
    vector_free(ssh->s_hostkey_type);     free(ssh->s_hostkey_type);
    vector_free(ssh->s_signature_type);   free(ssh->s_signature_type);
    vector_free(ssh->c_kex);              free(ssh->c_kex);
    vector_free(ssh->s_kex);              free(ssh->s_kex);
    vector_free(ssh->s_hostkey);          free(ssh->s_hostkey);
    vector_free(ssh->s_signature);        free(ssh->s_signature);
    vector_free(ssh->s_gex_p);            free(ssh->s_gex_p);
    vector_free(ssh->s_gex_g);            free(ssh->s_gex_g);
    for (i = 0; i < MAX_SSH_KEX_MESSAGES; ++i) {
        vector_free(ssh->kex_msgs[i].data); free(ssh->kex_msgs[i].data);
    }
}

void ssh_unit_test() {
    const struct pcap_pkthdr *header = NULL;
    struct ssh ssh;
    zfile output;
    char *msg = "should use a valid KEXT ssh msg here";

    output = zattach(stdout, "w");
    if (output == NULL) {
    fprintf(stderr, "error: could not initialize (possibly compressed) stdout for writing\n");
    }
    ssh_init(&ssh);
    ssh_update(&ssh, header, msg, 1, 1);
    ssh_update(&ssh, header, msg, 2, 1);
    ssh_update(&ssh, header, msg, 3, 1);
    ssh_update(&ssh, header, msg, 4, 1);
    ssh_update(&ssh, header, msg, 5, 1);
    ssh_update(&ssh, header, msg, 6, 1);
    ssh_update(&ssh, header, msg, 7, 1);
    ssh_update(&ssh, header, msg, 8, 1);
    ssh_update(&ssh, header, msg, 9, 1);
    ssh_print_json(&ssh, NULL, output);
 
} 
