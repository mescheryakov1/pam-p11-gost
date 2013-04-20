/*
 * libp11 PAM Login Module
 * Copyright (C) 2003 Mario Strasser <mast@gmx.net>,
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <syslog.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "pkcs11/rtpkcs11.h"

/* We have to make this definitions before we include the pam header files! */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>
#else
#define pam_syslog(handle, level, msg ...) syslog(level, ## msg)
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif

#define LOGNAME   "pam_p11" /* name for log-file entries */

#define RANDOM_SOURCE "/dev/urandom"
#define RANDOM_SIZE 128
#define MAX_SIGSIZE 256

extern int match_user(X509* x509, const char* login);

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc,
                                   const char** argv)
{
	printf("authenticating via PAM-GOST\n");
	int rv;
	const char* user;
	char* password;
	char password_prompt[64];

	struct pam_conv* conv;
	struct pam_message msg;
	struct pam_response* resp;
	struct pam_message*(msgp[1]);

	EVP_PKEY* pubkey;

	unsigned char rand_bytes[RANDOM_SIZE];
	unsigned char signature[MAX_SIGSIZE];
	int fd;
	unsigned siglen;
	unsigned int i;

	// ENGINE* gostEngine = ENGINE_by_id("gost");
	// if (!gostEngine)
	//  goto opensslEngineCleanup;

	// if (ENGINE_init(gostEngine))
	//  goto opensslGostEngineFree;

	/* check parameters */
	if (argc != 1) {
		pam_syslog(pamh, LOG_ERR, "need pkcs11 module as argument");
		return PAM_ABORT;
	}

	/* init openssl */
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();


	rv = PAM_SUCCESS;

out:
	// opensslGostEngineFinish:
	//  ENGINE_finish(gostEngine);
	// opensslGostEngineFree:
	//  ENGINE_free(gostEngine);

	return rv;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc,
                              const char** argv)
{
	/* Actually, we should return the same value as pam_sm_authenticate(). */
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc,
                                const char** argv)
{
	pam_syslog(pamh, LOG_WARNING,
	           "Function pam_sm_acct_mgmt() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc,
                                   const char** argv)
{
	pam_syslog(pamh, LOG_WARNING,
	           "Function pam_sm_open_session() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t* pamh, int flags, int argc,
                                    const char** argv)
{
	pam_syslog(pamh, LOG_WARNING,
	           "Function pam_sm_close_session() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t* pamh, int flags, int argc,
                                const char** argv)
{
	pam_syslog(pamh, LOG_WARNING,
	           "Function pam_sm_chauthtok() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

#ifdef PAM_STATIC
/* static module data */
struct pam_module _pam_group_modstruct = {
	"pam_p11",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok
};
#endif
