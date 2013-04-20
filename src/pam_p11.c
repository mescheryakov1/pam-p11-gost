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

#include <dlfcn.h>
#include <stddef.h>

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

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	printf("authenticating via PAM-PKCS#11-GOST\n");
	int rv;
	const char* user;
	char* pin;
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

	void* pkcs11Module;
	CK_C_GetFunctionList pkcsGetFunctionList;
	CK_FUNCTION_LIST_PTR pkcs;
	CK_ULONG slotCount;
	CK_SLOT_ID* slotIds;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_TOKEN_INFO tokenInfo;

	// ENGINE* gostEngine = ENGINE_by_id("gost");
	// if (!gostEngine)
	//  goto opensslEngineCleanup;

	// if (ENGINE_init(gostEngine))
	//  goto opensslGostEngineFree;

	if (argc != 1) {
		pam_syslog(pamh, LOG_ERR, "need pkcs11 module as argument");
		return PAM_ABORT;
	}

	// get PAM username
	rv = pam_get_user(pamh, &user, NULL);
	if (rv != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "pam_get_user() failed %s", pam_strerror(pamh, rv));
		return PAM_USER_UNKNOWN;
	}

	pkcs11Module = dlopen(argv[0], RTLD_NOW);
	if (!pkcs11Module) {
		pam_syslog(pamh, LOG_ERR, "failed to load PKCS#11 library");
		return PAM_AUTHINFO_UNAVAIL;
	}
	pkcsGetFunctionList = (CK_C_GetFunctionList)dlsym(pkcs11Module, "C_GetFunctionList");
	if (!pkcsGetFunctionList) {
		pam_syslog(pamh, LOG_ERR, "failed to load PKCS#11 library");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto libFinish;
	}
	pkcsGetFunctionList(&pkcs);
	rv = pkcs->C_Initialize(NULL);
	if (rv != CKR_OK) {
		pam_syslog(pamh, LOG_ERR, "C_Initialize failed with error 0x%08X", rv);
		rv = PAM_AUTHINFO_UNAVAIL;
		goto libFinish;
	}
	rv = pkcs->C_GetSlotList(CK_TRUE, NULL_PTR, &slotCount);
	if (rv != CKR_OK) {
		pam_syslog(pamh, LOG_ERR, "C_GetSlotList failed with error 0x%08X", rv);
		rv = PAM_AUTHINFO_UNAVAIL;
		goto pkcs11Finish;
	}
	if (slotCount == 0) {
		pam_syslog(pamh, LOG_ERR, "no token available");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto pkcs11Finish;
	}
	if (slotCount > 1) {
		pam_syslog(pamh, LOG_ERR, "use only one token");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto pkcs11Finish;
	}

	slotIds = (CK_SLOT_ID*)OPENSSL_malloc(slotCount * sizeof(CK_SLOT_ID));
	if (!slotIds) {
		pam_syslog(pamh, LOG_ERR, "out of memory");
		goto pkcs11Finish;
	}
	rv = pkcs->C_GetSlotList(CK_TRUE, slotIds, &slotCount);
	if (rv != CKR_OK) {
		pam_syslog(pamh, LOG_ERR, "C_GetSlotList failed with error 0x%08X", rv);
		return PAM_AUTHINFO_UNAVAIL;
	}
	slot = slotIds[0];
	rv = pkcs->C_GetTokenInfo(slot, &tokenInfo);
	if (rv != CKR_OK) {
		pam_syslog(pamh, LOG_ERR, "C_GetTokenInfo failed with error 0x%08X", rv);
		return PAM_AUTHINFO_UNAVAIL;
	}


	rv = pkcs->C_OpenSession(slot, (CKF_SERIAL_SESSION | CKF_RW_SESSION), NULL, NULL, &session);
	if (rv != CKR_OK) {
		pam_syslog(pamh, LOG_ERR, "C_OpenSession failed with error 0x%08X", rv);
		rv = PAM_AUTHINFO_UNAVAIL;
		goto pkcs11Finish;
	}

	// get token PIN via PAM
	msgp[0] = &msg;
	rv = pam_get_item(pamh, PAM_AUTHTOK, (void*)&pin);
	if (rv == PAM_SUCCESS && pin) {
		pin = strdup(pin);
	} else {
		sprintf(password_prompt, "PIN for %.32s: ", tokenInfo.label);
		msg.msg_style = PAM_PROMPT_ECHO_OFF;
		msg.msg = password_prompt;
		rv = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
		if (rv != PAM_SUCCESS) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto pkcs11SessionFinish;
		}
		if ((conv == NULL) || (conv->conv == NULL)) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto pkcs11SessionFinish;
		}
		rv = conv->conv(1, (const struct pam_message**)msgp, &resp, conv->appdata_ptr);
		if (rv != PAM_SUCCESS) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto pkcs11SessionFinish;
		}
		if ((resp == NULL) || (resp[0].resp == NULL)) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto pkcs11SessionFinish;
		}
		pin = strdup(resp[0].resp);
		memset(resp[0].resp, 0, strlen(resp[0].resp));
		free(&resp[0]);
	}

	rv = pkcs->C_Login(session, CKU_USER, (CK_UTF8CHAR*)pin, pin ? strlen(pin) : 0);
	memset(pin, 0, strlen(pin));
	free(pin);

	if (rv != CKR_OK) {
		if (rv == CKR_PIN_INCORRECT)
			pam_syslog(pamh, LOG_ERR, "Incorrect PIN entered");
		else
			pam_syslog(pamh, LOG_ERR, "C_Login failed with error 0x%08X", rv);
		rv = PAM_AUTHINFO_UNAVAIL;
		goto pkcs11SessionFinish;
	}

	/* init openssl */
	// TODO: errors?
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	rv = PAM_SUCCESS;

opensslFinish:
	OPENSSL_free(slotIds);
	// opensslGostEngineFinish:
	//  ENGINE_finish(gostEngine);
	// opensslGostEngineFree:
	//  ENGINE_free(gostEngine);

pkcs11SessionFinish:
	pkcs->C_CloseSession(session);
pkcs11Finish:
	pkcs->C_Finalize(NULL);
libFinish:
	dlclose(pkcs11Module);

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
