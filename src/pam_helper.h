/*
 * pam_helper.h
 *
 *  Created on: Apr 20, 2013
 *      Author: romanovskiy
 */

#ifndef PAM_HELPER_H_
#define PAM_HELPER_H_

#define PAM_checkerr(rv, pamh, message, label) \
	if (rv != PAM_SUCCESS) { \
		pam_syslog(pamh, LOG_ERR, message); \
		rv = PAM_AUTHINFO_UNAVAIL; \
		goto label; }

#define PAM_checkerr_ex(rv, ret, pamh, function, label) \
	if (rv != PAM_SUCCESS) { \
		pam_syslog(pamh, LOG_ERR, "PAM function %s failed: %s", function, pam_strerror(pamh, rv)); \
		rv = ret; \
		goto label; }

#define PKCS_checkerr(rv, message, label) \
	if (rv != CKR_OK) { \
		pam_syslog(pamh, LOG_ERR, message); \
		rv = PAM_AUTHINFO_UNAVAIL; \
		goto label; }

#define PKCS_checkerr_ex(rv, pamh, function, label) \
	if (rv != CKR_OK) { \
		pam_syslog(pamh, LOG_ERR, "%s failed with error: 0x%08X", function, rv); \
		rv = PAM_AUTHINFO_UNAVAIL; \
		goto label; }

#endif /* PAM_HELPER_H_ */
