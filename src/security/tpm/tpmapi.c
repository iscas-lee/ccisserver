/*
 * tpmapi.c
 *
 *  Created on: 2016年11月8日
 *      Author: somnus
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>

#include <trousers/trousers.h>  // XXX DEBUG

#include "tpmapi.h"

//#define DLOPEN_TSPI
//#define PRIKEY "server.key"

//#ifndef OPENSSL_NO_HW
//#ifndef OPENSSL_NO_HW_TPM

/* engine specific functions */
static int tpm_engine_destroy(ENGINE *);
static int tpm_engine_init(ENGINE *);
static int tpm_engine_finish(ENGINE *);
static int tpm_engine_ctrl(ENGINE *, int, long, void *, void (*)());
static EVP_PKEY *tpm_engine_load_key(ENGINE *, const char *, UI_METHOD *, void *);
static char *tpm_engine_get_auth(UI_METHOD *, char *, int, char *, void *);

#ifndef OPENSSL_NO_RSA
/* rsa functions */
static int tpm_rsa_init(RSA *rsa);
static int tpm_rsa_finish(RSA *rsa);
static int tpm_rsa_pub_dec(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm_rsa_pub_enc(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm_rsa_priv_dec(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm_rsa_priv_enc(int, const unsigned char *, unsigned char *, RSA *, int);
//static int tpm_rsa_sign(int, const unsigned char *, unsigned int, unsigned char *, unsigned int *, const RSA *);
static int tpm_rsa_keygen(RSA *, int, BIGNUM *, BN_GENCB *);
#endif

/* random functions */
static int tpm_rand_bytes(unsigned char *, int);
static int tpm_rand_status(void);
static void tpm_rand_seed(const void *, int);

/* The definitions for control commands specific to this engine */
#define TPM_CMD_SO_PATH		ENGINE_CMD_BASE
#define TPM_CMD_PIN		ENGINE_CMD_BASE+1
#define TPM_CMD_SECRET_MODE	ENGINE_CMD_BASE+2
static const ENGINE_CMD_DEFN tpm_cmd_defns[] = { { TPM_CMD_SO_PATH, "SO_PATH", "Specifies the path to the libtspi.so shared library",
ENGINE_CMD_FLAG_STRING }, { TPM_CMD_PIN, "PIN", "Specifies the secret for the SRK (default is plaintext, else set SECRET_MODE)",
ENGINE_CMD_FLAG_STRING }, { TPM_CMD_SECRET_MODE, "SECRET_MODE", "The TSS secret mode for all secrets",
ENGINE_CMD_FLAG_NUMERIC }, { 0, NULL, NULL, 0 } };

#ifndef OPENSSL_NO_RSA
static RSA_METHOD tpm_rsa = { "TPM RSA method", tpm_rsa_pub_enc, tpm_rsa_pub_dec, tpm_rsa_priv_enc, tpm_rsa_priv_dec,
NULL, /* set in tpm_engine_init */
BN_mod_exp_mont, tpm_rsa_init, tpm_rsa_finish, (RSA_FLAG_SIGN_VER | RSA_FLAG_NO_BLINDING),
NULL,
NULL, /* sign */
NULL, /* verify */
tpm_rsa_keygen };
#endif

static RAND_METHOD tpm_rand = {
/* "TPM RAND method", */
tpm_rand_seed, tpm_rand_bytes,
NULL,
NULL, tpm_rand_bytes, tpm_rand_status, };

/* Constants used when creating the ENGINE */
static const char *engine_tpm_id = "tpm";
static const char *engine_tpm_name = "TPM hardware engine support";
static const char *TPM_LIBNAME = "tspi";

//static EVP_PKEY *tpm_pkey = EVP_PKEY_new();
static EVP_PKEY *tpm_pkey = NULL;
static RSA *local_rsa = NULL;
static TSS_HCONTEXT hContext = NULL_HCONTEXT;
static TSS_HKEY hSRK = NULL_HKEY;
static TSS_HPOLICY hSRKPolicy = NULL_HPOLICY;
static TSS_HTPM hTPM = NULL_HTPM;
static TSS_UUID SRK_UUID = TSS_UUID_SRK;
static UINT32 secret_mode = TSS_SECRET_MODE_PLAIN;

/* varibles used to get/set CRYPTO_EX_DATA values */
int ex_app_data = TPM_ENGINE_EX_DATA_UNINIT;

#ifdef DLOPEN_TSPI
/* This is a process-global DSO handle used for loading and unloading
 * the TSS library. NB: This is only set (or unset) during an
 * init() or finish() call (reference counts permitting) and they're
 * operating with global locks, so this should be thread-safe
 * implicitly. */

static DSO *tpm_dso = NULL;

/* These are the function pointers that are (un)set when the library has
 * successfully (un)loaded. */
static unsigned int (*p_tspi_Context_Create)();
static unsigned int (*p_tspi_Context_Close)();
static unsigned int (*p_tspi_Context_Connect)();
static unsigned int (*p_tspi_Context_FreeMemory)();
static unsigned int (*p_tspi_Context_CreateObject)();
static unsigned int (*p_tspi_Context_LoadKeyByUUID)();
static unsigned int (*p_tspi_Context_LoadKeyByBlob)();
static unsigned int (*p_tspi_Context_GetTpmObject)();
static unsigned int (*p_tspi_TPM_GetRandom)();
static unsigned int (*p_tspi_TPM_StirRandom)();
static unsigned int (*p_tspi_Key_CreateKey)();
static unsigned int (*p_tspi_Key_LoadKey)();
static unsigned int (*p_tspi_Data_Bind)();
static unsigned int (*p_tspi_Data_Unbind)();
static unsigned int (*p_tspi_GetAttribData)();
static unsigned int (*p_tspi_SetAttribData)();
static unsigned int (*p_tspi_SetAttribUint32)();
static unsigned int (*p_tspi_GetAttribUint32)();
static unsigned int (*p_tspi_Context_CloseObject)();
static unsigned int (*p_tspi_Hash_Sign)();
static unsigned int (*p_tspi_Hash_SetHashValue)();
static unsigned int (*p_tspi_GetPolicyObject)();
static unsigned int (*p_tspi_Policy_SetSecret)();
static unsigned int (*p_tspi_Policy_AssignToObject)();

/* Override the real function calls to use our indirect pointers */
#define Tspi_Context_Create p_tspi_Context_Create
#define Tspi_Context_Close p_tspi_Context_Close
#define Tspi_Context_Connect p_tspi_Context_Connect
#define Tspi_Context_CreateObject p_tspi_Context_CreateObject
#define Tspi_Context_CloseObject p_tspi_Context_CloseObject
#define Tspi_Context_FreeMemory p_tspi_Context_FreeMemory
#define Tspi_Context_LoadKeyByBlob p_tspi_Context_LoadKeyByBlob
#define Tspi_Context_LoadKeyByUUID p_tspi_Context_LoadKeyByUUID
#define Tspi_Context_GetTpmObject p_tspi_Context_GetTpmObject
#define Tspi_TPM_GetRandom p_tspi_TPM_GetRandom
#define Tspi_TPM_StirRandom p_tspi_TPM_StirRandom
#define Tspi_Key_CreateKey p_tspi_Key_CreateKey
#define Tspi_Key_LoadKey p_tspi_Key_LoadKey
#define Tspi_Data_Bind p_tspi_Data_Bind
#define Tspi_Data_Unbind p_tspi_Data_Unbind
#define Tspi_GetAttribData p_tspi_GetAttribData
#define Tspi_SetAttribData p_tspi_SetAttribData
#define Tspi_GetAttribUint32 p_tspi_GetAttribUint32
#define Tspi_SetAttribUint32 p_tspi_SetAttribUint32
#define Tspi_GetPolicyObject p_tspi_GetPolicyObject
#define Tspi_Hash_Sign p_tspi_Hash_Sign
#define Tspi_Hash_SetHashValue p_tspi_Hash_SetHashValue
#define Tspi_Policy_SetSecret p_tspi_Policy_SetSecret
#define Tspi_Policy_AssignToObject p_tspi_Policy_AssignToObject
#endif /* DLOPEN_TSPI */

/* This internal function is used by ENGINE_tpm() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE * e)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!ENGINE_set_id(e, engine_tpm_id) || !ENGINE_set_name(e, engine_tpm_name) ||
#ifndef OPENSSL_NO_RSA
			!ENGINE_set_RSA(e, &tpm_rsa) ||
#endif
			!ENGINE_set_RAND(e, &tpm_rand) || !ENGINE_set_destroy_function(e, tpm_engine_destroy) || !ENGINE_set_init_function(e, tpm_engine_init)
			|| !ENGINE_set_finish_function(e, tpm_engine_finish) || !ENGINE_set_ctrl_function(e, tpm_engine_ctrl)
			|| !ENGINE_set_load_pubkey_function(e, tpm_engine_load_key) || !ENGINE_set_load_privkey_function(e, tpm_engine_load_key)
			|| !ENGINE_set_cmd_defns(e, tpm_cmd_defns))
        return FAILED;

	/* Ensure the tpm error handling is set up */
	ERR_load_TPM_strings();
    return SUCCESS;
}

static ENGINE *engine_tpm(void)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	ENGINE *ret = ENGINE_new();
	DBG("%s", __FUNCTION__);
	if (!ret)
		return NULL;
	if (!bind_helper(ret))
	{
		ENGINE_free(ret);
		return NULL;
	}
	return ret;
}

void ENGINE_load_tpm(void)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	/* Copied from eng_[openssl|dyn].c */
	ENGINE *toadd = engine_tpm();
	if (!toadd)
		return;
	ENGINE_add(toadd);
	ENGINE_free(toadd);
	ERR_clear_error();
}

int tpm_load_srk(UI_METHOD *ui, void *cb_data)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	TSS_RESULT result;
	UINT32 authusage;
    BYTE *auth = NULL;

	if (hSRK != NULL_HKEY)
	{
		DBGFN("SRK is already loaded.");
        return FAILED;
	}

	if ((result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK)))
	{
		TSSerr(TPM_F_TPM_LOAD_SRK, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	if ((result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO,
	TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &authusage)))
	{
		Tspi_Context_CloseObject(hContext, hSRK);
		TSSerr(TPM_F_TPM_LOAD_SRK, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	if (!authusage)
	{
		DBG("SRK has no auth associated with it.");
        return FAILED;
	}

	/* If hSRKPolicy is non 0, then a policy object for the SRK has already
	 * been set up by engine pre/post commands. Just assign it to the SRK.
	 * Otherwise, we need to get the SRK's implicit policy and prompt for a
	 * secret */
	if (hSRKPolicy)
	{
		DBG("Found an already initialized SRK policy, using it");
		if ((result = Tspi_Policy_AssignToObject(hSRKPolicy, hSRK)))
		{
			TSSerr(TPM_F_TPM_LOAD_SRK, TPM_R_REQUEST_FAILED);
            return FAILED;
		}

        return FAILED;
	}

	if ((result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy)))
	{
		Tspi_Context_CloseObject(hContext, hSRK);
		TSSerr(TPM_F_TPM_LOAD_SRK, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	if ((auth = calloc(1, 128)) == NULL)
	{
		TSSerr(TPM_F_TPM_LOAD_SRK, ERR_R_MALLOC_FAILURE);
        return FAILED;
	}

	if (!tpm_engine_get_auth(ui, (char *) auth, 128, "SRK authorization: ", cb_data))
	{
		Tspi_Context_CloseObject(hContext, hSRK);
		free(auth);
        auth = NULL;
		TSSerr(TPM_F_TPM_LOAD_SRK, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	/* secret_mode is a global that may be set by engine ctrl
	 * commands.  By default, its set to TSS_SECRET_MODE_PLAIN */
	if ((result = Tspi_Policy_SetSecret(hSRKPolicy, secret_mode, strlen((char *) auth), auth)))
	{
		Tspi_Context_CloseObject(hContext, hSRK);
		free(auth);
        auth = NULL;
		TSSerr(TPM_F_TPM_LOAD_SRK, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	free(auth);
    auth = NULL;

    return SUCCESS;
}

/* Destructor (complements the "ENGINE_tpm()" constructor) */
static int tpm_engine_destroy(ENGINE * e)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	/* Unload the tpm error strings so any error state including our
	 * functs or reasons won't lead to a segfault (they simply get displayed
	 * without corresponding string data because none will be found). */
	ERR_unload_TPM_strings();
    return SUCCESS;
}

/* initialisation function */
static int tpm_engine_init(ENGINE * e)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	TSS_RESULT result;

	DBG("%s", __FUNCTION__);

#ifdef DLOPEN_TSPI
	if (tpm_dso != NULL)
	{
		TSSerr(TPM_F_TPM_ENGINE_INIT, TPM_R_ALREADY_LOADED);
        return FAILED;
	}

	if ((tpm_dso = DSO_load(NULL, TPM_LIBNAME, NULL, 0)) == NULL)
	{
		TSSerr(TPM_F_TPM_ENGINE_INIT, TPM_R_DSO_FAILURE);
		goto err;
	}

#define bind_tspi_func(dso, func) (p_tspi_##func = (void *)DSO_bind_func(dso, "Tspi_" #func))

	if (!bind_tspi_func(tpm_dso, Context_Create) ||
			!bind_tspi_func(tpm_dso, Context_Close) ||
			!bind_tspi_func(tpm_dso, Context_Connect) ||
			!bind_tspi_func(tpm_dso, TPM_GetRandom) ||
			!bind_tspi_func(tpm_dso, Key_CreateKey) ||
			!bind_tspi_func(tpm_dso, Data_Bind) ||
			!bind_tspi_func(tpm_dso, Data_Unbind) ||
			!bind_tspi_func(tpm_dso, Context_CreateObject) ||
			!bind_tspi_func(tpm_dso, Context_FreeMemory) ||
			!bind_tspi_func(tpm_dso, Key_LoadKey) ||
			!bind_tspi_func(tpm_dso, Context_LoadKeyByUUID) ||
			!bind_tspi_func(tpm_dso, GetAttribData) ||
			!bind_tspi_func(tpm_dso, Hash_Sign) ||
			!bind_tspi_func(tpm_dso, Context_CloseObject) ||
			!bind_tspi_func(tpm_dso, Hash_SetHashValue) ||
			!bind_tspi_func(tpm_dso, SetAttribUint32) ||
			!bind_tspi_func(tpm_dso, GetPolicyObject) ||
			!bind_tspi_func(tpm_dso, Policy_SetSecret) ||
			!bind_tspi_func(tpm_dso, TPM_StirRandom) ||
			!bind_tspi_func(tpm_dso, Context_LoadKeyByBlob) ||
			!bind_tspi_func(tpm_dso, Context_GetTpmObject) ||
			!bind_tspi_func(tpm_dso, GetAttribUint32) ||
			!bind_tspi_func(tpm_dso, SetAttribData) ||
			!bind_tspi_func(tpm_dso, Policy_AssignToObject)
	)
	{
		TSSerr(TPM_F_TPM_ENGINE_INIT, TPM_R_DSO_FAILURE);
		goto err;
	}
#endif /* DLOPEN_TSPI */

	if ((result = Tspi_Context_Create(&hContext)))
	{
		TSSerr(TPM_F_TPM_ENGINE_INIT, TPM_R_UNIT_FAILURE);
		goto err;
	}

	/* XXX allow dest to be specified through pre commands */
	if ((result = Tspi_Context_Connect(hContext, NULL)))
	{
		TSSerr(TPM_F_TPM_ENGINE_INIT, TPM_R_UNIT_FAILURE);
		goto err;
	}

	if ((result = Tspi_Context_GetTpmObject(hContext, &hTPM)))
	{
		TSSerr(TPM_F_TPM_ENGINE_INIT, TPM_R_UNIT_FAILURE);
		goto err;
	}

	tpm_rsa.rsa_mod_exp = RSA_PKCS1_SSLeay()->rsa_mod_exp;

    return SUCCESS;
	err: if (hContext != NULL_HCONTEXT)
	{
		Tspi_Context_Close(hContext);
		hContext = NULL_HCONTEXT;
		hTPM = NULL_HTPM;
	}

#ifdef DLOPEN_TSPI
	if (tpm_dso)
	{
		DSO_free(tpm_dso);
		tpm_dso = NULL;
	}

	p_tspi_Context_Create = NULL;
	p_tspi_Context_Close = NULL;
	p_tspi_Context_Connect = NULL;
	p_tspi_Context_FreeMemory = NULL;
	p_tspi_Context_LoadKeyByBlob = NULL;
	p_tspi_Context_LoadKeyByUUID = NULL;
	p_tspi_Context_GetTpmObject = NULL;
	p_tspi_Context_CloseObject = NULL;
	p_tspi_Key_CreateKey = NULL;
	p_tspi_Key_LoadKey = NULL;
	p_tspi_Data_Bind = NULL;
	p_tspi_Data_Unbind = NULL;
	p_tspi_Hash_SetHashValue = NULL;
	p_tspi_Hash_Sign = NULL;
	p_tspi_GetAttribData = NULL;
	p_tspi_SetAttribData = NULL;
	p_tspi_GetAttribUint32 = NULL;
	p_tspi_SetAttribUint32 = NULL;
	p_tspi_GetPolicyObject = NULL;
	p_tspi_Policy_SetSecret = NULL;
	p_tspi_Policy_AssignToObject = NULL;
	p_tspi_TPM_StirRandom = NULL;
	p_tspi_TPM_GetRandom = NULL;
#endif
    return FAILED;
}

static char *tpm_engine_get_auth(UI_METHOD *ui_method, char *auth, int maxlen, char *input_string, void *cb_data)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	UI *ui;

	DBG("%s", __FUNCTION__);

	ui = UI_new();
	if (ui_method)
		UI_set_method(ui, ui_method);
	UI_add_user_data(ui, cb_data);

	if (!UI_add_input_string(ui, input_string, 0, auth, 0, maxlen))
	{
		TSSerr(TPM_F_TPM_ENGINE_GET_AUTH, TPM_R_UI_METHOD_FAILED);
		UI_free(ui);
		return NULL;
	}

	if (UI_process(ui))
	{
		TSSerr(TPM_F_TPM_ENGINE_GET_AUTH, TPM_R_UI_METHOD_FAILED);
		UI_free(ui);
		return NULL;
	}

	UI_free(ui);
	return auth;
}

static int tpm_engine_finish(ENGINE * e)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	DBG("%s", __FUNCTION__);

#ifdef DLOPEN_TSPI
	if (tpm_dso == NULL)
	{
		TSSerr(TPM_F_TPM_ENGINE_FINISH, TPM_R_NOT_LOADED);
        return FAILED;
	}
#endif
	if (hContext != NULL_HCONTEXT)
	{
		Tspi_Context_Close(hContext);
		hContext = NULL_HCONTEXT;
	}
#ifdef DLOPEN_TSPI
	if (!DSO_free(tpm_dso))
	{
		TSSerr(TPM_F_TPM_ENGINE_FINISH, TPM_R_DSO_FAILURE);
        return FAILED;
	}
	tpm_dso = NULL;
#endif
    return SUCCESS;
}

int fill_out_rsa_object(RSA *rsa, TSS_HKEY hKey)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	TSS_RESULT result;
	UINT32 pubkey_len, encScheme, sigScheme;
	BYTE *pubkey;
	struct rsa_app_data *app_data;

	DBG("%s", __FUNCTION__);

	if ((result = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	TSS_TSPATTRIB_KEYINFO_ENCSCHEME, &encScheme)))
	{
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	if ((result = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	TSS_TSPATTRIB_KEYINFO_SIGSCHEME, &sigScheme)))
	{
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	/* pull out the public key and put it into the RSA object */
	if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
	TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &pubkey_len, &pubkey)))
	{
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	if ((rsa->n = BN_bin2bn(pubkey, pubkey_len, rsa->n)) == NULL)
	{
		Tspi_Context_FreeMemory(hContext, pubkey);
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, TPM_R_BN_CONVERSION_FAILED);
        return FAILED;
	}

	Tspi_Context_FreeMemory(hContext, pubkey);

	/* set e in the RSA object */
	if (!rsa->e && ((rsa->e = BN_new()) == NULL))
	{
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, ERR_R_MALLOC_FAILURE);
        return FAILED;
	}

	if (!BN_set_word(rsa->e, 65537))
	{
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, TPM_R_REQUEST_FAILED);
		BN_free(rsa->e);
		rsa->e = NULL;
        return FAILED;
	}

	if ((app_data = OPENSSL_malloc(sizeof(struct rsa_app_data))) == NULL)
	{
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, ERR_R_MALLOC_FAILURE);
		BN_free(rsa->e);
		rsa->e = NULL;
        return FAILED;
	}

	DBG("Setting hKey(0x%x) in RSA object", hKey);DBG("Setting encScheme(0x%x) in RSA object", encScheme);DBG("Setting sigScheme(0x%x) in RSA object", sigScheme);

	memset(app_data, 0, sizeof(struct rsa_app_data));
	app_data->hKey = hKey;
	app_data->encScheme = encScheme;
	app_data->sigScheme = sigScheme;
	RSA_set_ex_data(rsa, ex_app_data, app_data);

    return SUCCESS;
}

static EVP_PKEY *tpm_engine_load_key(ENGINE *e, const char *key_id, UI_METHOD *ui, void *cb_data)
{
	ASN1_OCTET_STRING *blobstr;
	TSS_HKEY hKey;
	TSS_RESULT result;
	UINT32 authusage;
	RSA *rsa;
	EVP_PKEY *pkey;
	BIO *bf;

	DBG("%s", __FUNCTION__);

	if (!key_id)
	{
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	if (!tpm_load_srk(ui, cb_data))
	{
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_SRK_LOAD_FAILED);
		return NULL;
	}

	if ((bf = BIO_new_file(key_id, "r")) == NULL)
	{
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_FILE_NOT_FOUND);
		return NULL;
	}

	blobstr = PEM_ASN1_read_bio((void *) d2i_ASN1_OCTET_STRING, "TSS KEY BLOB", bf, NULL, NULL, NULL);
	if (!blobstr)
	{
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_FILE_READ_FAILED);
		BIO_free(bf);
		return NULL;
	}

	BIO_free(bf);
	DBG("Loading blob of size: %d", blobstr->length);
	if ((result = Tspi_Context_LoadKeyByBlob(hContext, hSRK, blobstr->length, blobstr->data, &hKey)))
	{
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
		return NULL;
	}
	ASN1_OCTET_STRING_free(blobstr);

	if ((result = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &authusage)))
	{
		Tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
		return NULL;
	}

	if (authusage)
	{
		TSS_HPOLICY hPolicy;
		BYTE *auth;

		if ((auth = calloc(1, 128)) == NULL)
		{
			Tspi_Context_CloseObject(hContext, hKey);
			TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, ERR_R_MALLOC_FAILURE);
			return NULL;
		}

		if (!tpm_engine_get_auth(ui, (char *) auth, 128, "TPM Key Password: ", cb_data))
		{
			Tspi_Context_CloseObject(hContext, hKey);
			free(auth);
            auth = NULL;
			TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
			return NULL;
		}

		if ((result = Tspi_Context_CreateObject(hContext,
		TSS_OBJECT_TYPE_POLICY,
		TSS_POLICY_USAGE, &hPolicy)))
		{
			Tspi_Context_CloseObject(hContext, hKey);
			free(auth);
            auth = NULL;
			TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
            return NULL;
		}

		if ((result = Tspi_Policy_AssignToObject(hPolicy, hKey)))
		{
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_CloseObject(hContext, hPolicy);
			free(auth);
            auth = NULL;
			TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
            return NULL;
		}

		if ((result = Tspi_Policy_SetSecret(hPolicy,
		TSS_SECRET_MODE_PLAIN, strlen((char *) auth), auth)))
		{
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_CloseObject(hContext, hPolicy);
			free(auth);
            auth = NULL;
			TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
            return NULL;
		}

		free(auth);
        auth = NULL;
	}

	/* create the new objects to return */
	if ((pkey = EVP_PKEY_new()) == NULL)
	{
		Tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	pkey->type = EVP_PKEY_RSA;

	if ((rsa = RSA_new()) == NULL)
	{
		EVP_PKEY_free(pkey);
		Tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	rsa->meth = &tpm_rsa;
	/* call our local init function here */
	rsa->meth->init(rsa);
	pkey->pkey.rsa = rsa;

	if (!fill_out_rsa_object(rsa, hKey))
	{
		EVP_PKEY_free(pkey);
		RSA_free(rsa);
		Tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
		return NULL;
	}

	EVP_PKEY_assign_RSA(pkey, rsa);

	return pkey;
}

static int tpm_create_srk_policy(void *secret)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	TSS_RESULT result;
	UINT32 secret_len;

	if (secret_mode == TSS_SECRET_MODE_SHA1)
		secret_len = SHA_DIGEST_LENGTH;
	else
	{
		secret_len = (secret == NULL) ? 0 : strlen((char *) secret);
		DBG("Using SRK secret = %s", (BYTE *)secret);
	}

	if (hSRKPolicy == NULL_HPOLICY)
	{
		DBG("Creating SRK policy");
		if ((result = Tspi_Context_CreateObject(hContext,
		TSS_OBJECT_TYPE_POLICY,
		TSS_POLICY_USAGE, &hSRKPolicy)))
		{
			TSSerr(TPM_F_TPM_CREATE_SRK_POLICY, TPM_R_REQUEST_FAILED);
            return FAILED;
		}
	}

	if ((result = Tspi_Policy_SetSecret(hSRKPolicy, secret_mode, secret_len, (BYTE *) secret)))
	{
		TSSerr(TPM_F_TPM_CREATE_SRK_POLICY, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

    return SUCCESS;
}

static int tpm_engine_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f)())
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int initialised = !!hContext;
	DBG("%s", __FUNCTION__);

	switch (cmd)
	{
		case TPM_CMD_SO_PATH:
			if (p == NULL)
			{
				TSSerr(TPM_F_TPM_ENGINE_CTRL, ERR_R_PASSED_NULL_PARAMETER);
                return FAILED;
			}
			if (initialised)
			{
				TSSerr(TPM_F_TPM_ENGINE_CTRL, TPM_R_ALREADY_LOADED);
                return FAILED;
			}
			TPM_LIBNAME = (const char *) p;
            return SUCCESS;
		case TPM_CMD_SECRET_MODE:
			switch ((UINT32) i)
			{
				case TSS_SECRET_MODE_POPUP:
					secret_mode = (UINT32) i;
					return tpm_create_srk_policy(p);
				case TSS_SECRET_MODE_SHA1:
					/* fall through */
				case TSS_SECRET_MODE_PLAIN:
					secret_mode = (UINT32) i;
					break;
				default:
					TSSerr(TPM_F_TPM_ENGINE_CTRL, TPM_R_UNKNOWN_SECRET_MODE);
					return 0;
					break;
			}
            return SUCCESS;
		case TPM_CMD_PIN:
			return tpm_create_srk_policy(p);
		default:
			break;
	}
	TSSerr(TPM_F_TPM_ENGINE_CTRL, TPM_R_CTRL_COMMAND_NOT_IMPLEMENTED);

    return FAILED;
}

#ifndef OPENSSL_NO_RSA
static int tpm_rsa_init(RSA *rsa)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	DBG("%s", __FUNCTION__);

	if (ex_app_data == TPM_ENGINE_EX_DATA_UNINIT)
		ex_app_data = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);

	if (ex_app_data == TPM_ENGINE_EX_DATA_UNINIT)
	{
		TSSerr(TPM_F_TPM_RSA_INIT, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

    return SUCCESS;
}

static int tpm_rsa_finish(RSA *rsa)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	struct rsa_app_data *app_data = RSA_get_ex_data(rsa, ex_app_data);

	DBG("%s", __FUNCTION__);

	if (!app_data)
        return FAILED;

	if (app_data->hHash)
	{
		Tspi_Context_CloseObject(hContext, app_data->hHash);
		app_data->hHash = NULL_HHASH;
	}

	if (app_data->hKey)
	{
		Tspi_Context_CloseObject(hContext, app_data->hKey);
		app_data->hKey = NULL_HKEY;
	}

	if (app_data->hEncData)
	{
		Tspi_Context_CloseObject(hContext, app_data->hEncData);
		app_data->hEncData = NULL_HENCDATA;
	}

	OPENSSL_free(app_data);

    return SUCCESS;
}

static int tpm_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int rv = 0;

	DBG("%s", __FUNCTION__);

	if ((rv = RSA_PKCS1_SSLeay()->rsa_pub_dec(flen, from, to, rsa, padding)) < 0)
	{
		TSSerr(TPM_F_TPM_RSA_PUB_DEC, TPM_R_REQUEST_FAILED);
        return 0;
	}

	return rv;
}

static int tpm_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	struct rsa_app_data *app_data = RSA_get_ex_data(rsa, ex_app_data);
	TSS_RESULT result;
	UINT32 out_len, in_len;
	BYTE *out;
    int rv = 0;

	DBG("%s", __FUNCTION__);

	if (!app_data)
	{
		DBG("No app data found for RSA object %p. Calling software.",
				rsa);
		if ((rv = RSA_PKCS1_SSLeay()->rsa_priv_dec(flen, from, to, rsa, padding)) < 0)
		{
			TSSerr(TPM_F_TPM_RSA_PRIV_DEC, TPM_R_REQUEST_FAILED);
		}

		return rv;
	}

	if (app_data->hKey == NULL_HKEY)
	{
		TSSerr(TPM_F_TPM_RSA_PRIV_DEC, TPM_R_INVALID_KEY);
        return 0;
	}

	if (app_data->hEncData == NULL_HENCDATA)
	{
		if ((result = Tspi_Context_CreateObject(hContext,
		TSS_OBJECT_TYPE_ENCDATA,
		TSS_ENCDATA_BIND, &app_data->hEncData)))
		{
			TSSerr(TPM_F_TPM_RSA_PRIV_DEC, TPM_R_REQUEST_FAILED);
            return 0;
		}
	}

	if (padding == RSA_PKCS1_PADDING && app_data->encScheme != TSS_ES_RSAESPKCSV15)
	{
		TSSerr(TPM_F_TPM_RSA_PRIV_DEC, TPM_R_INVALID_PADDING_TYPE);DBG("encScheme(0x%x) in RSA object", app_data->encScheme);
		return 0;
	} else if (padding == RSA_PKCS1_OAEP_PADDING && app_data->encScheme != TSS_ES_RSAESOAEP_SHA1_MGF1)
	{
		TSSerr(TPM_F_TPM_RSA_PRIV_DEC, TPM_R_INVALID_PADDING_TYPE);DBG("encScheme(0x%x) in RSA object", app_data->encScheme);
        return 0;
	}

	in_len = flen;
	if ((result = Tspi_SetAttribData(app_data->hEncData,
	TSS_TSPATTRIB_ENCDATA_BLOB,
	TSS_TSPATTRIB_ENCDATABLOB_BLOB, in_len, from)))
	{
		TSSerr(TPM_F_TPM_RSA_PRIV_DEC, TPM_R_REQUEST_FAILED);
        return 0;
	}

	if ((result = Tspi_Data_Unbind(app_data->hEncData, app_data->hKey, &out_len, &out)))
	{
		TSSerr(TPM_F_TPM_RSA_PRIV_DEC, TPM_R_REQUEST_FAILED);
        return 0;
	}

	DBG("%s: writing out %d bytes as a signature", __FUNCTION__, out_len);

	memcpy(to, out, out_len);
	Tspi_Context_FreeMemory(hContext, out);

	return out_len;
}

static int tpm_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	struct rsa_app_data *app_data = RSA_get_ex_data(rsa, ex_app_data);
	TSS_RESULT result;
	UINT32 out_len, in_len;
	BYTE *out;
    int rv = 0;

	DBG("%s", __FUNCTION__);

	if (!app_data)
	{
		DBG("No app data found for RSA object %p. Calling software.",
				rsa);
		if ((rv = RSA_PKCS1_SSLeay()->rsa_pub_enc(flen, from, to, rsa, padding)) < 0)
		{
			TSSerr(TPM_F_TPM_RSA_PUB_ENC, TPM_R_REQUEST_FAILED);
		}

		return rv;
	}

	if (app_data->hKey == NULL_HKEY)
	{
		TSSerr(TPM_F_TPM_RSA_PUB_ENC, TPM_R_INVALID_KEY);
        return 0;
	}

	if (app_data->hEncData == NULL_HENCDATA)
	{
		if ((result = Tspi_Context_CreateObject(hContext,
		TSS_OBJECT_TYPE_ENCDATA,
		TSS_ENCDATA_BIND, &app_data->hEncData)))
		{
			TSSerr(TPM_F_TPM_RSA_PUB_ENC, TPM_R_REQUEST_FAILED);
            return 0;
		}DBG("Setting hEncData(0x%x) in RSA object", app_data->hEncData);
	}

	DBG("flen is %d", flen);

	if (padding == RSA_PKCS1_PADDING)
	{
		if (app_data->encScheme != TSS_ES_RSAESPKCSV15)
		{
			TSSerr(TPM_F_TPM_RSA_PUB_ENC, TPM_R_INVALID_PADDING_TYPE);DBG("encScheme(0x%x) in RSA object",
					app_data->encScheme);
            return 0;
		}

		if (flen > (RSA_size(rsa) - RSA_PKCS1_PADDING_SIZE))
		{
			TSSerr(TPM_F_TPM_RSA_PUB_ENC, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
            return 0;
		}
	} else if (padding == RSA_PKCS1_OAEP_PADDING)
	{
		if (app_data->encScheme != TSS_ES_RSAESOAEP_SHA1_MGF1)
		{
			TSSerr(TPM_F_TPM_RSA_PUB_ENC, TPM_R_INVALID_PADDING_TYPE);DBG("encScheme(0x%x) in RSA object",
					app_data->encScheme);
            return 0;
		}

		/* subtract an extra 5 for the TCPA_BOUND_DATA structure */
		if (flen > (RSA_size(rsa) - RSA_PKCS1_PADDING_SIZE - 5))
		{
			TSSerr(TPM_F_TPM_RSA_PUB_ENC, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
            return 0;
		}
	} else
	{
		TSSerr(TPM_F_TPM_RSA_PUB_ENC, TPM_R_INVALID_ENC_SCHEME);
        return 0;
	}

	in_len = flen;
	DBG("Bind: hKey(0x%x) hEncData(0x%x) in_len(%u)", app_data->hKey,
			app_data->hEncData, in_len);

	if ((result = Tspi_Data_Bind(app_data->hEncData, app_data->hKey, in_len, from)))
	{
		TSSerr(TPM_F_TPM_RSA_PUB_ENC, TPM_R_REQUEST_FAILED);DBG("result = 0x%x (%s)", result,
				Trspi_Error_String(result));
        return 0;
	}

	/* pull out the bound data and return it */
	if ((result = Tspi_GetAttribData(app_data->hEncData,
	TSS_TSPATTRIB_ENCDATA_BLOB,
	TSS_TSPATTRIB_ENCDATABLOB_BLOB, &out_len, &out)))
	{
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_REQUEST_FAILED);
        return 0;
	}

	DBG("%s: writing out %d bytes as bound data", __FUNCTION__, out_len);

	memcpy(to, out, out_len);
	Tspi_Context_FreeMemory(hContext, out);

	return out_len;
}

static int tpm_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	struct rsa_app_data *app_data = RSA_get_ex_data(rsa, ex_app_data);
	TSS_RESULT result;
	UINT32 sig_len;
	BYTE *sig;
    int rv = 0;

	DBG("%s", __FUNCTION__);

	if (!app_data)
	{
		DBG("No app data found for RSA object %p. Calling software.",
				rsa);
		if ((rv = RSA_PKCS1_SSLeay()->rsa_priv_enc(flen, from, to, rsa, padding)) < 0)
		{
			TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_REQUEST_FAILED);
		}

		return rv;
	}

	if (padding != RSA_PKCS1_PADDING)
	{
		TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_INVALID_PADDING_TYPE);
        return 0;
	}

	if (app_data->hKey == NULL_HKEY)
	{
		TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_INVALID_KEY);
        return 0;
	}

	if (app_data->hHash == NULL_HHASH)
	{
		if ((result = Tspi_Context_CreateObject(hContext,
		TSS_OBJECT_TYPE_HASH,
		TSS_HASH_OTHER, &app_data->hHash)))
		{
			TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_REQUEST_FAILED);
            return 0;
		}
	}

	if (app_data->sigScheme == TSS_SS_RSASSAPKCS1V15_SHA1)
	{
		if (flen != SHA_DIGEST_LENGTH)
		{
			TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_INVALID_MSG_SIZE);
            return 0;
		}
	} else if (app_data->sigScheme == TSS_SS_RSASSAPKCS1V15_DER)
	{
		if (flen > (RSA_size(rsa) - RSA_PKCS1_PADDING_SIZE))
		{
			TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_INVALID_MSG_SIZE);
            return 0;
		}
	} else
	{
		TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_INVALID_ENC_SCHEME);
        return 0;
	}

	if ((result = Tspi_Hash_SetHashValue(app_data->hHash, flen, from)))
	{
		TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_REQUEST_FAILED);
        return 0;
	}

	if ((result = Tspi_Hash_Sign(app_data->hHash, app_data->hKey, &sig_len, &sig)))
	{
		TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_REQUEST_FAILED);DBG("result = 0x%x (%s)", result,
				Trspi_Error_String(result));
        return 0;
	}

	DBG("%s: writing out %d bytes as a signature", __FUNCTION__, sig_len);

	memcpy(to, sig, sig_len);
	Tspi_Context_FreeMemory(hContext, sig);

	return sig_len;
}

/* create a new key.  we need a way to specify creation of a key with OAEP
 * padding as well as PKCSv1.5, since signatures will need to be done on
 * data larger than 20 bytes, which is the max size *regardless of key size*
 * for an OAEP key signing using the TPM */
static int tpm_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	TSS_RESULT result;
	TSS_FLAG initFlags = TSS_KEY_TYPE_LEGACY;
	UINT32 encScheme, sigScheme;
	TSS_HKEY hKey;

	/* XXX allow this to be specified through pre commands */
	sigScheme = TSS_SS_RSASSAPKCS1V15_DER;
	encScheme = TSS_ES_RSAESPKCSV15;

	DBG("%s", __FUNCTION__);

	if (!BN_is_word(e, 65537))
	{
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_INVALID_EXPONENT);
        return FAILED;
	}

	/* set e in the RSA object as done in the built-in openssl function */
	if (!rsa->e && ((rsa->e = BN_new()) == NULL))
	{
		TSSerr(TPM_F_TPM_RSA_KEYGEN, ERR_R_MALLOC_FAILURE);
        return FAILED;
	}
	BN_copy(rsa->e, e);

	switch (bits)
	{
		case 512:
			initFlags |= TSS_KEY_SIZE_512;
			break;
		case 1024:
			initFlags |= TSS_KEY_SIZE_1024;
			break;
		case 2048:
			initFlags |= TSS_KEY_SIZE_2048;
			break;
		case 4096:
			initFlags |= TSS_KEY_SIZE_4096;
			break;
		case 8192:
			initFlags |= TSS_KEY_SIZE_8192;
			break;
		case 16384:
			initFlags |= TSS_KEY_SIZE_16384;
			break;
		default:
			TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_INVALID_KEY_SIZE);
            return FAILED;
	}

	/* Load the parent key (SRK) which will wrap the new key */
	if (!tpm_load_srk(NULL, NULL))
	{
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_SRK_LOAD_FAILED);
        return FAILED;
	}

	/* Create the new key object */
	if ((result = Tspi_Context_CreateObject(hContext,
	TSS_OBJECT_TYPE_RSAKEY, initFlags, &hKey)))
	{
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	/* set the signature scheme */
	if ((result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	TSS_TSPATTRIB_KEYINFO_SIGSCHEME, sigScheme)))
	{
		Tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	/* set the encryption scheme */
	if ((result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	TSS_TSPATTRIB_KEYINFO_ENCSCHEME, encScheme)))
	{
		Tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	/* Call create key using the new object */
	if ((result = Tspi_Key_CreateKey(hKey, hSRK, NULL_HPCRS)))
	{
		Tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	if (!fill_out_rsa_object(rsa, hKey))
	{
		Tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	/* Load the key into the chip so other functions don't need to */
	if ((result = Tspi_Key_LoadKey(hKey, hSRK)))
	{
		Tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

    return SUCCESS;
}
#endif

static int tpm_rand_bytes(unsigned char *buf, int num)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	TSS_RESULT result;
	BYTE *rand_data;
	UINT32 total_requested = 0;

	DBG("%s getting %d bytes", __FUNCTION__, num);

	if (num - total_requested > 4096)
	{
		if ((result = Tspi_TPM_GetRandom(hTPM, 4096, &rand_data)))
		{
			TSSerr(TPM_F_TPM_RAND_BYTES, TPM_R_REQUEST_FAILED);
            return FAILED;
		}

		memcpy(&buf[total_requested], rand_data, 4096);
		Tspi_Context_FreeMemory(hContext, rand_data);
		total_requested += 4096;
	}

	if ((result = Tspi_TPM_GetRandom(hTPM, num - total_requested, &rand_data)))
	{
		TSSerr(TPM_F_TPM_RAND_BYTES, TPM_R_REQUEST_FAILED);
        return FAILED;
	}

	memcpy(buf + total_requested, rand_data, num - total_requested);
	Tspi_Context_FreeMemory(hContext, rand_data);

    return SUCCESS;
}

static int tpm_rand_status(void)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	DBG("%s", __FUNCTION__);
    return SUCCESS;
}

static void tpm_rand_seed(const void *buf, int num)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	TSS_RESULT result;
	UINT32 total_stirred = 0;

	DBG("%s", __FUNCTION__);

	/* There's a hard maximum of 255 bytes allowed to be sent to the TPM on a TPM_StirRandom
	 * call.  Use all the bytes in  buf, but break them in to 255 or smaller byte chunks */
	while (num - total_stirred > 255)
	{
		if ((result = Tspi_TPM_StirRandom(hTPM, 255, buf + total_stirred)))
		{
			TSSerr(TPM_F_TPM_RAND_SEED, TPM_R_REQUEST_FAILED);
			return;
		}

		total_stirred += 255;
	}

	if ((result = Tspi_TPM_StirRandom(hTPM, num - total_stirred, buf + total_stirred)))
	{
		TSSerr(TPM_F_TPM_RAND_SEED, TPM_R_REQUEST_FAILED);
	}

	return;
}

/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */
static int bind_fn(ENGINE * e, const char *id)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (id && (strcmp(id, engine_tpm_id) != 0))
	{
		TSSerr(TPM_F_TPM_BIND_FN, TPM_R_ID_INVALID);
        return FAILED;
	}
	if (!bind_helper(e))
	{
		TSSerr(TPM_F_TPM_BIND_FN, TPM_R_REQUEST_FAILED);
        return FAILED;
	}
    return SUCCESS;
}

/***********************************************************
 Function:       init_rsa
 Description:    初始化TPM和本地证书
 Calls:
 Called By:
 Input:
 Output:
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
int init_rsa(char *prikey)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    //for arm and x86
    FILE *fp = NULL;
//    if ((fp = fopen(PRIKEY, "r")) == NULL)
    if ((fp = fopen(prikey, "r")) == NULL)
    {
        return FAILED;
    }

    if ((local_rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, "123123")) == NULL)
    {
        fclose(fp);//add by kobe
        return FAILED;
    }
    fclose(fp);
    return SUCCESS;
/*
//#ifdef __aarch64__
#if (defined __aarch64__ ) || (defined KOBE_NO_DEV_TEST)
    FILE *fp = NULL;
//    if ((fp = fopen(PRIKEY, "r")) == NULL)
    if ((fp = fopen(prikey, "r")) == NULL)
    {
        return FAILED;
    }

    if ((local_rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, "123123")) == NULL)
    {
        fclose(fp);//add by kobe
        return FAILED;
    }
    fclose(fp);
#else
    ENGINE_load_builtin_engines();
    ENGINE* engine = ENGINE_by_id("tpm");
    ENGINE_init(engine);

    UI_METHOD* ui_method = UI_OpenSSL();
//    tpm_pkey = ENGINE_load_private_key(engine, PRIKEY, ui_method, NULL);
    tpm_pkey = ENGINE_load_private_key(engine, prikey, ui_method, NULL);
#endif
    return SUCCESS;*/
}

/***********************************************************
 Function:       client_encrypt_data
 Description:    客户端加密数据
 Calls:
 Called By:
 Input:			 待加密数据
 Output:		 加密后的数据
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
int client_encrypt_data(char* data, char *encryptdata)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int rsa_len = 0;
	char encryptRSA[2048] = { 0 };

    //for arm and x86
    if (local_rsa == NULL) {
        return 0;
    }
    rsa_len = RSA_size(local_rsa);
    if (RSA_public_encrypt(rsa_len - 11, (unsigned char *) data, (unsigned char*) encryptRSA, local_rsa, RSA_PKCS1_PADDING) < 0)
    {
        return 0;
    }
    memcpy(encryptdata, encryptRSA, rsa_len);
    return rsa_len;

/*
//#ifdef __aarch64__
#if (defined __aarch64__ ) || (defined KOBE_NO_DEV_TEST)
    if (local_rsa == NULL) {
        return 0;
    }
    rsa_len = RSA_size(local_rsa);
    if (RSA_public_encrypt(rsa_len - 11, (unsigned char *) data, (unsigned char*) encryptRSA, local_rsa, RSA_PKCS1_PADDING) < 0)
    {
        return 0;
    }
#else
    rsa_len = RSA_size(tpm_pkey->pkey.rsa);
    if (RSA_public_encrypt(rsa_len - 11, (unsigned char *) data, (unsigned char*) encryptRSA, tpm_pkey->pkey.rsa, RSA_PKCS1_PADDING) < 0)
    {
        return 0;
    }
#endif
	memcpy(encryptdata, encryptRSA, rsa_len);
    return rsa_len;*/
}

/***********************************************************
 Function:       client_decrypt_data
 Description:    客户端解密数据
 Calls:
 Called By:
 Input:			 待解密数据
 Output:		 解密后的数据
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
int client_decrypt_data(char *encryptdata, char* decryptdata)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int rsa_len = 0;
	BYTE decryptresult[300] = { 0 };

    //for arm and x86
    rsa_len = RSA_size(local_rsa);
    if (RSA_private_decrypt(rsa_len, (unsigned char *) encryptdata, (unsigned char*) decryptresult, local_rsa, RSA_PKCS1_PADDING) < 0)
    {
        return FAILED;
    }
    memcpy(decryptdata, decryptresult, rsa_len);
    return SUCCESS;

    /*
//#ifdef __aarch64__
#if (defined __aarch64__ ) || (defined KOBE_NO_DEV_TEST)
    rsa_len = RSA_size(local_rsa);
    if (RSA_private_decrypt(rsa_len, (unsigned char *) encryptdata, (unsigned char*) decryptresult, local_rsa, RSA_PKCS1_PADDING) < 0)
    {
        return FAILED;
    }
#else
    rsa_len = RSA_size(tpm_pkey->pkey.rsa);
    if (RSA_private_decrypt(rsa_len, (unsigned char *) encryptdata, (unsigned char*) decryptresult, tpm_pkey->pkey.rsa, RSA_PKCS1_PADDING) < 0)
    {
        return FAILED;
    }
#endif
	memcpy(decryptdata, decryptresult, rsa_len);
    return SUCCESS;*/
}

/***********************************************************
 Function:       client_encrypt_file
 Description:    客户端加密文件
 Calls:
 Called By:
 Input:			 待加密文件名，加密后文件名
 Output:
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
/*int client_encrypt_file(char *infile, char *outfile)
{

	int rc;
	FILE *in, *out;
	unsigned char buf[MAXLEN] = { 0 };
	unsigned char data_decrypted[PRIKEYLEN] = { 0 };
	char data_encrypted[256] = { 0 };
	int rsa_len = 0;
	in = fopen(infile, "rb");
	if (in == NULL)
	{ //add by kobe
		return EXIT_FAILURE;
	}
	out = fopen(outfile, "wb");
	if (out == NULL)
	{ //add by kobe
		fclose(in);
		return EXIT_FAILURE;
	}

    //kobe test tpm
//    while ((rc = fread(buf, sizeof(unsigned char), MAXLEN, in)) != 0)
//    {
//        rsa_len = RSA_size(local_rsa);
//        if (RSA_public_encrypt(rsa_len - 11, (unsigned char *) buf, (unsigned char*) data_encrypted, local_rsa,
//        RSA_PKCS1_PADDING) < 0)
//        {
//            fclose(in);//add by kobe
//            fclose(out);
//            return EXIT_FAILURE;
//        }
//        fwrite(data_encrypted, sizeof(unsigned char), PRIKEYLEN, out);
//    }

#ifdef __aarch64__
    while ((rc = fread(buf, sizeof(unsigned char), MAXLEN, in)) != 0)
    {
        rsa_len = RSA_size(local_rsa);
        if (RSA_public_encrypt(rsa_len - 11, (unsigned char *) buf, (unsigned char*) data_encrypted, local_rsa,
        RSA_PKCS1_PADDING) < 0)
        {
            fclose(in);//add by kobe
            fclose(out);
            return EXIT_FAILURE;
        }
        fwrite(data_encrypted, sizeof(unsigned char), PRIKEYLEN, out);
    }
#else
    while ((rc = fread(buf, sizeof(unsigned char), MAXLEN, in)) != 0)
    {
        rsa_len = RSA_size(tpm_pkey->pkey.rsa);
        if (RSA_public_encrypt(rsa_len - 11, (unsigned char *) buf, (unsigned char*) data_encrypted, tpm_pkey->pkey.rsa,
                        RSA_PKCS1_PADDING) < 0)
        {
            fclose(in);//add by kobe
            fclose(out);
            return EXIT_FAILURE;
        }
        fwrite(data_encrypted, sizeof(unsigned char), PRIKEYLEN, out);
    }
#endif

    fclose(in);
    fclose(out);
    return EXIT_SUCCESS;
}*/

/***********************************************************
 Function:       client_decrypt_file
 Description:    客户端解密文件
 Calls:
 Called By:
 Input:			 待解密文件名，解密后文件名
 Output:
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
int client_decrypt_file(char *infile, char *outfile)
{

	int rc;
	FILE *in, *out;
	unsigned char buf[PRIKEYLEN] = { 0 };
	char data_encrypted[MAXLEN] = { 0 };
	int rsa_len = 0;
        if((infile == NULL) || (outfile == NULL) || (local_rsa == NULL))
        {
            return 1;
        }

	in = fopen(infile, "rb");

	out = fopen(outfile, "wb");;

	if((in == NULL) || (out == NULL))
	{
	    return 1;
	}
    

	while ((rc = fread(buf, sizeof(unsigned char), PRIKEYLEN, in)) != 0)
	{

			//printf("Decrypt rc %d\r\n",rc);
		rsa_len = RSA_size(local_rsa);
	memset(data_encrypted, 0, MAXLEN);
	int iLen = RSA_private_decrypt(rsa_len, (unsigned char *) buf, (unsigned char*) data_encrypted, local_rsa,
		RSA_PKCS1_PADDING);
		
//	printf("iLen %d\r\n",iLen);
	//printf("data_encrypted %s\r\n",data_encrypted);
		if (iLen < 0)
		{
			return EXIT_FAILURE;
		}


		fwrite(data_encrypted, sizeof(unsigned char), iLen, out);
//fwrite(data_encrypted, sizeof(unsigned char), iLen, out);

	}

	fclose(in);
	fclose(out);

	return 0;

/*
    int rc;
	FILE *in, *out;
	unsigned char buf[PRIKEYLEN] = { 0 };
	char data_encrypted[MAXLEN + 1] = { 0 };
	int rsa_len = 0;
	in = fopen(infile, "rb");
	if (in == NULL)
	{ //add by kobe
		return EXIT_FAILURE;
	}
	out = fopen(outfile, "wb");
	if (out == NULL)
	{ //add by kobe
		fclose(in);
		return EXIT_FAILURE;
	}


    //for arm and x86
    if (local_rsa == NULL) {
        fclose(in);//add by kobe
        fclose(out);
        return EXIT_FAILURE;
    }
    while ((rc = fread(buf, sizeof(unsigned char), PRIKEYLEN, in)) != 0)
    {
        rsa_len = RSA_size(local_rsa);
        if (rc = RSA_private_decrypt(rsa_len, (unsigned char *) buf, (unsigned char*) data_encrypted, local_rsa,
                        RSA_PKCS1_PADDING) < 0)
        {
            fclose(in);//add by kobe
            fclose(out);
            return EXIT_FAILURE;
        }
        fwrite(data_encrypted, sizeof(unsigned char), rc, out);
    }
    fclose(in);
    fclose(out);
    return EXIT_SUCCESS;

//#ifdef __aarch64__
#if (defined __aarch64__ ) || (defined KOBE_NO_DEV_TEST)
    if (local_rsa == NULL) {
        fclose(in);//add by kobe
        fclose(out);
        return EXIT_FAILURE;
    }
    while ((rc = fread(buf, sizeof(unsigned char), PRIKEYLEN, in)) != 0)
    {
        rsa_len = RSA_size(local_rsa);
        if (RSA_private_decrypt(rsa_len, (unsigned char *) buf, (unsigned char*) data_encrypted, local_rsa,
                        RSA_PKCS1_PADDING) < 0)
        {
            fclose(in);//add by kobe
            fclose(out);
            return EXIT_FAILURE;
        }
        fwrite(data_encrypted, sizeof(unsigned char), MAXLEN, out);
    }
#else
    while ((rc = fread(buf, sizeof(unsigned char), PRIKEYLEN, in)) != 0)
    {
        rsa_len = RSA_size(tpm_pkey->pkey.rsa);
        if (RSA_private_decrypt(rsa_len, (unsigned char *) buf, (unsigned char*) data_encrypted, tpm_pkey->pkey.rsa,
        RSA_PKCS1_PADDING) < 0)
        {
            fclose(in);//add by kobe
            fclose(out);
            return EXIT_FAILURE;
        }
        fwrite(data_encrypted, sizeof(unsigned char), MAXLEN, out);
    }
#endif
    fclose(in);
    fclose(out);
    return EXIT_SUCCESS;*/
}

/***********************************************************
 Function:       client_sign_data
 Description:    客户端签名数据
 Calls:
 Called By:
 Input:			 待签名数据
 Output:		 签名后的数据
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
/*int client_sign_data(unsigned char* data, unsigned char *signaturestr)
{
	int outlen = 0;
	BYTE signature[1024] = { 0 };
	int siglen = 1024;
	int rsa_len = 0;

#ifdef __aarch64__
    if (local_rsa == NULL) {
        return 0;
    }
	rsa_len = RSA_size(local_rsa);
	RSA_sign(NID_sha1, data, strlen(data), signature, &outlen, local_rsa);
#else
	rsa_len = RSA_size(tpm_pkey->pkey.rsa);
//	RSA_sign(NID_sha1, data, strlen(data), signature, &outlen, tpm_pkey->pkey.rsa);
	if (RSA_public_encrypt(rsa_len - 11, (unsigned char *) data, (unsigned char*) signature, tpm_pkey->pkey.rsa, RSA_PKCS1_PADDING) < 0)
	{
        return 0;
	}
#endif
	if(signature == NULL)
	{
		printf("RSA_sign failed!");
        return 0;
	}
	memcpy(signaturestr, signature, rsa_len);
	return rsa_len;
}8/

/***********************************************************
 Function:       client_verify_data
 Description:    客户端验签数据
 Calls:
 Called By:
 Input:			 签名数据，眼前数据
 Output:
 Return:         SUCCEED 0；FAIL 1。
 Others:
 ************************************************************/
/*int client_verify_data(unsigned char* data, unsigned char *signaturestr)
{
	int rsa_len = 0;
	BYTE verifyresult[300] = { 0 };
#ifdef __aarch64__
    if (local_rsa == NULL) {
        return FAILED;
    }
	rsa_len = RSA_size(local_rsa);
    int ret = RSA_verify(NID_sha1, (unsigned char*) data, strlen(data), (unsigned char*) signaturestr, rsa_len, local_rsa);
#else
	rsa_len = RSA_size(tpm_pkey->pkey.rsa);
//	ret = RSA_verify(NID_sha1, (unsigned char*) data, strlen(data), (unsigned char*) signaturestr, rsa_len, tpm_pkey->pkey.rsa);
	if (RSA_private_decrypt(rsa_len, (unsigned char *) signaturestr, (unsigned char*) verifyresult, tpm_pkey->pkey.rsa, RSA_PKCS1_PADDING) < 0)
	{
        return FAILED;
	}
#endif
	if (strcmp(data, verifyresult) == 0)
	{
		printf("验证成功\n");
        return SUCCESS;
	} else
	{
		printf("验证错误\n");
        return FAILED;
	}
    return SUCCESS;
}*/

/***********************************************************
 Function:       server_encrypt_data
 Description:    服务端加密数据
 Calls:
 Called By:
 Input:			 待加密数据
 Output:		 加密后的数据
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
int server_encrypt_data(char* data, char *encryptdata, RSA *rsa)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif

	int rsa_len = 0;
	char encryptRSA[2048] = { 0 };
#ifdef __aarch64__
	rsa_len = RSA_size(rsa);
	if (RSA_public_encrypt(rsa_len - 11, (unsigned char *) data, (unsigned char*) encryptRSA, rsa, RSA_PKCS1_PADDING) < 0)
	{
        return 0;
	}
#else
	rsa_len = RSA_size(rsa);
	if (RSA_public_encrypt(rsa_len - 11, (unsigned char *) data, (unsigned char*) encryptRSA, rsa, RSA_PKCS1_PADDING) < 0)
	{
        return 0;
	}
#endif
	memcpy(encryptdata, encryptRSA, rsa_len);
	return rsa_len;
}

/***********************************************************
 Function:       server_decrypt_data
 Description:    服务端解密数据
 Calls:
 Called By:
 Input:			 待解密数据
 Output:		 解密后的数据
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
int server_decrypt_data(char *encryptdata, char* decryptdata, RSA *rsa)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int rsa_len = 0;
	BYTE decryptresult[300] = { 0 };
#ifdef __aarch64__
	rsa_len = RSA_size(rsa);
	if (RSA_private_decrypt(rsa_len, (unsigned char *) encryptdata, (unsigned char*) decryptresult, rsa, RSA_PKCS1_PADDING) < 0)
	{
        return FAILED;
	}
	//	memcpy(decryptdata, decryptresult, strlen(decryptresult));
#else
	rsa_len = RSA_size(rsa);
	if (RSA_private_decrypt(rsa_len, (unsigned char *) encryptdata, (unsigned char*) decryptresult, rsa, RSA_PKCS1_PADDING) < 0)
	{
        return FAILED;
	}
	//	memcpy(decryptdata, decryptresult, strlen(decryptresult));
#endif
	memcpy(decryptdata, decryptresult, rsa_len);
    return SUCCESS;
}

/***********************************************************
 Function:       server_encrypt_long_data
 Description:    客户端加密数据
 Calls:
 Called By:
 Input:			待加密数据
 Output:		加密后的数据
 Return:         加密后长度
 Others:
 ************************************************************/
int server_encrypt_long_data(char *expressData, char *encryptData, RSA *rsa)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int rsa_len = 0;
    rsa_len = RSA_size(rsa);
    int encryptDataLen = 0;

    char *org_data = (char*) malloc(MAXLEN + 1); //一次只能加密server_key_len - 11
    if (org_data == NULL)
    {
        return FAILED;
    }
    char *en_data = (char*) malloc(rsa_len); //一次只能解密server_key_len
    if (en_data == NULL)
    {
        if (NULL != org_data)
        {
            free(org_data);
            org_data = NULL;
        }
        return FAILED;
    }

    int idlen = strlen(expressData);
    char *old_p = expressData;
    char *en_p = encryptData;
    while (idlen > 0)
    {
        memset(org_data, '\0', MAXLEN + 1);
        memset(en_data, '\0', rsa_len);
        memcpy(org_data, old_p, (MAXLEN));
        if (RSA_public_encrypt(rsa_len - 11, (unsigned char *) org_data, (unsigned char*) en_data, rsa,
        RSA_PKCS1_PADDING) < 0)
        {
            if (NULL != org_data)
            {
                free(org_data);
                org_data = NULL;
            }
            if (NULL != en_data)
            {
                free(en_data);
                en_data = NULL;
            }
            return FAILED;
        }
        memcpy(en_p, en_data, rsa_len);
        encryptDataLen += rsa_len;
        idlen = idlen - MAXLEN;
        old_p = old_p + MAXLEN;
        en_p = en_p + rsa_len;
    }

    //add by kobe
    if (NULL != org_data) {
        free(org_data);
        org_data = NULL;
    }
    if (NULL != en_data){
        free(en_data);
        en_data = NULL;
    }
    return encryptDataLen;
}

/***********************************************************
 Function:       server_decrypt_long_data
 Description:    服务端解密数据
 Calls:
 Called By:
 Input:			待解密数据
 Output:		解密后的数据
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
int server_decrypt_long_data(char *encryptData, int encryptDataLen, char *decryptData, RSA *rsa)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int rsa_len = 0;
    rsa_len = RSA_size(rsa);

    char *org_data = (char*) malloc(rsa_len); //一次只能加密server_key_len - 11
    if (org_data == NULL)
    {
        return FAILED;
    }
    char *de_data = (char*) malloc(MAXLEN + 1); //一次只能解密server_key_len
    if (de_data == NULL)
    {
        if (NULL != org_data)
        {
            free(org_data);
            org_data = NULL;
        }
        return FAILED;
    }

    char *old_p = encryptData;
//	char *de_p = decryptData;
    while (encryptDataLen > 0)
    {
        memset(org_data, '\0', rsa_len);
        memset(de_data, '\0', MAXLEN + 1);
        memcpy(org_data, old_p, rsa_len);
        if (RSA_private_decrypt(rsa_len, (unsigned char *) org_data, (unsigned char*) de_data, rsa,
        RSA_PKCS1_PADDING) < 0)
        {
            if (NULL != org_data){
                free(org_data);
                org_data = NULL;
            }
            if (NULL != de_data) {
                free(de_data);
                de_data = NULL;
            }
            return FAILED;
        }
        strcat(decryptData, de_data);
        encryptDataLen = encryptDataLen - rsa_len;
        old_p = old_p + rsa_len;
    }

    //add by kobe
    if (NULL != org_data){
        free(org_data);
        org_data = NULL;
    }
    if (NULL != de_data) {
        free(de_data);
        de_data = NULL;
    }
    return SUCCESS;
}

/***********************************************************
 Function:       server_encrypt_file
 Description:    服务端加密文件
 Calls:
 Called By:
 Input:			 待加密文件名，加密后文件名
 Output:
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
int server_encrypt_file(char *infile, char *outfile, RSA *rsa)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif

    int rc;
    FILE *in, *out;
    unsigned char buf[MAXLEN];
    unsigned char data_decrypted[PRIKEYLEN] = { 0 };
    char data_encrypted[256] = { 0 };
    int rsa_len = 0;
    in = fopen(infile, "rb");
    if (in == NULL) {//add by kobe
        return EXIT_FAILURE;
    }
    out = fopen(outfile, "wb");
    if (out == NULL) {//add by kobe
        fclose(in);
        return EXIT_FAILURE;
    }

    while ((rc = fread(buf, sizeof(unsigned char), MAXLEN, in)) != 0)
    {
        rsa_len = RSA_size(rsa);
        if (RSA_public_encrypt(rc , (unsigned char *) buf, (unsigned char*) data_encrypted, rsa,
        RSA_PKCS1_PADDING) < 0) {
            //add by kobe
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }
        fwrite(data_encrypted, sizeof(unsigned char), PRIKEYLEN, out);

    }

    fclose(in);
    fclose(out);

    return EXIT_SUCCESS;
}

/***********************************************************
 Function:       server_decrypt_file
 Description:    服务端解密文件
 Calls:
 Called By:
 Input:			 待解密文件名，解密后文件名
 Output:
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
int server_decrypt_file(char *infile, char *outfile, RSA *rsa)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int rc;
    FILE *in, *out;
    unsigned char buf[MAXLEN] = { 0 };
    char data_encrypted[PRIKEYLEN] = { 0 };
    int rsa_len = 0;
    in = fopen(infile, "rb");
    if (in == NULL) {//add by kobe
        return EXIT_FAILURE;
    }
    out = fopen(outfile, "wb");
    if (out == NULL) {//add by kobe
        fclose(in);
        return EXIT_FAILURE;
    }

    while ((rc = fread(buf, sizeof(unsigned char), PRIKEYLEN, in)) != 0)
    {
        rsa_len = RSA_size(rsa);
        if (RSA_private_decrypt(rsa_len, (unsigned char *) buf, (unsigned char*) data_encrypted, rsa,
        RSA_PKCS1_PADDING) < 0)
        {
            //add by kobe
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }
        fwrite(data_encrypted, sizeof(unsigned char), MAXLEN, out);

    }

    fclose(in);
    fclose(out);
    return EXIT_SUCCESS;
}

/***********************************************************
 Function:       server_sign_data
 Description:    服务端签名数据
 Calls:
 Called By:
 Input:			 待签名数据
 Output:		 签名后的数据
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
int server_sign_data(unsigned char* data, unsigned char *signaturestr, RSA *rsa)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int outlen = 0;
	BYTE signature[1024] = { 0 };
	int siglen = 1024;
	int rsa_len = 0;
	rsa_len = RSA_size(rsa);

#ifdef __aarch64__
	RSA_sign(NID_sha1, data, strlen(data), signature, &outlen, rsa);
	if (signature == NULL)
	{
		printf("RSA_sign failed!");
        return 0;
	}
#else
	RSA_sign(NID_sha1, data, strlen(data), signature, &outlen, rsa);
	if (signature == NULL)
	{
		printf("RSA_sign failed!");
        return 0;
	}
#endif
	memcpy(signaturestr, signature, rsa_len);
	return rsa_len;
}

/***********************************************************
 Function:       server_verify_data
 Description:    服务端验签数据
 Calls:
 Called By:
 Input:			 签名数据，眼前数据
 Output:
 Return:         SUCCEED 0；FAIL 1。
 Others:
 ************************************************************/
int server_verify_data(unsigned char* data, unsigned char *signaturestr, RSA *rsa)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int ret = -1;
	int rsa_len = 0;
	rsa_len = RSA_size(rsa);
#ifdef __aarch64__
	ret = RSA_verify(NID_sha1, (unsigned char*) data, strlen(data), (unsigned char*) signaturestr, rsa_len, rsa);
#else
	ret = RSA_verify(NID_sha1, (unsigned char*) data, strlen(data), (unsigned char*) signaturestr, rsa_len, rsa);
#endif
	if (ret == 1)
	{
		printf("验证成功\n");
        return SUCCESS;
	} else
	{
		printf("验证错误\n");
        return FAILED;
	}
    return SUCCESS;
}

/***********************************************************
 Function:       client_encrypt_long_data
 Description:    客户端加密数据
 Calls:
 Called By:
 Input:			待加密数据
 Output:		加密后的数据
 Return:         加密后长度
 Others:
 ************************************************************/
/*int client_encrypt_long_data(char *expressData, char *encryptData)
{
#ifdef __aarch64__
    int rsa_len = 0;
    rsa_len = RSA_size(local_rsa);
    int encryptDataLen = 0;

    char *org_data = (char*) malloc(MAXLEN + 1); //一次只能加密server_key_len - 11
    if (org_data == NULL)
    {
        return FAILED;
    }
    char *en_data = (char*) malloc(rsa_len); //一次只能解密server_key_len
    if (en_data == NULL)
    {
        if (NULL != org_data)
        {
            free(org_data);
            org_data = NULL;
        }
        return FAILED;
    }

    int idlen = strlen(expressData);
    char *old_p = expressData;
    char *en_p = encryptData;
    while (idlen > 0)
    {
        memset(org_data, '\0', MAXLEN + 1);
        memset(en_data, '\0', rsa_len);
        memcpy(org_data, old_p, (MAXLEN));
        if (RSA_public_encrypt(rsa_len - 11, (unsigned char *) org_data, (unsigned char*) en_data, local_rsa,
        RSA_PKCS1_PADDING) < 0)
        {
            if (NULL != org_data) {
                free(org_data);
                org_data = NULL;
            }
            if (NULL != en_data) {
                free(en_data);
                en_data = NULL;
            }
            return FAILED;
        }
        memcpy(en_p, en_data, rsa_len);
        encryptDataLen += rsa_len;
        idlen = idlen - MAXLEN;
        old_p = old_p + MAXLEN;
        en_p = en_p + rsa_len;
    }
    //add by kobe
    if (NULL != org_data) {
        free(org_data);
        org_data = NULL;
    }
    if (NULL != en_data) {
        free(en_data);
        en_data = NULL;
    }
#else
    int rsa_len = 0;
    rsa_len = RSA_size(tpm_pkey->pkey.rsa);
    int encryptDataLen = 0;

    char *org_data = (char*) malloc(MAXLEN + 1); //一次只能加密server_key_len - 11
    if (org_data == NULL)
    {
        return FAILED;
    }
    char *en_data = (char*) malloc(rsa_len); //一次只能解密server_key_len
    if (en_data == NULL)
    {
        if (NULL != org_data)
        {
            free(org_data);
            org_data = NULL;
        }
        return FAILED;
    }

    int idlen = strlen(expressData);
    char *old_p = expressData;
    char *en_p = encryptData;
    while (idlen > 0)
    {
        memset(org_data, '\0', MAXLEN + 1);
        memset(en_data, '\0', rsa_len);
        memcpy(org_data, old_p, (MAXLEN));
        if (RSA_public_encrypt(rsa_len - 11, (unsigned char *) org_data, (unsigned char*) en_data, tpm_pkey->pkey.rsa,
        RSA_PKCS1_PADDING) < 0)
        {
            if (NULL != org_data) {
                free(org_data);
                org_data = NULL;
            }
            if (NULL != en_data) {
                free(en_data);
                en_data = NULL;
            }
            return FAILED;
        }
        memcpy(en_p, en_data, rsa_len);
        encryptDataLen += rsa_len;
        idlen = idlen - MAXLEN;
        old_p = old_p + MAXLEN;
        en_p = en_p + rsa_len;
    }
    //add by kobe
    if (NULL != org_data) {
        free(org_data);
        org_data = NULL;
    }
    if (NULL != en_data) {
        free(en_data);
        en_data = NULL;
    }
#endif
    return encryptDataLen;
}*/

/***********************************************************
 Function:       client_decrypt_long_data
 Description:    客户端解密数据
 Calls:
 Called By:
 Input:			待解密数据
 Output:		解密后的数据
 Return:         SUCCEED 0；FAIL OTHER。
 Others:
 ************************************************************/
int client_decrypt_long_data(char *encryptData, int encryptDataLen, char *decryptData)
{
    int rsa_len = 0;

    //for arm and x86
    if (local_rsa == NULL) {
        return FAILED;
    }

    rsa_len = RSA_size(local_rsa);

    char *org_data = (char*) malloc(rsa_len); //一次只能加密server_key_len - 11
    if (org_data == NULL)
    {
        return FAILED;
    }
    char *de_data = (char*) malloc(MAXLEN + 1); //一次只能解密server_key_len
    if (de_data == NULL)
    {
        if (NULL != org_data)
        {
            free(org_data);
            org_data = NULL;
        }
        return FAILED;
    }

    char *old_p = encryptData;
    while (encryptDataLen > 0)
    {
        memset(org_data, '\0', rsa_len);
        memset(de_data, '\0', MAXLEN + 1);
        memcpy(org_data, old_p, rsa_len);
        if (RSA_private_decrypt(rsa_len, (unsigned char *) org_data, (unsigned char*) de_data, local_rsa,
        RSA_PKCS1_PADDING) < 0)
        {
            if (NULL != org_data) {
                free(org_data);
                org_data = NULL;
            }
            if (NULL != de_data) {
                free(de_data);
                de_data = NULL;
            }
	    ccis_log_info("RSA_private_decrypt failed");
	    unsigned long ulErr = ERR_get_error(); // 获取错误号
	    char szErrMsg[1024] = {0};
	    char *pTmp = NULL;
	    pTmp = ERR_error_string(ulErr,szErrMsg); // 格式：error:errId:库:函数:原因
	    ccis_log_info("errno %d,szErrMsg %s,pTmp %s\n",ulErr,szErrMsg,pTmp);
            return FAILED;
        }
        strcat(decryptData, de_data);
        encryptDataLen = encryptDataLen - rsa_len;
        old_p = old_p + rsa_len;
    }

    //add by kobe
    if (NULL != org_data) {
        free(org_data);
        org_data = NULL;
    }
    if (NULL != de_data) {
        free(de_data);
        de_data = NULL;
    }
    return SUCCESS;
/*
//#ifdef __aarch64__
#if (defined __aarch64__ ) || (defined KOBE_NO_DEV_TEST)
    if (local_rsa == NULL) {
        return FAILED;
    }

    rsa_len = RSA_size(local_rsa);

    char *org_data = (char*) malloc(rsa_len); //一次只能加密server_key_len - 11
    if (org_data == NULL)
    {
        return FAILED;
    }
    char *de_data = (char*) malloc(MAXLEN + 1); //一次只能解密server_key_len
    if (de_data == NULL)
    {
        if (NULL != org_data)
        {
            free(org_data);
            org_data = NULL;
        }
        return FAILED;
    }

    char *old_p = encryptData;
    while (encryptDataLen > 0)
    {
        memset(org_data, '\0', rsa_len);
        memset(de_data, '\0', MAXLEN + 1);
        memcpy(org_data, old_p, rsa_len);
        if (RSA_private_decrypt(rsa_len, (unsigned char *) org_data, (unsigned char*) de_data, local_rsa,
        RSA_PKCS1_PADDING) < 0)
        {
            if (NULL != org_data) {
                free(org_data);
                org_data = NULL;
            }
            if (NULL != de_data) {
                free(de_data);
                de_data = NULL;
            }
            return FAILED;
        }
        strcat(decryptData, de_data);
        encryptDataLen = encryptDataLen - rsa_len;
        old_p = old_p + rsa_len;
    }

    //add by kobe
    if (NULL != org_data) {
        free(org_data);
        org_data = NULL;
    }
    if (NULL != de_data) {
        free(de_data);
        de_data = NULL;
    }
#else
    rsa_len = RSA_size(tpm_pkey->pkey.rsa);
    char *org_data = (char*) malloc(rsa_len); //一次只能加密server_key_len - 11
    if (org_data == NULL)
    {
        return FAILED;
    }
    char *de_data = (char*) malloc(MAXLEN + 1); //一次只能解密server_key_len
    if (de_data == NULL)
    {
        if (NULL != org_data)
        {
            free(org_data);
            org_data = NULL;
        }
        return FAILED;
    }

    char *old_p = encryptData;
    //	char *de_p = decryptData;
    while (encryptDataLen > 0)
    {
        memset(org_data, '\0', rsa_len);
        memset(de_data, '\0', MAXLEN + 1);
        memcpy(org_data, old_p, rsa_len);
        if (RSA_private_decrypt(rsa_len, (unsigned char *) org_data, (unsigned char*) de_data, tpm_pkey->pkey.rsa,
                        RSA_PKCS1_PADDING) < 0)
        {
            if (NULL != org_data)
            {
                free(org_data);
                org_data = NULL;
            }
            if (NULL != de_data)
            {
                free(de_data);
                de_data = NULL;
            }
            return FAILED;
        }
        strcat(decryptData, de_data);
        encryptDataLen = encryptDataLen - rsa_len;
        old_p = old_p + rsa_len;
    }
#endif
    return SUCCESS;*/
}

int loadpriv(SSL_CTX* ctx, const char* file)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int ret = 0;

    //for arm and x86
    ret = SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM);
    if (ret <= 0) {
        return FAILED;
    }
    else
        return SUCCESS;
/*
//#ifdef __aarch64__
#if (defined __aarch64__ ) || (defined KOBE_NO_DEV_TEST)
    ret = SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM);
    if (ret <= 0) {
        return FAILED;
    }
    else
        return SUCCESS;
#else
    ENGINE_load_builtin_engines();
    ENGINE* engine = ENGINE_by_id("tpm");
    ENGINE_init(engine);
    UI_METHOD* ui_method = UI_OpenSSL();
    EVP_PKEY* pkey = ENGINE_load_private_key(engine, file, ui_method, NULL);
    SSL_CTX_use_PrivateKey(ctx, pkey);
#endif*/
    return ret;
}

/***********************************************************
 Function:       get_cert_serial
 Description:    获取证书序列号
 Calls:
 Called By:
 Input:			证书路径
 Output:		证书序列号
 Return:         SUCCEED 0；FAIL 1。
 Others:
 ************************************************************/
int get_cert_serial(char *certpath, char *certserial)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif

	BIO *bio = NULL;
	X509 *x = NULL;
	EVP_PKEY *mytestpkey = EVP_PKEY_new();
	if ((bio = BIO_new_file(certpath, "r")) == NULL)
	{
		BIO_free_all(bio);
		EVP_PKEY_free(mytestpkey);
		return FAILED;
	}
	if ((x = PEM_read_bio_X509(bio, NULL, 0, NULL)) == NULL)
	{
		BIO_free_all(bio);
		EVP_PKEY_free(mytestpkey);
		return FAILED;
	}

	ASN1_INTEGER *serial = X509_get_serialNumber(x);
	BIGNUM *bnser = ASN1_INTEGER_to_BN(serial, NULL);
	char *asciiHex = BN_bn2hex(bnser);
	strcpy(certserial, asciiHex);
	ASN1_INTEGER_free(serial);
	BN_free(bnser);

    return SUCCESS;
}
//IMPLEMENT_DYNAMIC_CHECK_FN()
//IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
//#endif
//#endif
