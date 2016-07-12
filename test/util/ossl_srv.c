/*------------------------------------------------------------------
 * ossl_srv.c - Interface between EST server and OpenSSL for 
 *              EST server operations.  This code was taken from
 *              OpenSSL /apps directory and modified to work
 *              with the EST stack.  It's used with Mongoose
 *              for SSL support. Essentially, this is a very 
 *              lightweight CA server based on OpenSSL. 
 *
 * November, 2012
 *
 * Copyright (c) 2012, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* This was written by Gordon Chaffee <chaffee@plateau.cs.berkeley.edu>
 * and donated 'to the cause' along with lots and lots of other fixes to
 * the library. */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/lhash.h>
#include <openssl/ui.h>
#include <openssl/bio.h>
#include "apps.h"  //taken from openssl/apps/apps.h

extern BIO *bio_err;
BIO *cacerts = NULL;
static int msie_hack=0;
static int preserve=0;
static CONF *conf=NULL;
static CONF *extconf=NULL;
static char *section=NULL;

static BIO * ossl_get_certs_pkcs7(BIO *in);

#define REV_NONE		0
#define BASE_SECTION	"ca"
#define CONFIG_FILE "openssl.cnf"

#define ENV_DEFAULT_CA		"default_ca"

#define STRING_MASK	"string_mask"
#define UTF8_IN			"utf8"

#define ENV_DIR			"dir"
#define ENV_CERTS		"certs"
#define ENV_CRL_DIR		"crl_dir"
#define ENV_CA_DB		"CA_DB"
#define ENV_NEW_CERTS_DIR	"new_certs_dir"
#define ENV_CERTIFICATE 	"certificate"
#define ENV_SERIAL		"serial"
#define ENV_CRLNUMBER		"crlnumber"
#define ENV_CRL			"crl"
#define ENV_PRIVATE_KEY		"private_key"
#define ENV_RANDFILE		"RANDFILE"
#define ENV_DEFAULT_DAYS 	"default_days"
#define ENV_DEFAULT_STARTDATE 	"default_startdate"
#define ENV_DEFAULT_ENDDATE 	"default_enddate"
#define ENV_DEFAULT_CRL_DAYS 	"default_crl_days"
#define ENV_DEFAULT_CRL_HOURS 	"default_crl_hours"
#define ENV_DEFAULT_MD		"default_md"
#define ENV_DEFAULT_EMAIL_DN	"email_in_dn"
#define ENV_PRESERVE		"preserve"
#define ENV_POLICY      	"policy"
#define ENV_EXTENSIONS      	"x509_extensions"
#define ENV_CRLEXT      	"crl_extensions"
#define ENV_MSIE_HACK		"msie_hack"
#define ENV_NAMEOPT		"name_opt"
#define ENV_CERTOPT		"cert_opt"
#define ENV_EXTCOPY		"copy_extensions"
#define ENV_UNIQUE_SUBJECT	"unique_subject"

#define ENV_DATABASE		"database"
#define BSIZE 256

int parse_yesno(const char *str, int def);
int rand_serial(BIGNUM *b, ASN1_INTEGER *ai);

typedef struct {
	const char *name;
	unsigned long flag;
	unsigned long mask;
} NAME_EX_TBL;

static UI_METHOD *ui_method = NULL;

#if defined(_WIN32) || defined(_WIN64) 
#define strcasecmp _stricmp 
#endif

/*****************************************************************************************
 * simple enrollment processing logic from this point
 *****************************************************************************************/

int pkey_ctrl_string(EVP_PKEY_CTX *ctx, char *value)
{
	int rv;
	char *stmp, *vtmp = NULL;
	stmp = BUF_strdup(value);
	if (!stmp)
		return -1;
	vtmp = strchr(stmp, ':');
	if (vtmp)
		{
		*vtmp = 0;
		vtmp++;
		}
	rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
	OPENSSL_free(stmp);
	return rv;
}

int add_oid_section(BIO *err, CONF *conf)
{	
	char *p;
	STACK_OF(CONF_VALUE) *sktmp;
	CONF_VALUE *cnf;
	int i;
	if(!(p=NCONF_get_string(conf,NULL,"oid_section")))
		{
		ERR_clear_error();
		return 1;
		}
	if(!(sktmp = NCONF_get_section(conf, p))) {
		BIO_printf(err, "problem loading oid section %s\n", p);
		return 0;
	}
	for(i = 0; i < sk_CONF_VALUE_num(sktmp); i++) {
		cnf = sk_CONF_VALUE_value(sktmp, i);
		if(OBJ_create(cnf->value, cnf->name, cnf->name) == NID_undef) {
			BIO_printf(err, "problem creating object %s=%s\n",
							 cnf->name, cnf->value);
			return 0;
		}
	}
	return 1;
}


static int load_pkcs12(BIO *err, BIO *in, const char *desc,
		pem_password_cb *pem_cb,  void *cb_data,
		EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
 	const char *pass;
	char tpass[PEM_BUFSIZE];
	int len, ret = 0;
	PKCS12 *p12;
	p12 = d2i_PKCS12_bio(in, NULL);
	if (p12 == NULL)
		{
		BIO_printf(err, "Error loading PKCS12 file for %s\n", desc);	
		goto die;
		}
	/* See if an empty password will do */
	if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0))
		pass = "";
	else
		{
		if (!pem_cb)
			pem_cb = (pem_password_cb *)password_callback;
		len = pem_cb(tpass, PEM_BUFSIZE, 0, cb_data);
		if (len < 0) 
			{
			BIO_printf(err, "Passpharse callback error for %s\n",
					desc);
			goto die;
			}
		if (len < PEM_BUFSIZE)
			tpass[len] = 0;
		if (!PKCS12_verify_mac(p12, tpass, len))
			{
			BIO_printf(err,
	"Mac verify error (wrong password?) in PKCS12 file for %s\n", desc);	
			goto die;
			}
		pass = tpass;
		}
	ret = PKCS12_parse(p12, pass, pkey, cert, ca);
	die:
	if (p12)
		PKCS12_free(p12);
	return ret;
}



X509 *load_cert(BIO *err, const char *file, int format,
	const char *pass, ENGINE *e, const char *cert_descrip)
{
	X509 *x=NULL;
	BIO *cert;

	if ((cert=BIO_new(BIO_s_file())) == NULL)
		{
		ERR_print_errors(err);
		goto end;
		}

	if (file == NULL)
		{
#ifdef _IONBF
# ifndef OPENSSL_NO_SETVBUF_IONBF
		setvbuf(stdin, NULL, _IONBF, 0);
# endif /* ndef OPENSSL_NO_SETVBUF_IONBF */
#endif
		BIO_set_fp(cert,stdin,BIO_NOCLOSE);
		}
	else
		{
		if (BIO_read_filename(cert,file) <= 0)
			{
			BIO_printf(err, "Error opening %s %s\n",
				cert_descrip, file);
			ERR_print_errors(err);
			goto end;
			}
		}

	if 	(format == FORMAT_ASN1)
		x=d2i_X509_bio(cert,NULL);
	else if (format == FORMAT_NETSCAPE)
		{
		NETSCAPE_X509 *nx;
		nx=ASN1_item_d2i_bio(ASN1_ITEM_rptr(NETSCAPE_X509),cert,NULL);
		if (nx == NULL)
				goto end;

		if ((strncmp(NETSCAPE_CERT_HDR,(char *)nx->header->data,
			nx->header->length) != 0))
			{
			NETSCAPE_X509_free(nx);
			BIO_printf(err,"Error reading header on certificate\n");
			goto end;
			}
		x=nx->cert;
		nx->cert = NULL;
		NETSCAPE_X509_free(nx);
		}
	else if (format == FORMAT_PEM)
		x=PEM_read_bio_X509_AUX(cert,NULL,
			(pem_password_cb *)password_callback, NULL);
	else if (format == FORMAT_PKCS12)
		{
		if (!load_pkcs12(err, cert,cert_descrip, NULL, NULL,
					NULL, &x, NULL))
			goto end;
		}
	else	{
		BIO_printf(err,"bad input format specified for %s\n",
			cert_descrip);
		goto end;
		}
end:
	if (x == NULL)
		{
		BIO_printf(err,"unable to load certificate\n");
		ERR_print_errors(err);
		}
	if (cert != NULL) BIO_free(cert);
	return(x);
}

EVP_PKEY *load_key(BIO *err, const char *file, int format, int maybe_stdin,
	const char *pass, ENGINE *e, const char *key_descrip)
{
	BIO *key=NULL;
	EVP_PKEY *pkey=NULL;
	PW_CB_DATA cb_data;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	if (file == NULL && (!maybe_stdin || format == FORMAT_ENGINE))
		{
		BIO_printf(err,"no keyfile specified\n");
		goto end;
		}
	if (format == FORMAT_ENGINE)
		{
		if (!e)
			BIO_printf(err,"no engine specified\n");
		else
			{
			pkey = (EVP_PKEY *)ENGINE_load_private_key(e, file,
				ui_method, &cb_data);
			if (!pkey) 
				{
				BIO_printf(err,"cannot load %s from engine\n",key_descrip);
				ERR_print_errors(err);
				}	
			}
		goto end;
		}
	key=BIO_new(BIO_s_file());
	if (key == NULL)
		{
		ERR_print_errors(err);
		goto end;
		}
	if (file == NULL && maybe_stdin)
		{
#ifdef _IONBF
# ifndef OPENSSL_NO_SETVBUF_IONBF
		setvbuf(stdin, NULL, _IONBF, 0);
# endif /* ndef OPENSSL_NO_SETVBUF_IONBF */
#endif
		BIO_set_fp(key,stdin,BIO_NOCLOSE);
		}
	else
		if (BIO_read_filename(key,file) <= 0)
			{
			BIO_printf(err, "Error opening %s %s\n",
				key_descrip, file);
			ERR_print_errors(err);
			goto end;
			}
	if (format == FORMAT_ASN1)
		{
		pkey=d2i_PrivateKey_bio(key, NULL);
		}
	else if (format == FORMAT_PEM)
		{
		pkey=PEM_read_bio_PrivateKey(key,NULL,
			(pem_password_cb *)password_callback, &cb_data);
		}
#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
//	else if (format == FORMAT_NETSCAPE || format == FORMAT_IISSGC)
//		pkey = load_netscape_key(err, key, file, key_descrip, format);
#endif
	else if (format == FORMAT_PKCS12)
		{
		if (!load_pkcs12(err, key, key_descrip,
				(pem_password_cb *)password_callback, &cb_data,
				&pkey, NULL, NULL))
			goto end;
		}
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DSA) && !defined (OPENSSL_NO_RC4)
	else if (format == FORMAT_MSBLOB)
		pkey = b2i_PrivateKey_bio(key);
	else if (format == FORMAT_PVK)
		pkey = b2i_PVK_bio(key, (pem_password_cb *)password_callback,
								&cb_data);
#endif
	else
		{
		BIO_printf(err,"bad input format specified for key file\n");
		goto end;
		}
 end:
	if (key != NULL) BIO_free(key);
	if (pkey == NULL) 
		{
		BIO_printf(err,"unable to load %s\n", key_descrip);
		ERR_print_errors(err);
		}	
	return(pkey);
}



int load_config(BIO *err, CONF *cnf)
{
	static int load_config_called = 0;
	if (load_config_called)
		return 1;
	load_config_called = 1;
	if (!cnf)
		return 1;

	OPENSSL_load_builtin_modules();

	if (CONF_modules_load(cnf, NULL, 0) <= 0)
		{
		BIO_printf(err, "Error configuring OpenSSL\n");
		ERR_print_errors(err);
		return 0;
		}
	return 1;
}

BIGNUM *load_serial(char *serialfile, int create, ASN1_INTEGER **retai)
{
	BIO *in=NULL;
	BIGNUM *ret=NULL;
	static char buf[1024];
	ASN1_INTEGER *ai=NULL;

	ai=ASN1_INTEGER_new();
	if (ai == NULL) goto err;

	if ((in=BIO_new(BIO_s_file())) == NULL)
		{
		ERR_print_errors(bio_err);
		goto err;
		}

	if (BIO_read_filename(in,serialfile) <= 0)
		{
		if (!create)
			{
			perror(serialfile);
			goto err;
			}
		else
			{
			ret=BN_new();
			if (ret == NULL || !rand_serial(ret, ai))
				BIO_printf(bio_err, "Out of memory\n");
			}
		}
	else
		{
		if (!a2i_ASN1_INTEGER(in,ai,buf,1024))
			{
			BIO_printf(bio_err,"unable to load number from %s\n",
				serialfile);
			goto err;
			}
		ret=ASN1_INTEGER_to_BN(ai,NULL);
		if (ret == NULL)
			{
			BIO_printf(bio_err,"error converting number from bin to BIGNUM\n");
			goto err;
			}
		}

	if (ret && retai)
		{
		*retai = ai;
		ai = NULL;
		}
 err:
	if (in != NULL) BIO_free(in);
	if (ai != NULL) ASN1_INTEGER_free(ai);
	return(ret);
}

int save_serial(char *serialfile, char *suffix, BIGNUM *serial, ASN1_INTEGER **retai)
{
	char buf[1][BSIZE];
	BIO *out = NULL;
	int ret=0;
	ASN1_INTEGER *ai=NULL;
	int j;

	if (suffix == NULL)
		j = strlen(serialfile);
	else
		j = strlen(serialfile) + strlen(suffix) + 1;
	if (j >= BSIZE)
		{
		BIO_printf(bio_err,"file name too long\n");
		goto err;
		}

	if (suffix == NULL)
		BUF_strlcpy(buf[0], serialfile, BSIZE);
	else
		{
		j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s", serialfile, suffix);
		}
	BIO_printf(bio_err, "DEBUG: writing \"%s\"\n", buf[0]);
	out=BIO_new(BIO_s_file());
	if (out == NULL)
		{
		ERR_print_errors(bio_err);
		goto err;
		}
	if (BIO_write_filename(out,buf[0]) <= 0)
		{
		perror(serialfile);
		goto err;
		}

	if ((ai=BN_to_ASN1_INTEGER(serial,NULL)) == NULL)
		{
		BIO_printf(bio_err,"error converting serial to ASN.1 format\n");
		goto err;
		}
	i2a_ASN1_INTEGER(out,ai);
	BIO_puts(out,"\n");
	ret=1;
	if (retai)
		{
		*retai = ai;
		ai = NULL;
		}
err:
	if (out != NULL) BIO_free_all(out);
	if (ai != NULL) ASN1_INTEGER_free(ai);
	return(ret);
}

int rotate_serial(char *serialfile, char *new_suffix, char *old_suffix)
{
	char buf[5][BSIZE];
	int i,j;

	i = strlen(serialfile) + strlen(old_suffix);
	j = strlen(serialfile) + strlen(new_suffix);
	if (i > j) j = i;
	if (j + 1 >= BSIZE)
		{
		BIO_printf(bio_err,"file name too long\n");
		goto err;
		}

	j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s",
		serialfile, new_suffix);
	j = BIO_snprintf(buf[1], sizeof buf[1], "%s.%s",
		serialfile, old_suffix);
	BIO_printf(bio_err, "DEBUG: renaming \"%s\" to \"%s\"\n",
		serialfile, buf[1]);
#ifndef WIN32
	if (rename(serialfile,buf[1]) < 0 && errno != ENOENT
#ifdef ENOTDIR
			&& errno != ENOTDIR
#endif
	   )		{
			BIO_printf(bio_err,
				"unable to rename %s to %s\n",
				serialfile, buf[1]);
			perror("reason");
			goto err;
			}
#endif 
	BIO_printf(bio_err, "DEBUG: renaming \"%s\" to \"%s\"\n",
		buf[0],serialfile);
#ifdef WIN32
    remove(serialfile);
#endif 
	if (rename(buf[0],serialfile) < 0)
		{
		BIO_printf(bio_err,
			"unable to rename %s to %s\n",
			buf[0],serialfile);
		perror("reason");
		rename(buf[1],serialfile);
		goto err;
		}
	return 1;
 err:
	return 0;
}

int copy_extensions(X509 *x, X509_REQ *req, int copy_type)
{
	STACK_OF(X509_EXTENSION) *exts = NULL;
	X509_EXTENSION *ext, *tmpext;
	ASN1_OBJECT *obj;
	int i, idx, ret = 0;
	if (!x || !req || (copy_type == EXT_COPY_NONE))
		return 1;
	exts = X509_REQ_get_extensions(req);

	for(i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
		ext = sk_X509_EXTENSION_value(exts, i);
		obj = X509_EXTENSION_get_object(ext);
		idx = X509_get_ext_by_OBJ(x, obj, -1);
		/* Does extension exist? */
		if (idx != -1) {
			/* If normal copy don't override existing extension */
			if (copy_type == EXT_COPY_ADD)
				continue;
			/* Delete all extensions of same type */
			do {
				tmpext = X509_get_ext(x, idx);
				X509_delete_ext(x, idx);
				X509_EXTENSION_free(tmpext);
				idx = X509_get_ext_by_OBJ(x, obj, -1);
			} while (idx != -1);
		}
		if (!X509_add_ext(x, ext, -1))
			goto end;
	}

	ret = 1;

	end:

	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	return ret;
}
		
		


static int set_table_opts(unsigned long *flags, const char *arg, const NAME_EX_TBL *in_tbl)
{
	char c;
	const NAME_EX_TBL *ptbl;
	c = arg[0];

	if(c == '-') {
		c = 0;
		arg++;
	} else if (c == '+') {
		c = 1;
		arg++;
	} else c = 1;

	for(ptbl = in_tbl; ptbl->name; ptbl++) {
		if(!strcasecmp(arg, ptbl->name)) {
			*flags &= ~ptbl->mask;
			if(c) *flags |= ptbl->flag;
			else *flags &= ~ptbl->flag;
			return 1;
		}
	}
	return 0;
}
static int set_multi_opts(unsigned long *flags, const char *arg, const NAME_EX_TBL *in_tbl)
{
	STACK_OF(CONF_VALUE) *vals;
	CONF_VALUE *val;
	int i, ret = 1;
	if(!arg) return 0;
	vals = X509V3_parse_list(arg);
	for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
		val = sk_CONF_VALUE_value(vals, i);
		if (!set_table_opts(flags, val->name, in_tbl))
			ret = 0;
	}
	sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
	return ret;
}



#define X509V3_EXT_UNKNOWN_MASK		(0xfL << 16)
/* Return error for unknown extensions */
#define X509V3_EXT_DEFAULT		0
/* Print error for unknown extensions */
#define X509V3_EXT_ERROR_UNKNOWN	(1L << 16)
/* ASN1 parse unknown extensions */
#define X509V3_EXT_PARSE_UNKNOWN	(2L << 16)
/* BIO_dump unknown extensions */
#define X509V3_EXT_DUMP_UNKNOWN		(3L << 16)

#define X509_FLAG_CA (X509_FLAG_NO_ISSUER | X509_FLAG_NO_PUBKEY | \
			 X509_FLAG_NO_HEADER | X509_FLAG_NO_VERSION)

int set_cert_ex(unsigned long *flags, const char *arg)
{
	static const NAME_EX_TBL cert_tbl[] = {
		{ "compatible", X509_FLAG_COMPAT, 0xffffffffl},
		{ "ca_default", X509_FLAG_CA, 0xffffffffl},
		{ "no_header", X509_FLAG_NO_HEADER, 0},
		{ "no_version", X509_FLAG_NO_VERSION, 0},
		{ "no_serial", X509_FLAG_NO_SERIAL, 0},
		{ "no_signame", X509_FLAG_NO_SIGNAME, 0},
		{ "no_validity", X509_FLAG_NO_VALIDITY, 0},
		{ "no_subject", X509_FLAG_NO_SUBJECT, 0},
		{ "no_issuer", X509_FLAG_NO_ISSUER, 0},
		{ "no_pubkey", X509_FLAG_NO_PUBKEY, 0},
		{ "no_extensions", X509_FLAG_NO_EXTENSIONS, 0},
		{ "no_sigdump", X509_FLAG_NO_SIGDUMP, 0},
		{ "no_aux", X509_FLAG_NO_AUX, 0},
		{ "no_attributes", X509_FLAG_NO_ATTRIBUTES, 0},
		{ "ext_default", X509V3_EXT_DEFAULT, X509V3_EXT_UNKNOWN_MASK},
		{ "ext_error", X509V3_EXT_ERROR_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
		{ "ext_parse", X509V3_EXT_PARSE_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
		{ "ext_dump", X509V3_EXT_DUMP_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
		{ NULL, 0, 0}
	};
	return set_multi_opts(flags, arg, cert_tbl);
}

int set_name_ex(unsigned long *flags, const char *arg)
{
	static const NAME_EX_TBL ex_tbl[] = {
		{ "esc_2253", ASN1_STRFLGS_ESC_2253, 0},
		{ "esc_ctrl", ASN1_STRFLGS_ESC_CTRL, 0},
		{ "esc_msb", ASN1_STRFLGS_ESC_MSB, 0},
		{ "use_quote", ASN1_STRFLGS_ESC_QUOTE, 0},
		{ "utf8", ASN1_STRFLGS_UTF8_CONVERT, 0},
		{ "ignore_type", ASN1_STRFLGS_IGNORE_TYPE, 0},
		{ "show_type", ASN1_STRFLGS_SHOW_TYPE, 0},
		{ "dump_all", ASN1_STRFLGS_DUMP_ALL, 0},
		{ "dump_nostr", ASN1_STRFLGS_DUMP_UNKNOWN, 0},
		{ "dump_der", ASN1_STRFLGS_DUMP_DER, 0},
		{ "compat", XN_FLAG_COMPAT, 0xffffffffL},
		{ "sep_comma_plus", XN_FLAG_SEP_COMMA_PLUS, XN_FLAG_SEP_MASK},
		{ "sep_comma_plus_space", XN_FLAG_SEP_CPLUS_SPC, XN_FLAG_SEP_MASK},
		{ "sep_semi_plus_space", XN_FLAG_SEP_SPLUS_SPC, XN_FLAG_SEP_MASK},
		{ "sep_multiline", XN_FLAG_SEP_MULTILINE, XN_FLAG_SEP_MASK},
		{ "dn_rev", XN_FLAG_DN_REV, 0},
		{ "nofname", XN_FLAG_FN_NONE, XN_FLAG_FN_MASK},
		{ "sname", XN_FLAG_FN_SN, XN_FLAG_FN_MASK},
		{ "lname", XN_FLAG_FN_LN, XN_FLAG_FN_MASK},
		{ "align", XN_FLAG_FN_ALIGN, 0},
		{ "oid", XN_FLAG_FN_OID, XN_FLAG_FN_MASK},
		{ "space_eq", XN_FLAG_SPC_EQ, 0},
		{ "dump_unknown", XN_FLAG_DUMP_UNKNOWN_FIELDS, 0},
		{ "RFC2253", XN_FLAG_RFC2253, 0xffffffffL},
		{ "oneline", XN_FLAG_ONELINE, 0xffffffffL},
		{ "multiline", XN_FLAG_MULTILINE, 0xffffffffL},
		{ "ca_default", XN_FLAG_MULTILINE, 0xffffffffL},
		{ NULL, 0, 0}
	};
	return set_multi_opts(flags, arg, ex_tbl);
}

int set_ext_copy(int *copy_type, const char *arg)
{
	if (!strcasecmp(arg, "none"))
		*copy_type = EXT_COPY_NONE;
	else if (!strcasecmp(arg, "copy"))
		*copy_type = EXT_COPY_ADD;
	else if (!strcasecmp(arg, "copyall"))
		*copy_type = EXT_COPY_ALL;
	else
		return 0;
	return 1;
}




static char *app_get_pass(BIO *err, char *arg, int keepbio)
{
	char *tmp, tpass[APP_PASS_LEN];
	static BIO *pwdbio = NULL;
	int i;
	if(!strncmp(arg, "pass:", 5)) return BUF_strdup(arg + 5);
	if(!strncmp(arg, "env:", 4)) {
		tmp = getenv(arg + 4);
		if(!tmp) {
			BIO_printf(err, "Can't read environment variable %s\n", arg + 4);
			return NULL;
		}
		return BUF_strdup(tmp);
	}
	if(!keepbio || !pwdbio) {
		if(!strncmp(arg, "file:", 5)) {
			pwdbio = BIO_new_file(arg + 5, "r");
			if(!pwdbio) {
				BIO_printf(err, "Can't open file %s\n", arg + 5);
				return NULL;
			}
		/*
		 * Under _WIN32, which covers even Win64 and CE, file
		 * descriptors referenced by BIO_s_fd are not inherited
		 * by child process and therefore below is not an option.
		 * It could have been an option if bss_fd.c was operating
		 * on real Windows descriptors, such as those obtained
		 * with CreateFile.
		 */
		} else if(!strncmp(arg, "fd:", 3)) {
			BIO *btmp;
			i = atoi(arg + 3);
			if(i >= 0) pwdbio = BIO_new_fd(i, BIO_NOCLOSE);
			if((i < 0) || !pwdbio) {
				BIO_printf(err, "Can't access file descriptor %s\n", arg + 3);
				return NULL;
			}
			/* Can't do BIO_gets on an fd BIO so add a buffering BIO */
			btmp = BIO_new(BIO_f_buffer());
			pwdbio = BIO_push(btmp, pwdbio);
		} else if(!strcmp(arg, "stdin")) {
			pwdbio = BIO_new_fp(stdin, BIO_NOCLOSE);
			if(!pwdbio) {
				BIO_printf(err, "Can't open BIO for stdin\n");
				return NULL;
			}
		} else {
			BIO_printf(err, "Invalid password argument \"%s\"\n", arg);
			return NULL;
		}
	}
	i = BIO_gets(pwdbio, tpass, APP_PASS_LEN);
	if(keepbio != 1) {
		BIO_free_all(pwdbio);
		pwdbio = NULL;
	}
	if(i <= 0) {
		BIO_printf(err, "Error reading password from BIO\n");
		return NULL;
	}
	tmp = strchr(tpass, '\n');
	if(tmp) *tmp = 0;
	return BUF_strdup(tpass);
}


int app_passwd(BIO *err, char *arg1, char *arg2, char **pass1, char **pass2)
{
	int same;
	if(!arg2 || !arg1 || strcmp(arg1, arg2)) same = 0;
	else same = 1;
	if(arg1) {
		*pass1 = app_get_pass(err, arg1, same);
		if(!*pass1) return 0;
	} else if(pass1) *pass1 = NULL;
	if(arg2) {
		*pass2 = app_get_pass(err, arg2, same ? 2 : 0);
		if(!*pass2) return 0;
	} else if(pass2) *pass2 = NULL;
	return 1;
}


int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp)
{
	UI *ui = NULL;
	int res = 0;
	const char *prompt_info = NULL;
	const char *password = NULL;
	PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

	if (cb_data)
		{
		if (cb_data->password)
			password = cb_data->password;
		if (cb_data->prompt_info)
			prompt_info = cb_data->prompt_info;
		}

	if (password)
		{
		res = strlen(password);
		if (res > bufsiz)
			res = bufsiz;
		memcpy(buf, password, res);
		return res;
		}

	ui = UI_new_method(ui_method);
	if (ui)
		{
		int ok = 0;
		char *buff = NULL;
		int ui_flags = 0;
		char *prompt = NULL;

		prompt = UI_construct_prompt(ui, "pass phrase",
			prompt_info);

		ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
		UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

		if (ok >= 0)
			ok = UI_add_input_string(ui,prompt,ui_flags,buf,
				PW_MIN_LENGTH,BUFSIZ-1);
		if (ok >= 0 && verify)
			{
			buff = (char *)OPENSSL_malloc(bufsiz);
			ok = UI_add_verify_string(ui,prompt,ui_flags,buff,
				PW_MIN_LENGTH,BUFSIZ-1, buf);
			}
		if (ok >= 0)
			do
				{
				ok = UI_process(ui);
				}
			while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

		if (buff)
			{
			OPENSSL_cleanse(buff,(unsigned int)bufsiz);
			OPENSSL_free(buff);
			}

		if (ok >= 0)
			res = strlen(buf);
		if (ok == -1)
			{
			BIO_printf(bio_err, "User interface error\n");
			ERR_print_errors(bio_err);
			OPENSSL_cleanse(buf,(unsigned int)bufsiz);
			res = 0;
			}
		if (ok == -2)
			{
			BIO_printf(bio_err,"aborted!\n");
			OPENSSL_cleanse(buf,(unsigned int)bufsiz);
			res = 0;
			}
		UI_free(ui);
		OPENSSL_free(prompt);
		}
	return res;
}

static void lookup_fail(const char *name, const char *tag)
{
	BIO_printf(bio_err,"variable lookup failed for %s::%s\n",name,tag);
}


int rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
	BIGNUM *btmp;
	int ret = 0;
	if (b)
		btmp = b;
	else
		btmp = BN_new();

	if (!btmp)
		return 0;

	if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0))
		goto error;
	if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
		goto error;

	ret = 1;
	
	error:

	if (!b)
		BN_free(btmp);
	
	return ret;
}



CA_DB *load_index(char *dbfile, DB_ATTR *db_attr)
{
	CA_DB *retdb = NULL;
	TXT_DB *tmpdb = NULL;
	BIO *in = BIO_new(BIO_s_file());
	CONF *dbattr_conf = NULL;
	char buf[1][BSIZE];
	long errorline= -1;

	if (in == NULL)
		{
		ERR_print_errors(bio_err);
		goto err;
		}
	if (BIO_read_filename(in,dbfile) <= 0)
		{
		perror(dbfile);
		BIO_printf(bio_err,"unable to open '%s'\n",dbfile);
		goto err;
		}
	if ((tmpdb = TXT_DB_read(in,DB_NUMBER)) == NULL)
		goto err;

	BIO_snprintf(buf[0], sizeof buf[0], "%s.attr", dbfile);
	dbattr_conf = NCONF_new(NULL);
	if (NCONF_load(dbattr_conf,buf[0],&errorline) <= 0)
		{
		if (errorline > 0)
			{
			BIO_printf(bio_err,
				"error on line %ld of db attribute file '%s'\n"
				,errorline,buf[0]);
			goto err;
			}
		else
			{
			NCONF_free(dbattr_conf);
			dbattr_conf = NULL;
			}
		}

	if ((retdb = OPENSSL_malloc(sizeof(CA_DB))) == NULL)
		{
		fprintf(stderr, "Out of memory\n");
		goto err;
		}

	retdb->db = tmpdb;
	tmpdb = NULL;
	if (db_attr)
		retdb->attributes = *db_attr;
	else
		{
		retdb->attributes.unique_subject = 1;
		}

	if (dbattr_conf)
		{
		char *p = NCONF_get_string(dbattr_conf,NULL,"unique_subject");
		if (p)
			{
			BIO_printf(bio_err, "DEBUG[load_index]: unique_subject = \"%s\"\n", p);
			retdb->attributes.unique_subject = parse_yesno(p,1);
			}
		}

 err:
	if (dbattr_conf) NCONF_free(dbattr_conf);
	if (tmpdb) TXT_DB_free(tmpdb);
	if (in) BIO_free_all(in);
	return retdb;
}
static unsigned long index_serial_hash(const OPENSSL_CSTRING *a)
{
	const char *n;

	n=a[DB_serial];
	while (*n == '0') n++;
	return(lh_strhash(n));
}

static int index_serial_cmp(const OPENSSL_CSTRING *a, const OPENSSL_CSTRING *b)
{
	const char *aa,*bb;

	for (aa=a[DB_serial]; *aa == '0'; aa++);
	for (bb=b[DB_serial]; *bb == '0'; bb++);
	return(strcmp(aa,bb));
}

static int index_name_qual(char **a)
	{ return(a[0][0] == 'V'); }
static unsigned long index_name_hash(const OPENSSL_CSTRING *a)
	{ return(lh_strhash(a[DB_name])); }
int index_name_cmp(const OPENSSL_CSTRING *a, const OPENSSL_CSTRING *b)
	{ return(strcmp(a[DB_name], b[DB_name])); }


static IMPLEMENT_LHASH_HASH_FN(index_serial, OPENSSL_CSTRING)
static IMPLEMENT_LHASH_COMP_FN(index_serial, OPENSSL_CSTRING)
static IMPLEMENT_LHASH_HASH_FN(index_name, OPENSSL_CSTRING)
static IMPLEMENT_LHASH_COMP_FN(index_name, OPENSSL_CSTRING)

int index_index(CA_DB *db)
{
	if (!TXT_DB_create_index(db->db, DB_serial, NULL,
				LHASH_HASH_FN(index_serial),
				LHASH_COMP_FN(index_serial)))
		{
		BIO_printf(bio_err,
		  "error creating serial number index:(%ld,%ld,%ld)\n",
		  			db->db->error,db->db->arg1,db->db->arg2);
			return 0;
		}

	if (db->attributes.unique_subject
		&& !TXT_DB_create_index(db->db, DB_name, index_name_qual,
			LHASH_HASH_FN(index_name),
			LHASH_COMP_FN(index_name)))
		{
		BIO_printf(bio_err,"error creating name index:(%ld,%ld,%ld)\n",
			db->db->error,db->db->arg1,db->db->arg2);
		return 0;
		}
	return 1;
}

int save_index(const char *dbfile, const char *suffix, CA_DB *db)
{
	char buf[3][BSIZE];
	BIO *out = BIO_new(BIO_s_file());
	int j;

	if (out == NULL)
		{
		ERR_print_errors(bio_err);
		goto err;
		}

	j = strlen(dbfile) + strlen(suffix);
	if (j + 6 >= BSIZE)
		{
		BIO_printf(bio_err,"file name too long\n");
		goto err;
		}

	j = BIO_snprintf(buf[2], sizeof buf[2], "%s.attr", dbfile);
	j = BIO_snprintf(buf[1], sizeof buf[1], "%s.attr.%s", dbfile, suffix);
	j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s", dbfile, suffix);
	BIO_printf(bio_err, "DEBUG: writing \"%s\"\n", buf[0]);
	if (BIO_write_filename(out,buf[0]) <= 0)
		{
		perror(dbfile);
		BIO_printf(bio_err,"unable to open '%s'\n", dbfile);
		goto err;
		}
	j=TXT_DB_write(out,db->db);
	if (j <= 0) goto err;
			
	BIO_free(out);

	out = BIO_new(BIO_s_file());
	BIO_printf(bio_err, "DEBUG: writing \"%s\"\n", buf[1]);
	if (BIO_write_filename(out,buf[1]) <= 0)
		{
		perror(buf[2]);
		BIO_printf(bio_err,"unable to open '%s'\n", buf[2]);
		goto err;
		}
	BIO_printf(out,"unique_subject = %s\n",
		db->attributes.unique_subject ? "yes" : "no");
	BIO_free(out);

	return 1;
 err:
	return 0;
}

int rotate_index(const char *dbfile, const char *new_suffix, const char *old_suffix)
{
	char buf[5][BSIZE];
	int i,j;

	i = strlen(dbfile) + strlen(old_suffix);
	j = strlen(dbfile) + strlen(new_suffix);
	if (i > j) j = i;
	if (j + 6 >= BSIZE)
		{
		BIO_printf(bio_err,"file name too long\n");
		goto err;
		}

	j = BIO_snprintf(buf[4], sizeof buf[4], "%s.attr", dbfile);
	j = BIO_snprintf(buf[2], sizeof buf[2], "%s.attr.%s",
		dbfile, new_suffix);
	j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s",
		dbfile, new_suffix);
	j = BIO_snprintf(buf[1], sizeof buf[1], "%s.%s",
		dbfile, old_suffix);
	j = BIO_snprintf(buf[3], sizeof buf[3], "%s.attr.%s",
		dbfile, old_suffix);
	BIO_printf(bio_err, "DEBUG: renaming \"%s\" to \"%s\"\n",
		dbfile, buf[1]);
	if (rename(dbfile,buf[1]) < 0 && errno != ENOENT
#ifdef ENOTDIR
		&& errno != ENOTDIR
#endif
	   )		{
			BIO_printf(bio_err,
				"unable to rename %s to %s\n",
				dbfile, buf[1]);
			perror("reason");
			goto err;
			}
	BIO_printf(bio_err, "DEBUG: renaming \"%s\" to \"%s\"\n",
		buf[0],dbfile);
	if (rename(buf[0],dbfile) < 0)
		{
		BIO_printf(bio_err,
			"unable to rename %s to %s\n",
			buf[0],dbfile);
		perror("reason");
		rename(buf[1],dbfile);
		goto err;
		}
	BIO_printf(bio_err, "DEBUG: renaming \"%s\" to \"%s\"\n",
		buf[4],buf[3]);
	if (rename(buf[4],buf[3]) < 0 && errno != ENOENT
#ifdef ENOTDIR
		&& errno != ENOTDIR
#endif
	   )		{
			BIO_printf(bio_err,
				"unable to rename %s to %s\n",
				buf[4], buf[3]);
			perror("reason");
			rename(dbfile,buf[0]);
			rename(buf[1],dbfile);
			goto err;
			}
	BIO_printf(bio_err, "DEBUG: renaming \"%s\" to \"%s\"\n",
		buf[2],buf[4]);
	if (rename(buf[2],buf[4]) < 0)
		{
		BIO_printf(bio_err,
			"unable to rename %s to %s\n",
			buf[2],buf[4]);
		perror("reason");
		rename(buf[3],buf[4]);
		rename(dbfile,buf[0]);
		rename(buf[1],dbfile);
		goto err;
		}
	return 1;
 err:
	return 0;
}

void free_index(CA_DB *db)
{
	if (db)
		{
		if (db->db) TXT_DB_free(db->db);
		OPENSSL_free(db);
		}
}

int parse_yesno(const char *str, int def)
	{
	int ret = def;
	if (str)
		{
		switch (*str)
			{
		case 'f': /* false */
		case 'F': /* FALSE */
		case 'n': /* no */
		case 'N': /* NO */
		case '0': /* 0 */
			ret = 0;
			break;
		case 't': /* true */
		case 'T': /* TRUE */
		case 'y': /* yes */
		case 'Y': /* YES */
		case '1': /* 1 */
			ret = 1;
			break;
		default:
			ret = def;
			break;
			}
		}
	return ret;
	}

/*
 * subject is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
X509_NAME *parse_name(char *subject, long chtype, int multirdn)
	{
	size_t buflen = strlen(subject)+1; /* to copy the types and values into. due to escaping, the copy can only become shorter */
	char *buf = OPENSSL_malloc(buflen);
	size_t max_ne = buflen / 2 + 1; /* maximum number of name elements */
	char **ne_types = OPENSSL_malloc(max_ne * sizeof (char *));
	char **ne_values = OPENSSL_malloc(max_ne * sizeof (char *));
	int *mval = OPENSSL_malloc (max_ne * sizeof (int));

	char *sp = subject, *bp = buf;
	int i, ne_num = 0;

	X509_NAME *n = NULL;
	int nid;

	if (!buf || !ne_types || !ne_values)
		{
		BIO_printf(bio_err, "malloc error\n");
		goto error;
		}	

	if (*subject != '/')
		{
		BIO_printf(bio_err, "Subject does not start with '/'.\n");
		goto error;
		}
	sp++; /* skip leading / */

	/* no multivalued RDN by default */
	mval[ne_num] = 0;

	while (*sp)
		{
		/* collect type */
		ne_types[ne_num] = bp;
		while (*sp)
			{
			if (*sp == '\\') /* is there anything to escape in the type...? */
				{
				if (*++sp)
					*bp++ = *sp++;
				else	
					{
					BIO_printf(bio_err, "escape character at end of string\n");
					goto error;
					}
				}	
			else if (*sp == '=')
				{
				sp++;
				*bp++ = '\0';
				break;
				}
			else
				*bp++ = *sp++;
			}
		if (!*sp)
			{
			BIO_printf(bio_err, "end of string encountered while processing type of subject name element #%d\n", ne_num);
			goto error;
			}
		ne_values[ne_num] = bp;
		while (*sp)
			{
			if (*sp == '\\')
				{
				if (*++sp)
					*bp++ = *sp++;
				else
					{
					BIO_printf(bio_err, "escape character at end of string\n");
					goto error;
					}
				}
			else if (*sp == '/')
				{
				sp++;
				/* no multivalued RDN by default */
				mval[ne_num+1] = 0;
				break;
				}
			else if (*sp == '+' && multirdn)
				{
				/* a not escaped + signals a mutlivalued RDN */
				sp++;
				mval[ne_num+1] = -1;
				break;
				}
			else
				*bp++ = *sp++;
			}
		*bp++ = '\0';
		ne_num++;
		}	

	if (!(n = X509_NAME_new()))
		goto error;

	for (i = 0; i < ne_num; i++)
		{
		if ((nid=OBJ_txt2nid(ne_types[i])) == NID_undef)
			{
			BIO_printf(bio_err, "Subject Attribute %s has no known NID, skipped\n", ne_types[i]);
			continue;
			}

		if (!*ne_values[i])
			{
			BIO_printf(bio_err, "No value provided for Subject Attribute %s, skipped\n", ne_types[i]);
			continue;
			}

		if (!X509_NAME_add_entry_by_NID(n, nid, chtype, (unsigned char*)ne_values[i], -1,-1,mval[i]))
			goto error;
		}

	OPENSSL_free(ne_values);
	OPENSSL_free(ne_types);
	OPENSSL_free(buf);
	return n;

error:
	X509_NAME_free(n);
	if (ne_values)
		OPENSSL_free(ne_values);
	if (ne_types)
		OPENSSL_free(ne_types);
	if (buf)
		OPENSSL_free(buf);
	return NULL;
}




static int do_updatedb (CA_DB *db)
{
	ASN1_UTCTIME	*a_tm = NULL;
	int i, cnt = 0;
	int db_y2k, a_y2k;  /* flags = 1 if y >= 2000 */ 
	char **rrow, *a_tm_s;

	a_tm = ASN1_UTCTIME_new();

	/* get actual time and make a string */
	a_tm = X509_gmtime_adj(a_tm, 0);
	a_tm_s = (char *) OPENSSL_malloc(a_tm->length+1);
	if (a_tm_s == NULL)
		{
		cnt = -1;
		goto err;
		}

	memcpy(a_tm_s, a_tm->data, a_tm->length);
	a_tm_s[a_tm->length] = '\0';

	if (strncmp(a_tm_s, "49", 2) <= 0)
		a_y2k = 1;
	else
		a_y2k = 0;

	for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++)
		{
		rrow = sk_OPENSSL_PSTRING_value(db->db->data, i);

		if (rrow[DB_type][0] == 'V')
		 	{
			/* ignore entries that are not valid */
			if (strncmp(rrow[DB_exp_date], "49", 2) <= 0)
				db_y2k = 1;
			else
				db_y2k = 0;

			if (db_y2k == a_y2k)
				{
				/* all on the same y2k side */
				if (strcmp(rrow[DB_exp_date], a_tm_s) <= 0)
				       	{
				       	rrow[DB_type][0]  = 'E';
				       	rrow[DB_type][1]  = '\0';
	  				cnt++;

					BIO_printf(bio_err, "%s=Expired\n",
							rrow[DB_serial]);
					}
				}
			else if (db_y2k < a_y2k)
				{
		  		rrow[DB_type][0]  = 'E';
		  		rrow[DB_type][1]  = '\0';
	  			cnt++;

				BIO_printf(bio_err, "%s=Expired\n",
							rrow[DB_serial]);
				}

			}
    		}

err:

	ASN1_UTCTIME_free(a_tm);
	OPENSSL_free(a_tm_s);

	return (cnt);
}


int old_entry_print(BIO *bp, ASN1_OBJECT *obj, ASN1_STRING *str)
{
	char buf[25],*pbuf, *p;
	int j;
	j=i2a_ASN1_OBJECT(bp,obj);
	pbuf=buf;
	for (j=22-j; j>0; j--)
		*(pbuf++)=' ';
	*(pbuf++)=':';
	*(pbuf++)='\0';
	BIO_puts(bp,buf);

	if (str->type == V_ASN1_PRINTABLESTRING)
		BIO_printf(bp,"PRINTABLE:'");
	else if (str->type == V_ASN1_T61STRING)
		BIO_printf(bp,"T61STRING:'");
	else if (str->type == V_ASN1_IA5STRING)
		BIO_printf(bp,"IA5STRING:'");
	else if (str->type == V_ASN1_UNIVERSALSTRING)
		BIO_printf(bp,"UNIVERSALSTRING:'");
	else
		BIO_printf(bp,"ASN.1 %2d:'",str->type);
			
	p=(char *)str->data;
	for (j=str->length; j>0; j--)
		{
		if ((*p >= ' ') && (*p <= '~'))
			BIO_printf(bp,"%c",*p);
		else if (*p & 0x80)
			BIO_printf(bp,"\\0x%02X",*p);
		else if ((unsigned char)*p == 0xf7)
			BIO_printf(bp,"^?");
		else	BIO_printf(bp,"^%c",*p+'@');
		p++;
		}
	BIO_printf(bp,"'\n");
	return 1;
}

static int do_sign_init(BIO *err, EVP_MD_CTX *ctx, EVP_PKEY *pkey,
			const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
{
	EVP_PKEY_CTX *pkctx = NULL;
	int i;
	EVP_MD_CTX_init(ctx);
	if (!EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey))
		return 0;
	for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++)
		{
		char *sigopt = sk_OPENSSL_STRING_value(sigopts, i);
		if (pkey_ctrl_string(pkctx, sigopt) <= 0)
			{
			BIO_printf(err, "parameter error \"%s\"\n", sigopt);
			ERR_print_errors(bio_err);
			return 0;
			}
		}
	return 1;
}

static int do_X509_sign(BIO *err, X509 *x, EVP_PKEY *pkey, const EVP_MD *md,
			STACK_OF(OPENSSL_STRING) *sigopts)
{
	int rv;
	EVP_MD_CTX mctx;
	EVP_MD_CTX_init(&mctx);
	rv = do_sign_init(err, &mctx, pkey, md, sigopts);
	if (rv > 0)
		rv = X509_sign_ctx(x, &mctx);
	EVP_MD_CTX_cleanup(&mctx);
	return rv > 0 ? 1 : 0;
}



static int do_body(X509 **xret, EVP_PKEY *pkey, X509 *x509, const EVP_MD *dgst,
	     STACK_OF(OPENSSL_STRING) *sigopts, STACK_OF(CONF_VALUE) *policy,
             CA_DB *db, BIGNUM *serial, char *subj,
	     unsigned long chtype, int multirdn,
	     int email_dn, char *startdate, char *enddate, long days, int batch,
	     int verbose, X509_REQ *req, char *ext_sect, CONF *lconf,
	     unsigned long certopt, unsigned long nameopt, int default_op,
	     int ext_copy, int selfsign)
{
	X509_NAME *name=NULL,*CAname=NULL,*subject=NULL, *dn_subject=NULL;
	ASN1_UTCTIME *tm,*tmptm;
	ASN1_STRING *str,*str2;
	ASN1_OBJECT *obj;
	X509 *ret=NULL;
	X509_CINF *ci;
	X509_NAME_ENTRY *ne;
	X509_NAME_ENTRY *tne,*push;
	EVP_PKEY *pktmp;
	int ok= -1,i,j,last,nid;
	const char *p;
	CONF_VALUE *cv;
	char *row[DB_NUMBER];
	char **irow=NULL;
	char **rrow=NULL;
	char buf[25];

	tmptm=ASN1_UTCTIME_new();
	if (tmptm == NULL)
		{
		BIO_printf(bio_err,"malloc error\n");
		return(0);
		}

	for (i=0; i<DB_NUMBER; i++)
		row[i]=NULL;

	if (subj)
		{
		X509_NAME *n = parse_name(subj, chtype, multirdn);

		if (!n)
			{
			ERR_print_errors(bio_err);
			goto err;
			}
		X509_REQ_set_subject_name(req,n);
		req->req_info->enc.modified = 1;
		X509_NAME_free(n);
		}

	if (default_op)
		BIO_printf(bio_err,"The Subject's Distinguished Name is as follows\n");

	name=X509_REQ_get_subject_name(req);
	for (i=0; i<X509_NAME_entry_count(name); i++)
		{
		ne= X509_NAME_get_entry(name,i);
		str=X509_NAME_ENTRY_get_data(ne);
		obj=X509_NAME_ENTRY_get_object(ne);

		if (msie_hack)
			{
			/* assume all type should be strings */
			nid=OBJ_obj2nid(ne->object);

			if (str->type == V_ASN1_UNIVERSALSTRING)
				ASN1_UNIVERSALSTRING_to_string(str);

			if ((str->type == V_ASN1_IA5STRING) &&
				(nid != NID_pkcs9_emailAddress))
				str->type=V_ASN1_T61STRING;

			if ((nid == NID_pkcs9_emailAddress) &&
				(str->type == V_ASN1_PRINTABLESTRING))
				str->type=V_ASN1_IA5STRING;
			}

		/* If no EMAIL is wanted in the subject */
		if ((OBJ_obj2nid(obj) == NID_pkcs9_emailAddress) && (!email_dn))
			continue;

		/* check some things */
		if ((OBJ_obj2nid(obj) == NID_pkcs9_emailAddress) &&
			(str->type != V_ASN1_IA5STRING))
			{
			BIO_printf(bio_err,"\nemailAddress type needs to be of type IA5STRING\n");
			goto err;
			}
		if ((str->type != V_ASN1_BMPSTRING) && (str->type != V_ASN1_UTF8STRING))
			{
			j=ASN1_PRINTABLE_type(str->data,str->length);
			if (	((j == V_ASN1_T61STRING) &&
				 (str->type != V_ASN1_T61STRING)) ||
				((j == V_ASN1_IA5STRING) &&
				 (str->type == V_ASN1_PRINTABLESTRING)))
				{
				BIO_printf(bio_err,"\nThe string contains characters that are illegal for the ASN.1 type\n");
				goto err;
				}
			}

		if (default_op)
			old_entry_print(bio_err, obj, str);
		}

	/* Ok, now we check the 'policy' stuff. */
	if ((subject=X509_NAME_new()) == NULL)
		{
		BIO_printf(bio_err,"Memory allocation failure\n");
		goto err;
		}

	/* take a copy of the issuer name before we mess with it. */
	if (selfsign)
		CAname=X509_NAME_dup(name);
	else
		CAname=X509_NAME_dup(x509->cert_info->subject);
	if (CAname == NULL) goto err;
	str=str2=NULL;

	for (i=0; i<sk_CONF_VALUE_num(policy); i++)
		{
		cv=sk_CONF_VALUE_value(policy,i); /* get the object id */
		if ((j=OBJ_txt2nid(cv->name)) == NID_undef)
			{
			BIO_printf(bio_err,"%s:unknown object type in 'policy' configuration\n",cv->name);
			goto err;
			}
		obj=OBJ_nid2obj(j);

		last= -1;
		for (;;)
			{
			/* lookup the object in the supplied name list */
			j=X509_NAME_get_index_by_OBJ(name,obj,last);
			if (j < 0)
				{
				if (last != -1) break;
				tne=NULL;
				}
			else
				{
				tne=X509_NAME_get_entry(name,j);
				}
			last=j;

			/* depending on the 'policy', decide what to do. */
			push=NULL;
			if (strcmp(cv->value,"optional") == 0)
				{
				if (tne != NULL)
					push=tne;
				}
			else if (strcmp(cv->value,"supplied") == 0)
				{
				if (tne == NULL)
					{
					BIO_printf(bio_err,"The %s field needed to be supplied and was missing\n",cv->name);
					goto err;
					}
				else
					push=tne;
				}
			else if (strcmp(cv->value,"match") == 0)
				{
				int last2;

				if (tne == NULL)
					{
					BIO_printf(bio_err,"The mandatory %s field was missing\n",cv->name);
					goto err;
					}

				last2= -1;

again2:
				j=X509_NAME_get_index_by_OBJ(CAname,obj,last2);
				if ((j < 0) && (last2 == -1))
					{
					BIO_printf(bio_err,"The %s field does not exist in the CA certificate,\nthe 'policy' is misconfigured\n",cv->name);
					goto err;
					}
				if (j >= 0)
					{
					push=X509_NAME_get_entry(CAname,j);
					str=X509_NAME_ENTRY_get_data(tne);
					str2=X509_NAME_ENTRY_get_data(push);
					last2=j;
					if (ASN1_STRING_cmp(str,str2) != 0)
						goto again2;
					}
				if (j < 0)
					{
					BIO_printf(bio_err,"The %s field needed to be the same in the\nCA certificate (%s) and the request (%s)\n",cv->name,((str2 == NULL)?"NULL":(char *)str2->data),((str == NULL)?"NULL":(char *)str->data));
					goto err;
					}
				}
			else
				{
				BIO_printf(bio_err,"%s:invalid type in 'policy' configuration\n",cv->value);
				goto err;
				}

			if (push != NULL)
				{
				if (!X509_NAME_add_entry(subject,push, -1, 0))
					{
					if (push != NULL)
						X509_NAME_ENTRY_free(push);
					BIO_printf(bio_err,"Memory allocation failure\n");
					goto err;
					}
				}
			if (j < 0) break;
			}
		}

	if (preserve)
		{
		X509_NAME_free(subject);
		/* subject=X509_NAME_dup(X509_REQ_get_subject_name(req)); */
		subject=X509_NAME_dup(name);
		if (subject == NULL) goto err;
		}

	if (verbose)
		BIO_printf(bio_err,"The subject name appears to be ok, checking data base for clashes\n");

	/* Build the correct Subject if no e-mail is wanted in the subject */
	/* and add it later on because of the method extensions are added (altName) */
	 
	if (email_dn)
		dn_subject = subject;
	else
		{
		X509_NAME_ENTRY *tmpne;
		/* Its best to dup the subject DN and then delete any email
		 * addresses because this retains its structure.
		 */
		if (!(dn_subject = X509_NAME_dup(subject)))
			{
			BIO_printf(bio_err,"Memory allocation failure\n");
			goto err;
			}
		while((i = X509_NAME_get_index_by_NID(dn_subject,
					NID_pkcs9_emailAddress, -1)) >= 0)
			{
			tmpne = X509_NAME_get_entry(dn_subject, i);
			X509_NAME_delete_entry(dn_subject, i);
			X509_NAME_ENTRY_free(tmpne);
			}
		}

	if (BN_is_zero(serial))
		row[DB_serial]=BUF_strdup("00");
	else
		row[DB_serial]=BN_bn2hex(serial);
	if (row[DB_serial] == NULL)
		{
		BIO_printf(bio_err,"Memory allocation failure\n");
		goto err;
		}

	if (db->attributes.unique_subject)
		{
		char **crow=row;

		rrow=TXT_DB_get_by_index(db->db,DB_name,crow);
		if (rrow != NULL)
			{
			BIO_printf(bio_err,
				"ERROR:There is already a certificate for %s\n",
				row[DB_name]);
			}
		}
	if (rrow == NULL)
		{
		rrow=TXT_DB_get_by_index(db->db,DB_serial,row);
		if (rrow != NULL)
			{
			BIO_printf(bio_err,"ERROR:Serial number %s has already been issued,\n",
				row[DB_serial]);
			BIO_printf(bio_err,"      check the database/serial_file for corruption\n");
			}
		}

	if (rrow != NULL)
		{
		BIO_printf(bio_err,
			"The matching entry has the following details\n");
		if (rrow[DB_type][0] == 'E')
			p="Expired";
		else if (rrow[DB_type][0] == 'R')
			p="Revoked";
		else if (rrow[DB_type][0] == 'V')
			p="Valid";
		else
			p="\ninvalid type, Data base error\n";
		BIO_printf(bio_err,"Type	  :%s\n",p);;
		if (rrow[DB_type][0] == 'R')
			{
			p=rrow[DB_exp_date]; if (p == NULL) p="undef";
			BIO_printf(bio_err,"Was revoked on:%s\n",p);
			}
		p=rrow[DB_exp_date]; if (p == NULL) p="undef";
		BIO_printf(bio_err,"Expires on    :%s\n",p);
		p=rrow[DB_serial]; if (p == NULL) p="undef";
		BIO_printf(bio_err,"Serial Number :%s\n",p);
		p=rrow[DB_file]; if (p == NULL) p="undef";
		BIO_printf(bio_err,"File name     :%s\n",p);
		p=rrow[DB_name]; if (p == NULL) p="undef";
		BIO_printf(bio_err,"Subject Name  :%s\n",p);
		ok= -1; /* This is now a 'bad' error. */
		goto err;
		}

	/* We are now totally happy, lets make and sign the certificate */
	if (verbose)
		BIO_printf(bio_err,"Everything appears to be ok, creating and signing the certificate\n");

	if ((ret=X509_new()) == NULL) goto err;
	ci=ret->cert_info;

	/* Make it an X509 v3 certificate. */
	if (!X509_set_version(ret,2)) goto err;

	if (BN_to_ASN1_INTEGER(serial,ci->serialNumber) == NULL)
		goto err;
	if (selfsign)
		{
		if (!X509_set_issuer_name(ret,subject))
			goto err;
		}
	else
		{
		if (!X509_set_issuer_name(ret,X509_get_subject_name(x509)))
			goto err;
		}

	if (strcmp(startdate,"today") == 0)
		X509_gmtime_adj(X509_get_notBefore(ret),0);
	else ASN1_TIME_set_string(X509_get_notBefore(ret),startdate);

	if (enddate == NULL)
		X509_time_adj_ex(X509_get_notAfter(ret),days, 0, NULL);
	else ASN1_TIME_set_string(X509_get_notAfter(ret),enddate);

	if (!X509_set_subject_name(ret,subject)) goto err;

	pktmp=X509_REQ_get_pubkey(req);
	i = X509_set_pubkey(ret,pktmp);
	EVP_PKEY_free(pktmp);
	if (!i) goto err;

	/* Lets add the extensions, if there are any */
	if (ext_sect)
		{
		X509V3_CTX ctx;
		if (ci->version == NULL)
			if ((ci->version=ASN1_INTEGER_new()) == NULL)
				goto err;
		ASN1_INTEGER_set(ci->version,2); /* version 3 certificate */

		/* Free the current entries if any, there should not
		 * be any I believe */
		if (ci->extensions != NULL)
			sk_X509_EXTENSION_pop_free(ci->extensions,
						   X509_EXTENSION_free);

		ci->extensions = NULL;

		/* Initialize the context structure */
		if (selfsign)
			X509V3_set_ctx(&ctx, ret, ret, req, NULL, 0);
		else
			X509V3_set_ctx(&ctx, x509, ret, req, NULL, 0);

		if (extconf)
			{
			if (verbose)
				BIO_printf(bio_err, "Extra configuration file found\n");
 
			/* Use the extconf configuration db LHASH */
			X509V3_set_nconf(&ctx, extconf);
 
			/* Test the structure (needed?) */
			/* X509V3_set_ctx_test(&ctx); */

			/* Adds exts contained in the configuration file */
			if (!X509V3_EXT_add_nconf(extconf, &ctx, ext_sect,ret))
				{
				BIO_printf(bio_err,
				    "ERROR: adding extensions in section %s\n",
								ext_sect);
				ERR_print_errors(bio_err);
				goto err;
				}
			if (verbose)
				BIO_printf(bio_err, "Successfully added extensions from file.\n");
			}
		else if (ext_sect)
			{
			/* We found extensions to be set from config file */
			X509V3_set_nconf(&ctx, lconf);

			if(!X509V3_EXT_add_nconf(lconf, &ctx, ext_sect, ret))
				{
				BIO_printf(bio_err, "ERROR: adding extensions in section %s\n", ext_sect);
				ERR_print_errors(bio_err);
				goto err;
				}

			if (verbose) 
				BIO_printf(bio_err, "Successfully added extensions from config\n");
			}
		}

	/* Copy extensions from request (if any) */

	if (!copy_extensions(ret, req, ext_copy))
		{
		BIO_printf(bio_err, "ERROR: adding extensions from request\n");
		ERR_print_errors(bio_err);
		goto err;
		}

	/* Set the right value for the noemailDN option */
	if( email_dn == 0 )
		{
		if (!X509_set_subject_name(ret,dn_subject)) goto err;
		}

	if (!default_op)
		{
		BIO_printf(bio_err, "Certificate Details:\n");
		/* Never print signature details because signature not present */
		certopt |= X509_FLAG_NO_SIGDUMP | X509_FLAG_NO_SIGNAME;
		X509_print_ex(bio_err, ret, nameopt, certopt); 
		}

	BIO_printf(bio_err,"Certificate is to be certified until ");
	ASN1_TIME_print(bio_err,X509_get_notAfter(ret));
	if (days) BIO_printf(bio_err," (%ld days)",days);
	BIO_printf(bio_err, "\n");

	if (!batch)
		{

		BIO_printf(bio_err,"Sign the certificate? [y/n]:");
		(void)BIO_flush(bio_err);
		buf[0]='\0';
		if (!fgets(buf,sizeof(buf)-1,stdin))
			{
			BIO_printf(bio_err,"CERTIFICATE WILL NOT BE CERTIFIED: I/O error\n");
			ok=0;
			goto err;
			}
		if (!((buf[0] == 'y') || (buf[0] == 'Y')))
			{
			BIO_printf(bio_err,"CERTIFICATE WILL NOT BE CERTIFIED\n");
			ok=0;
			goto err;
			}
		}

	pktmp=X509_get_pubkey(ret);
	if (EVP_PKEY_missing_parameters(pktmp) &&
		!EVP_PKEY_missing_parameters(pkey))
		EVP_PKEY_copy_parameters(pktmp,pkey);
	EVP_PKEY_free(pktmp);

	if (!do_X509_sign(bio_err, ret,pkey,dgst, sigopts))
		goto err;

	/* We now just add it to the database */
	row[DB_type]=(char *)OPENSSL_malloc(2);

	tm=X509_get_notAfter(ret);
	row[DB_exp_date]=(char *)OPENSSL_malloc(tm->length+1);
	memcpy(row[DB_exp_date],tm->data,tm->length);
	row[DB_exp_date][tm->length]='\0';

	row[DB_rev_date]=NULL;

	/* row[DB_serial] done already */
	row[DB_file]=(char *)OPENSSL_malloc(8);
	row[DB_name]=X509_NAME_oneline(X509_get_subject_name(ret),NULL,0);

	if ((row[DB_type] == NULL) || (row[DB_exp_date] == NULL) ||
		(row[DB_file] == NULL) || (row[DB_name] == NULL))
		{
		BIO_printf(bio_err,"Memory allocation failure\n");
		goto err;
		}
	BUF_strlcpy(row[DB_file],"unknown",8);
	row[DB_type][0]='V';
	row[DB_type][1]='\0';

	if ((irow=(char **)OPENSSL_malloc(sizeof(char *)*(DB_NUMBER+1))) == NULL)
		{
		BIO_printf(bio_err,"Memory allocation failure\n");
		goto err;
		}

	for (i=0; i<DB_NUMBER; i++)
		{
		irow[i]=row[i];
		row[i]=NULL;
		}
	irow[DB_NUMBER]=NULL;

	if (!TXT_DB_insert(db->db,irow))
		{
		BIO_printf(bio_err,"failed to update database\n");
		BIO_printf(bio_err,"TXT_DB error number %ld\n",db->db->error);
		goto err;
		}
	ok=1;
err:
	for (i=0; i<DB_NUMBER; i++)
		if (row[i] != NULL) OPENSSL_free(row[i]);

	if (CAname != NULL)
		X509_NAME_free(CAname);
	if (subject != NULL)
		X509_NAME_free(subject);
	if ((dn_subject != NULL) && !email_dn)
		X509_NAME_free(dn_subject);
	if (tmptm != NULL)
		ASN1_UTCTIME_free(tmptm);
	if (ok <= 0)
		{
		if (ret != NULL) X509_free(ret);
		ret=NULL;
		}
	else
		*xret=ret;
	return(ok);
}



static int certify (X509 **xret, char *inptr, EVP_PKEY *pkey, X509 *x509,
	     const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
	     STACK_OF(CONF_VALUE) *policy, CA_DB *db,
	     BIGNUM *serial, char *subj,unsigned long chtype, int multirdn,
	     int email_dn, char *startdate, char *enddate,
	     long days, int batch, char *ext_sect, CONF *lconf, int verbose,
	     unsigned long certopt, unsigned long nameopt, int default_op,
	     int ext_copy, int selfsign, int p10len)
{
	X509_REQ *req=NULL;
	BIO *in=NULL;
	BIO *b64;
	EVP_PKEY *pktmp=NULL;
	int ok= -1,i;

        b64 = BIO_new(BIO_f_base64());
	in = BIO_new_mem_buf(inptr, p10len);
	in = BIO_push(b64, in);

	//Read DER encoded PKCS10 request 
	if ((req=d2i_X509_REQ_bio(in,NULL)) == NULL)
	//if ((req=PEM_read_bio_X509_REQ(in,NULL,NULL,NULL)) == NULL)
		{
		BIO_printf(bio_err,"Error reading certificate request\n");
		goto err;
		}
	if (verbose)
		X509_REQ_print(bio_err,req);

	BIO_printf(bio_err,"Check that the request matches the signature\n");

	if (selfsign && !X509_REQ_check_private_key(req,pkey))
		{
		BIO_printf(bio_err,"Certificate request and CA private key do not match\n");
		ok=0;
		goto err;
		}
	if ((pktmp=X509_REQ_get_pubkey(req)) == NULL)
		{
		BIO_printf(bio_err,"error unpacking public key\n");
		goto err;
		}
	i=X509_REQ_verify(req,pktmp);
	EVP_PKEY_free(pktmp);
	if (i < 0)
		{
		ok=0;
		BIO_printf(bio_err,"Signature verification problems....\n");
		goto err;
		}
	if (i == 0)
		{
		ok=0;
		BIO_printf(bio_err,"Signature did not match the certificate request\n");
		goto err;
		}
	else
		BIO_printf(bio_err,"Signature ok\n");

	ok=do_body(xret,pkey,x509,dgst,sigopts, policy,db,serial,subj,chtype,
		multirdn, email_dn,
		startdate,enddate,days,batch,verbose,req,ext_sect,lconf,
		certopt, nameopt, default_op, ext_copy, selfsign);

err:
	if (req != NULL) X509_REQ_free(req);
	if (in != NULL) BIO_free_all(in);
	return(ok);
}

static int get_certificate_status(const char *serial, CA_DB *db)
{
	char *row[DB_NUMBER],**rrow;
	int ok=-1,i;

	/* Free Resources */
	for (i=0; i<DB_NUMBER; i++)
		row[i]=NULL;

	/* Malloc needed char spaces */
	row[DB_serial] = OPENSSL_malloc(strlen(serial) + 2);
	if (row[DB_serial] == NULL)
		{
		BIO_printf(bio_err,"Malloc failure\n");
		goto err;
		}

	if (strlen(serial) % 2)
		{
		/* Set the first char to 0 */;
		row[DB_serial][0]='0';

		/* Copy String from serial to row[DB_serial] */
		memcpy(row[DB_serial]+1, serial, strlen(serial));
		row[DB_serial][strlen(serial)+1]='\0';
		}
	else
		{
		/* Copy String from serial to row[DB_serial] */
		memcpy(row[DB_serial], serial, strlen(serial));
		row[DB_serial][strlen(serial)]='\0';
		}
			
	/* Make it Upper Case */
	for (i=0; row[DB_serial][i] != '\0'; i++)
		row[DB_serial][i] = toupper((unsigned char)row[DB_serial][i]);
	

	ok=1;

	/* Search for the certificate */
	rrow=TXT_DB_get_by_index(db->db,DB_serial,row);
	if (rrow == NULL)
		{
		BIO_printf(bio_err,"Serial %s not present in db.\n",
				 row[DB_serial]);
		ok=-1;
		goto err;
		}
	else if (rrow[DB_type][0]=='V')
		{
		BIO_printf(bio_err,"%s=Valid (%c)\n",
			row[DB_serial], rrow[DB_type][0]);
		goto err;
		}
	else if (rrow[DB_type][0]=='R')
		{
		BIO_printf(bio_err,"%s=Revoked (%c)\n",
			row[DB_serial], rrow[DB_type][0]);
		goto err;
		}
	else if (rrow[DB_type][0]=='E')
		{
		BIO_printf(bio_err,"%s=Expired (%c)\n",
			row[DB_serial], rrow[DB_type][0]);
		goto err;
		}
	else if (rrow[DB_type][0]=='S')
		{
		BIO_printf(bio_err,"%s=Suspended (%c)\n",
			row[DB_serial], rrow[DB_type][0]);
		goto err;
		}
	else
		{
		BIO_printf(bio_err,"%s=Unknown (%c).\n",
			row[DB_serial], rrow[DB_type][0]);
		ok=-1;
		}
err:
	for (i=0; i<DB_NUMBER; i++)
		{
		if (row[i] != NULL)
			OPENSSL_free(row[i]);
		}
	return(ok);
}

static int check_time_format(const char *str)
{
	return ASN1_TIME_set_string(NULL, str);
}

/****************************************************************************
 * 
 * Functions above this point are mostly taken directly from OpenSLL
 * without modifications. Below this point are the new functions added
 * to interface with the EST stack.
 *
 ****************************************************************************/


/*
 * This function is used to statisfy the callback request from the EST
 * stack when a simple enrollment request needs to be serviced.
 * The EST stack will receive PKCS10 data from the HTTP layer and
 * forward it to this function.  This function returns the signed
 * PKCS7 response.  The buflen parameter will contain the length
 * of the response.  The data is returned as a char array so that
 * the EST stack can easily send it to the client in an HTTP
 * response message.
 *
 * This function was mostly taken from OpenSSL and modified to work
 * specifically for pkcs10->pkcs7 signing for the EST stack.  
 * Please accept my apology in advance for the poor formatting 
 * in the code below.
 */
BIO * ossl_simple_enroll (const char *p10buf, int p10len, char *configfile)
{
	char *keyfile = NULL;
	BIO *p7out;
	char passargin[20] = "pass:hello";
	ENGINE *e = NULL;
	char *key=NULL;
	int create_ser = 0;
	int free_key = 0;
	int total=0;
	int total_done=0;
	int ret=1;
	int email_dn=1;
	int req=1;
	int verbose=1;
	int gencrl=0;
	int doupdatedb=0;
	long errorline= -1;
	char *md=NULL;
	char *policy=NULL;    
	char *certfile=NULL;
	int keyform=FORMAT_PEM;
	char *inptr = (char *)p10buf;
	char *spkac_file=NULL;
	char *ss_cert_file=NULL;
	char *ser_status=NULL;
	EVP_PKEY *pkey=NULL;
	char *serialfile=NULL;
	char *extensions=NULL;
	char *subj=NULL;
	unsigned long chtype = MBSTRING_ASC;
	int multirdn = 0;
	char *tmp_email_dn=NULL;
	BIGNUM *serial=NULL;
	BIGNUM *crlnumber=NULL;
	char *startdate=NULL;
	char *enddate=NULL;
	long days=0;
	int batch=1;
	int notext=0;
	unsigned long nameopt = 0, certopt = 0;
	int default_op = 1;
	int ext_copy = EXT_COPY_NONE;
	int selfsign = 0;
	X509 *x509=NULL, *x509p = NULL;
	X509 *x=NULL;
	BIO *in=NULL,*out=NULL,*Cout=NULL;
	char *dbfile=NULL;
	CA_DB *db=NULL;
	X509_CRL *crl=NULL;
	char *f;
	const char *p;
	char * const *pp;
	int i,j;
	const EVP_MD *dgst=NULL;
	STACK_OF(CONF_VALUE) *attribs=NULL;
	STACK_OF(X509) *cert_sk=NULL;
	STACK_OF(OPENSSL_STRING) *sigopts = NULL;
	char buf[3][256];
	char *randfile=NULL;
	char *tofree=NULL;
	DB_ATTR db_attr;
	BIO *retval = NULL;

	conf = NULL;
	key = NULL;
	section = NULL;

	preserve=0;
	msie_hack=0;
	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

#if 0
		//FIXME: We may still need this eventually
		else if (strcmp(*argv,"-subj") == 0)
			{
			if (--argc < 1) goto bad;
			subj= *(++argv);
			/* preserve=1; */
			}
#endif

	ERR_load_crypto_strings();

	/*****************************************************************/
	tofree=NULL;
	if (configfile == NULL) {
	    BIO_printf(bio_err,"\nOpenSSL CA config file not known");
	    return NULL;
	}

	BIO_printf(bio_err,"Using configuration from %s\n",configfile);
	conf = NCONF_new(NULL);
	if (NCONF_load(conf,configfile,&errorline) <= 0) {
		if (errorline <= 0)
			BIO_printf(bio_err,"error loading the config file '%s'\n",
				configfile);
		else
			BIO_printf(bio_err,"error on line %ld of config file '%s'\n"
				,errorline,configfile);
		goto err;
	}
	if(tofree) {
		OPENSSL_free(tofree);
		tofree = NULL;
	}

	if (!load_config(bio_err, conf)) goto err;


	/* Lets get the config section we are using */
	if (section == NULL) {
		section=NCONF_get_string(conf,BASE_SECTION,ENV_DEFAULT_CA);
		if (section == NULL) {
			lookup_fail(BASE_SECTION,ENV_DEFAULT_CA);
			goto err;
		}
	}

	if (conf != NULL) {
		p=NCONF_get_string(conf,NULL,"oid_file");
		if (p == NULL) ERR_clear_error();
		if (p != NULL) {
			BIO *oid_bio;

			oid_bio=BIO_new_file(p,"r");
			if (oid_bio == NULL) {
				/*
				BIO_printf(bio_err,"problems opening %s for extra oid's\n",p);
				ERR_print_errors(bio_err);
				*/
				ERR_clear_error();
			}
			else {
				OBJ_create_objects(oid_bio);
				BIO_free(oid_bio);
			}
		}
		if (!add_oid_section(bio_err,conf)) {
			ERR_print_errors(bio_err);
			goto err;
		}
	}


	randfile = NCONF_get_string(conf, BASE_SECTION, "RANDFILE");
	if (randfile == NULL) ERR_clear_error();
	//app_RAND_load_file(randfile, bio_err, 0);

	f = NCONF_get_string(conf, section, STRING_MASK);
	if (!f) ERR_clear_error();

	if(f && !ASN1_STRING_set_default_mask_asc(f)) {
		BIO_printf(bio_err, "Invalid global string mask setting %s\n", f);
		goto err;
	}

	if (chtype != MBSTRING_UTF8){
		f = NCONF_get_string(conf, section, UTF8_IN);
		if (!f)
			ERR_clear_error();
		else if (!strcmp(f, "yes"))
			chtype = MBSTRING_UTF8;
	}

	db_attr.unique_subject = 1;
	p = NCONF_get_string(conf, section, ENV_UNIQUE_SUBJECT);
	if (p) {
		BIO_printf(bio_err, "DEBUG: unique_subject = \"%s\"\n", p);
		db_attr.unique_subject = parse_yesno(p,1);
	}
	else
		ERR_clear_error();
	if (!p) BIO_printf(bio_err, "DEBUG: unique_subject undefined %s\n", p);
	BIO_printf(bio_err, "DEBUG: configured unique_subject is %d\n",
		db_attr.unique_subject);
	
	in=BIO_new(BIO_s_file());
	out=BIO_new(BIO_s_file());
	Cout=BIO_new(BIO_s_mem());
	if ((in == NULL) || (out == NULL) || (Cout == NULL)) {
		ERR_print_errors(bio_err);
		goto err;
	}

	/*****************************************************************/
	/* report status of cert with serial number given on command line */
	if (ser_status) {
		if ((dbfile=NCONF_get_string(conf,section,ENV_DATABASE)) == NULL) {
			lookup_fail(section,ENV_DATABASE);
			goto err;
		}
		db = load_index(dbfile,&db_attr);
		if (db == NULL) goto err;

		if (!index_index(db)) goto err;

		if (get_certificate_status(ser_status,db) != 1)
			BIO_printf(bio_err,"Error verifying serial %s!\n",
				 ser_status);
		goto err;
	}

	/*****************************************************************/
	/* we definitely need a private key, so let's get it */

	if ((keyfile == NULL) && ((keyfile=NCONF_get_string(conf,
		section,ENV_PRIVATE_KEY)) == NULL)) {
		lookup_fail(section,ENV_PRIVATE_KEY);
		goto err;
	}
	if (!key) {
		free_key = 1;
		if (!app_passwd(bio_err, passargin, NULL, &key, NULL)) {
			BIO_printf(bio_err,"Error getting password\n");
			goto err;
		}
	}
	pkey = load_key(bio_err, keyfile, keyform, 0, key, e, 
		"CA private key");
	if (key) OPENSSL_cleanse(key,strlen(key));
	if (pkey == NULL) {
		/* load_key() has already printed an appropriate message */
		goto err;
	}

	/*****************************************************************/
	/* we need a certificate */
	if (!selfsign || spkac_file || ss_cert_file || gencrl) {
		if ((certfile == NULL)
			&& ((certfile=NCONF_get_string(conf,
				     section,ENV_CERTIFICATE)) == NULL)) {
			lookup_fail(section,ENV_CERTIFICATE);
			goto err;
		}
		x509=load_cert(bio_err, certfile, FORMAT_PEM, NULL, e,
			"CA certificate");
		if (x509 == NULL)
			goto err;

		if (!X509_check_private_key(x509,pkey)) {
			BIO_printf(bio_err,"CA certificate and CA private key do not match\n");
			goto err;
		}
	}
	if (!selfsign) x509p = x509;

	f=NCONF_get_string(conf,BASE_SECTION,ENV_PRESERVE);
	if (f == NULL) ERR_clear_error();
	if ((f != NULL) && ((*f == 'y') || (*f == 'Y'))) preserve=1;
	f=NCONF_get_string(conf,BASE_SECTION,ENV_MSIE_HACK);
	if (f == NULL) ERR_clear_error();
	if ((f != NULL) && ((*f == 'y') || (*f == 'Y'))) msie_hack=1;

	f=NCONF_get_string(conf,section,ENV_NAMEOPT);

	if (f) {
		if (!set_name_ex(&nameopt, f))
			{
			BIO_printf(bio_err, "Invalid name options: \"%s\"\n", f);
			goto err;
			}
		default_op = 0;
	}
	else ERR_clear_error();

	f=NCONF_get_string(conf,section,ENV_CERTOPT);

	if (f) {
		if (!set_cert_ex(&certopt, f))
			{
			BIO_printf(bio_err, "Invalid certificate options: \"%s\"\n", f);
			goto err;
			}
		default_op = 0;
	}
	else ERR_clear_error();

	f=NCONF_get_string(conf,section,ENV_EXTCOPY);

	if (f) {
		if (!set_ext_copy(&ext_copy, f)) {
			BIO_printf(bio_err, "Invalid extension copy option: \"%s\"\n", f);
			goto err;
		}
	}
	else ERR_clear_error();


	/*****************************************************************/
	/* we need to load the database file */
	if ((dbfile=NCONF_get_string(conf,section,ENV_DATABASE)) == NULL) {
		lookup_fail(section,ENV_DATABASE);
		goto err;
	}
	db = load_index(dbfile, &db_attr);
	if (db == NULL) goto err;

	/* Lets check some fields */
	for (i=0; i<sk_OPENSSL_PSTRING_num(db->db->data); i++) {
		pp=sk_OPENSSL_PSTRING_value(db->db->data,i);
		if ((pp[DB_type][0] != DB_TYPE_REV) &&
			(pp[DB_rev_date][0] != '\0')) {
			BIO_printf(bio_err,"entry %d: not revoked yet, but has a revocation date\n",i+1);
			goto err;
		}
#if 0
		if ((pp[DB_type][0] == DB_TYPE_REV) &&
			!make_revoked(NULL, pp[DB_rev_date])) {
			BIO_printf(bio_err," in entry %d\n", i+1);
			goto err;
		}
#endif
		if (!check_time_format((char *)pp[DB_exp_date])) {
			BIO_printf(bio_err,"entry %d: invalid expiry date\n",i+1);
			goto err;
		}
		p=pp[DB_serial];
		j=strlen(p);
		if (*p == '-') {
			p++;
			j--;
		}
		if ((j&1) || (j < 2)) {
			BIO_printf(bio_err,"entry %d: bad serial number length (%d)\n",i+1,j);
			goto err;
		}
		while (*p) {
			if (!(	((*p >= '0') && (*p <= '9')) ||
				((*p >= 'A') && (*p <= 'F')) ||
				((*p >= 'a') && (*p <= 'f')))  ) {
				BIO_printf(bio_err,"entry %d: bad serial number characters, char pos %ld, char is '%c'\n",i+1,(long)(p-pp[DB_serial]),*p);
				goto err;
			}
			p++;
		}
	}
#if 0
	if (verbose) {
		BIO_set_fp(out,stdout,BIO_NOCLOSE|BIO_FP_TEXT); /* cannot fail */
		TXT_DB_write(out,db->db);
		BIO_printf(bio_err,"%d entries loaded from the database\n",
			   sk_OPENSSL_PSTRING_num(db->db->data));
		BIO_printf(bio_err,"generating index\n");
	}
#endif
	
	if (!index_index(db)) goto err;

	/*****************************************************************/
	/* Update the db file for expired certificates */
	if (doupdatedb) {
		if (verbose) BIO_printf(bio_err, "Updating %s ...\n", dbfile);

		i = do_updatedb(db);
		if (i == -1) {
			BIO_printf(bio_err,"Malloc failure\n");
			goto err;
		}
		else if (i == 0) {
			if (verbose) BIO_printf(bio_err,
					"No entries found to mark expired\n"); 
		}
	    	else {
			if (!save_index(dbfile,"new",db)) goto err;
				
			if (!rotate_index(dbfile,"new","old")) goto err;
				
			if (verbose) BIO_printf(bio_err,
				"Done. %d entries marked as expired\n",i); 
	      	}
	  }


	if ((md == NULL) && ((md=NCONF_get_string(conf, section,ENV_DEFAULT_MD)) == NULL)) {
		lookup_fail(section,ENV_DEFAULT_MD);
		goto err;
	}

	if (!strcmp(md, "default")) {
		int def_nid;
		if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) <= 0) {
			BIO_puts(bio_err,"no default digest\n");
			goto err;
		}
		md = (char *)OBJ_nid2sn(def_nid);
	}

	if ((dgst=EVP_get_digestbyname(md)) == NULL) {
		BIO_printf(bio_err,"%s is an unsupported message digest type\n",md);
		goto err;
	}

	if (req) {
		if ((email_dn == 1) && ((tmp_email_dn=NCONF_get_string(conf,
			section,ENV_DEFAULT_EMAIL_DN)) != NULL )) {
			if(strcmp(tmp_email_dn,"no") == 0)
				email_dn=0;
		}
		if (verbose)
			BIO_printf(bio_err,"message digest is %s\n",
				OBJ_nid2ln(dgst->type));
		if ((policy == NULL) && ((policy=NCONF_get_string(conf,
			section,ENV_POLICY)) == NULL)) {
			lookup_fail(section,ENV_POLICY);
			goto err;
		}
		if (verbose)
			BIO_printf(bio_err,"policy is %s\n",policy);

		if ((serialfile=NCONF_get_string(conf,section,ENV_SERIAL))
			== NULL) {
			lookup_fail(section,ENV_SERIAL);
			goto err;
		}

		if (!extconf) {
			/* no '-extfile' option, so we look for extensions
			 * in the main configuration file */
			if (!extensions) {
				extensions=NCONF_get_string(conf,section,
								ENV_EXTENSIONS);
				if (!extensions)
					ERR_clear_error();
			}
			if (extensions) {
				/* Check syntax of file */
				X509V3_CTX ctx;
				X509V3_set_ctx_test(&ctx);
				X509V3_set_nconf(&ctx, conf);
				if (!X509V3_EXT_add_nconf(conf, &ctx, extensions, NULL)) {
					BIO_printf(bio_err,
				 	"Error Loading extension section %s\n",
								 extensions);
					ret = 1;
					goto err;
				}
			}
		}

		if (startdate == NULL) {
			startdate=NCONF_get_string(conf,section,
				ENV_DEFAULT_STARTDATE);
			if (startdate == NULL)
				ERR_clear_error();
		}
		if (startdate && !ASN1_TIME_set_string(NULL, startdate)) {
			BIO_printf(bio_err,"start date is invalid, it should be YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ\n");
			goto err;
		}
		if (startdate == NULL) startdate="today";

		if (enddate == NULL) {
			enddate=NCONF_get_string(conf,section,
				ENV_DEFAULT_ENDDATE);
			if (enddate == NULL) ERR_clear_error();
		}
		if (enddate && !ASN1_TIME_set_string(NULL, enddate)) {
			BIO_printf(bio_err,"end date is invalid, it should be YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ\n");
			goto err;
		}

		if (days == 0) {
			if(!NCONF_get_number(conf,section, ENV_DEFAULT_DAYS, &days))
				days = 0;
		}
		if (!enddate && (days == 0)) {
			BIO_printf(bio_err,"cannot lookup how many days to certify for\n");
			goto err;
		}

		if ((serial=load_serial(serialfile, create_ser, NULL)) == NULL) {
			BIO_printf(bio_err,"error while loading serial number\n");
			goto err;
		}
		if (verbose) {
			if (BN_is_zero(serial))
				BIO_printf(bio_err,"next serial number is 00\n");
			else
				{
				if ((f=BN_bn2hex(serial)) == NULL) goto err;
				BIO_printf(bio_err,"next serial number is %s\n",f);
				OPENSSL_free(f);
				}
		}

		if ((attribs=NCONF_get_section(conf,policy)) == NULL) {
			BIO_printf(bio_err,"unable to find 'section' for %s\n",policy);
			goto err;
		}

		if ((cert_sk=sk_X509_new_null()) == NULL) {
			BIO_printf(bio_err,"Memory allocation failure\n");
			goto err;
		}

		if (inptr != NULL) {
			total++;
			j=certify(&x,inptr,pkey,x509p,dgst,sigopts, attribs,db,
				serial,subj,chtype,multirdn,email_dn,startdate,enddate,days,batch,
				extensions,conf,verbose, certopt, nameopt,
				default_op, ext_copy, selfsign, p10len);
			if (j <= 0) goto err;
			if (j > 0) {
				total_done++;
				BIO_printf(bio_err,"\n");
				if (!BN_add_word(serial,1)) goto err;
				if (!sk_X509_push(cert_sk,x)) {
					BIO_printf(bio_err,"Memory allocation failure\n");
					goto err;
				}
			}
		}
		/* we have a stack of newly certified certificates
		 * and a data base and serial number that need
		 * updating */

		if (sk_X509_num(cert_sk) > 0) {
			BIO_printf(bio_err,"Write out database with %d new entries\n",sk_X509_num(cert_sk));

			if (!save_serial(serialfile,"new",serial,NULL)) goto err;

			if (!save_index(dbfile, "new", db)) goto err;
		}
	
		if (verbose)
			BIO_printf(bio_err,"writing new certificates\n");
		for (i=0; i<sk_X509_num(cert_sk); i++) {
			int k;
			char *n;

			x=sk_X509_value(cert_sk,i);

			j=x->cert_info->serialNumber->length;
			p=(const char *)x->cert_info->serialNumber->data;
			

			BUF_strlcat(buf[2],"/",sizeof(buf[2]));

			n=(char *)&(buf[2][strlen(buf[2])]);
			if (j > 0) {
				for (k=0; k<j; k++) {
					if (n >= &(buf[2][sizeof(buf[2])]))
						break;
					BIO_snprintf(n,
						     &buf[2][0] + sizeof(buf[2]) - n,
						     "%02X",(unsigned char)*(p++));
					n+=2;
				}
			}
			else {
				*(n++)='0';
				*(n++)='0';
			}
			*(n++)='.'; *(n++)='p'; *(n++)='e'; *(n++)='m';
			*n='\0';
			if (verbose)
				BIO_printf(bio_err,"writing %s\n",buf[2]);

			if (!notext)X509_print(Cout,x);
			PEM_write_bio_X509(Cout,x);
		}

		if (sk_X509_num(cert_sk)) {
			/* Rename the database and the serial file */
			if (!rotate_serial(serialfile,"new","old")) goto err;
#ifndef WIN32
			if (!rotate_index(dbfile,"new","old")) goto err;
#endif 
			BIO_printf(bio_err,"Data Base Updated\n");
		}
	}

	//At this point we're not pkcs7, convert to pkcs7
	p7out = ossl_get_certs_pkcs7(Cout);
	if (!p7out) {
	    printf("\nossl_get_certs_pkcs7 failed");
	    goto err;
	}
	retval = p7out;

err:
	if(tofree)
		OPENSSL_free(tofree);
	//BIO_free_all(Cout);
	BIO_free_all(out);
	BIO_free_all(in);

	if (cert_sk)
		sk_X509_pop_free(cert_sk,X509_free);

	if (ret) ERR_print_errors(bio_err);
	if (free_key && key)
		OPENSSL_free(key);
	BN_free(serial);
	BN_free(crlnumber);
	free_index(db);
#ifndef WIN32
	if (sigopts)
		sk_OPENSSL_STRING_free(sigopts);
#endif 
	EVP_PKEY_free(pkey);
	if (x509) X509_free(x509);
	X509_CRL_free(crl);
	NCONF_free(conf);
	NCONF_free(extconf);
	OBJ_cleanup();
	return retval;
}




/*
 * Utility function to take a list of certs in a BIO and
 * convert it to a stack of X509 records.
 */
static int ossl_add_certs_from_BIO(STACK_OF(X509) *stack, BIO *in)
{
    int count=0;
    int ret= -1;
    STACK_OF(X509_INFO) *sk=NULL;
    X509_INFO *xi;


    /* This loads from a file, a stack of x509/crl/pkey sets */
    sk=PEM_X509_INFO_read_bio(in,NULL,NULL,NULL);
    if (sk == NULL) {
	printf("\nerror reading certs from BIO\n");
	goto end;
    }

    /* scan over it and pull out the CRL's */
    while (sk_X509_INFO_num(sk)) {
	xi=sk_X509_INFO_shift(sk);
	if (xi->x509 != NULL) {
	    sk_X509_push(stack,xi->x509);
	    xi->x509=NULL;
	    count++;
	}
	X509_INFO_free(xi);
    }

    ret=count;
end:
    /* never need to OPENSSL_free x */
    if (in != NULL) BIO_free(in);
    if (sk != NULL) sk_X509_INFO_free(sk);
    return(ret);
}


/*
 * This utility function takes a list of certificate that hav been written 
 * to a BIO, reads the BIO, and converts it to a pkcs7 certificate.
 * The input form is PEM encoded X509 certificates in a BIO.
 * The pkcs7 data is then written to a new BIO and returned to the
 * caller.
 */
static BIO * ossl_get_certs_pkcs7(BIO *in)
{
    STACK_OF(X509) *cert_stack=NULL;
    PKCS7_SIGNED *p7s = NULL;
    PKCS7 *p7 = NULL;
    BIO *out;
    BIO *b64;
    int rv = 0;


    //FIXME: error handling and memory leaks needs to be
    //       addressed here.
    if ((p7=PKCS7_new()) == NULL) {
	printf("\npkcs7_new failed in %s", __FUNCTION__);
        return NULL;
    }
    if ((p7s=PKCS7_SIGNED_new()) == NULL) { 
	printf("\npkcs7_signed_new failed in %s", __FUNCTION__);
        return NULL;
    }
    p7->type=OBJ_nid2obj(NID_pkcs7_signed);
    p7->d.sign=p7s;
    p7s->contents->type=OBJ_nid2obj(NID_pkcs7_data);
    if (!ASN1_INTEGER_set(p7s->version,1)) {
	printf("\nASN1_integer_set failed in %s", __FUNCTION__);
	return NULL;
    }

    if ((cert_stack=sk_X509_new_null()) == NULL) {
	printf("\nstack mallock failed in %s", __FUNCTION__);
        return NULL;
    }
    p7s->cert=cert_stack;

    if (ossl_add_certs_from_BIO(cert_stack, in) < 0) {
	printf("\nerror loading certificates\n");
        ERR_print_errors(bio_err);
	return NULL;
    }

#if 0
    //Output PEM PKCS7 cert
    //This is the old revision 02 draft method
    out = BIO_new(BIO_s_mem());
    if (!out) {
	printf("\nBIO_new failed\n");
        return NULL;
    }
    rv = PEM_write_bio_PKCS7(out,p7);
#endif

    //Output BASE64 encoded ASN.1 (DER) PKCS7 cert
    b64 = BIO_new(BIO_f_base64());
    out = BIO_new(BIO_s_mem());
    if (!out) {
	printf("\nBIO_new failed\n");
        return NULL;
    }
    out = BIO_push(b64, out);
    rv = i2d_PKCS7_bio(out,p7);
    (void)BIO_flush(out);
    if (!rv) {
	printf("\nerror in PEM_write_bio_PKCS7\n");
        ERR_print_errors(bio_err);
	return NULL;
    }
    if (p7 != NULL) PKCS7_free(p7);

    return out;
}

