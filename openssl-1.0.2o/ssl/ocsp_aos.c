/* Copyright 2019 ALE USA Inc.*/

#include <openssl/ocsp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <string.h>
#include <unistd.h>
#include "ocsp_aos.h"

#ifndef AOS_SYSTEM_CA_PATH
#define AOS_SYSTEM_CA_PATH "/flash/switch/ca.d"
#endif

unsigned int aos_ocsp_debug = 1;

static int prepareRequest(OCSP_REQUEST **req, X509 *cert, const EVP_MD *cert_id_md,X509 *issuer,
        STACK_OF(OCSP_CERTID) *ids);
static OCSP_RESPONSE * queryResponder(BIO *err, BIO *cbio, char *path,
        char *host, OCSP_REQUEST *req, int req_timeout);
static OCSP_RESPONSE * sendRequest(BIO *err, OCSP_REQUEST *req,
        char *host, char *path, char *port, int use_ssl,
        int req_timeout);

static int parseResponse(OCSP_REQUEST *req, OCSP_RESPONSE *resp);

static void aos_debug_print(const char *fn, int line, const char *format, ...);

static void aos_debug_print(const char *fn, int line, const char *format, ...)
{
    char buffer[256] = {0};
    va_list ap;
    if(aos_ocsp_debug)
    {
        va_start(ap, format);
        vsnprintf(buffer, sizeof(buffer), format, ap);
        printf("%s:%d -- %s\n", fn, line, buffer);
        va_end(ap);
    }
    else
        return;
}

X509 *getIssuerCert(SSL_CTX *ctx, X509 *pcert)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX *store_ctx = NULL;
    X509 *issuer = NULL;
    aos_debug_print(__FUNCTION__, __LINE__, "Testing my aos_debug_print");
    if(!ctx)
    {
        return NULL;
    }
	store = SSL_CTX_get_cert_store(ctx);
    if(NULL == (store_ctx = X509_STORE_CTX_new()))
    {
        return NULL;
    }
    X509_STORE_CTX_init(store_ctx, store, pcert, NULL);
    if(1 != X509_STORE_CTX_get1_issuer(&issuer, store_ctx, pcert))
    {
        X509_STORE_CTX_free(store_ctx);
        return NULL;
    }
    X509_STORE_CTX_free(store_ctx);
    return issuer;
}
#if 0
X509*  getIssuerCert(X509 *pcert)
{
    X509 *issuer_cert = NULL;
    char hash_buf[32] = {0};
    unsigned long hash = 0;
    BIO *certbio = NULL;


    /* Get hash name of the issuer */
    hash = X509_NAME_hash(pcert->cert_info->issuer);
    snprintf(hash_buf, sizeof(hash_buf), "%s/%lx.0", AOS_SYSTEM_CA_PATH, hash);
    /* We need to check if the hash link file exists at */
    /* ca directory */
    if(access(hash_buf, F_OK) != 0)
    {
        printf("Could not find file: %s\n", hash_buf);
        return NULL;
    }

   if(NULL == ( certbio = BIO_new(BIO_s_file()) ))
   {
       printf("Could not initialize BIO stream\n");
       return NULL;
   }

   if(0 == BIO_read_filename(certbio, hash_buf))
   {
       printf("Could not read file into BIO stream\n");
       BIO_free_all(certbio);
       return NULL;
   }

   if ( NULL == (issuer_cert = PEM_read_bio_X509(certbio, NULL, 0, NULL)))
   {
       printf("Could not read certificate from BIO stream\n");
       BIO_free_all(certbio);
       return NULL;
   }

   BIO_free_all(certbio);
   return issuer_cert;
}
#endif
/*
 *
 */
static int prepareRequest(OCSP_REQUEST **req, X509 *cert, const EVP_MD *cert_id_md,X509 *issuer,
        STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;
    if(!issuer)
    {
        aos_debug_print(__FUNCTION__, __LINE__, "No issuer certificate specified");
        return 0;
    }
    if(!*req) *req = OCSP_REQUEST_new();
    if(!*req) goto err;
    id = OCSP_cert_to_id(cert_id_md, cert, issuer);
    if(!id || !sk_OCSP_CERTID_push(ids, id)) goto err;
    if(!OCSP_request_add0_id(*req, id)) goto err;
    return 1;

err:
    aos_debug_print(__FUNCTION__, __LINE__,"Error Creating OCSP request\n");
    return 0;
}
/*
 *
 */
static OCSP_RESPONSE * queryResponder(BIO *err, BIO *cbio, char *path,
        char *host, OCSP_REQUEST *req, int req_timeout)
{
    int fd;
    int rv;
    OCSP_REQ_CTX *ctx = NULL;
    OCSP_RESPONSE *rsp = NULL;
    fd_set confds;
    struct timeval tv;

    if (req_timeout != -1)
        BIO_set_nbio(cbio, 1);

    rv = BIO_do_connect(cbio);

    if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio)))
    {
        aos_debug_print(__FUNCTION__, __LINE__,"Error connecting BIO\n");
        return NULL;
    }

    if (BIO_get_fd(cbio, &fd) <= 0)
    {
        aos_debug_print(__FUNCTION__, __LINE__,"Can't get connection fd\n");
        goto err;
    }

    if (req_timeout != -1 && rv <= 0)
    {
        FD_ZERO(&confds);
        FD_SET(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        rv = select(fd + 1, NULL, &confds, NULL, &tv);
        if (rv == 0)
        {
            aos_debug_print(__FUNCTION__, __LINE__,"Timeout on connect\n");
            return NULL;
        }
    }

    ctx = OCSP_sendreq_new(cbio, path, NULL, -1);
    if (!ctx)
    {
        aos_debug_print(__FUNCTION__, __LINE__,"OCSP_sendreq_new returned NULL\n");
        return NULL;
    }

    if (!OCSP_REQ_CTX_add1_header(ctx, "Host", host))
    {
        aos_debug_print(__FUNCTION__, __LINE__,"OCSP_REQ_CTX_add1_header failed\n");
        goto err;
    }

    if (!OCSP_REQ_CTX_set1_req(ctx, req))
    {
        aos_debug_print(__FUNCTION__, __LINE__,"OCSP_REQ_CTX_set1_req failed\n");
        goto err;
    }

    for (;;)
    {
        rv = OCSP_sendreq_nbio(&rsp, ctx);

        if(rv != -1)
            break;

        if (req_timeout == -1)
            continue;
        FD_ZERO(&confds);
        FD_SET(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        if (BIO_should_read(cbio))
            rv = select(fd + 1, &confds, NULL, NULL, &tv);
        else if (BIO_should_write(cbio))
            rv = select(fd + 1, NULL, &confds, NULL, &tv);
        else
        {
            aos_debug_print(__FUNCTION__, __LINE__,"Unexpected retry condition\n");
            goto err;
        }
        if (rv == 0)
        {
            aos_debug_print(__FUNCTION__, __LINE__,"Timeout on request\n");
            break;
        }
        if (rv == -1)
        {
            aos_debug_print(__FUNCTION__, __LINE__,"Select error\n");
            break;
        }

    }
err:
    if (ctx)
        OCSP_REQ_CTX_free(ctx);

    return rsp;
}
/*
 *
 */
static OCSP_RESPONSE * sendRequest(BIO *err, OCSP_REQUEST *req,
        char *host, char *path, char *port, int use_ssl,
        int req_timeout)
{
    BIO *cbio = NULL;
    OCSP_RESPONSE *resp = NULL;
    cbio = BIO_new_connect(host);
    if (cbio && port && use_ssl==0)
    {
        BIO_set_conn_port(cbio, port);
        resp = queryResponder(err, cbio, path, host, req, req_timeout);
        if (!resp)
            aos_debug_print(__FUNCTION__, __LINE__,"Error querying OCSP responder\n");
    }
    if (cbio)
        BIO_free_all(cbio);
    return resp;
}
/*
 *
 */
static int parseResponse(OCSP_REQUEST *req, OCSP_RESPONSE *resp)
{
    int is_revoked = -1;
    int i = 0;
    OCSP_BASICRESP *br = NULL;
    OCSP_CERTSTATUS *cst = NULL;
    OCSP_RESPBYTES *rb = resp->responseBytes;
    OCSP_SINGLERESP *single = NULL; 

    if (rb && OBJ_obj2nid(rb->responseType) == NID_id_pkix_OCSP_basic)
    {
        if(!(br = OCSP_response_get1_basic(resp)))
        {
            aos_debug_print(__FUNCTION__, __LINE__,"OCSP_response_get1_basic failed\n");
            goto err;
        }

        if(0 >= OCSP_check_nonce(req, br))
        {
            aos_debug_print(__FUNCTION__, __LINE__,"OCSP_check_nonce failed\n");
            goto err;
        }

        for (i = 0; i < OCSP_resp_count(br); i++)
        {
            single = OCSP_resp_get0(br, i);
            cst = single->certStatus;
            if (cst->type == V_OCSP_CERTSTATUS_REVOKED)
            {
                is_revoked = 1;
            }
            else if (cst->type == V_OCSP_CERTSTATUS_GOOD)
            {
                is_revoked = 0;
            }
        }
    }
err:
    OCSP_BASICRESP_free(br);
    return is_revoked;
}
/*
 *
 */
int checkCertOCSP(X509 *x509, X509 *issuer)
{
    int is_revoked=-1;
    int j = 0;

    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE|BIO_FP_TEXT);
    BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE|BIO_FP_TEXT);

    if (issuer)
    {
        /*build ocsp request*/
        OCSP_REQUEST *req = NULL;
        STACK_OF(OPENSSL_STRING) *ocsp_list = NULL;
        STACK_OF(OCSP_CERTID) *ids = sk_OCSP_CERTID_new_null();
        const EVP_MD *cert_id_md = EVP_sha1();
        prepareRequest(&req, x509, cert_id_md, issuer, ids);

        /*loop through OCSP urls*/
        ocsp_list = X509_get1_ocsp(x509);
        for (j = 0; j < sk_OPENSSL_STRING_num(ocsp_list) && is_revoked==-1; j++)
        {
            char *host = NULL, *port = NULL, *path = NULL; 
            int use_ssl, req_timeout = 30;

            char *ocsp_url = sk_OPENSSL_STRING_value(ocsp_list, j);
            if (OCSP_parse_url(ocsp_url, &host, &port, &path, &use_ssl) && !use_ssl)
            {
                /*send ocsp request*/
                OCSP_RESPONSE *resp = sendRequest(bio_err, req, host, path, port, use_ssl, req_timeout);
                if (resp)
                {
                    /*see crypto/ocsp/ocsp_prn.c for examples parsing OCSP responses*/
                    int responder_status = OCSP_response_status(resp);

                    /*parse response*/
                    if (resp && responder_status == OCSP_RESPONSE_STATUS_SUCCESSFUL)
                    {
                        is_revoked = parseResponse(req, resp);
                    }
                    else if(responder_status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
                    {
                        switch(responder_status)
                        {
                            /* log error */
                            case OCSP_RESPONSE_STATUS_MALFORMEDREQUEST:
                                aos_debug_print(__FUNCTION__, __LINE__,"OCSP request is malformed\n");
                                break;
                            case OCSP_RESPONSE_STATUS_INTERNALERROR:
                                aos_debug_print(__FUNCTION__, __LINE__,"OCSP internal error\n");
                                break;
                            case OCSP_RESPONSE_STATUS_TRYLATER:
                                aos_debug_print(__FUNCTION__, __LINE__,"OCSP responder busy, try latter\n");
                                break;
                            case OCSP_RESPONSE_STATUS_SIGREQUIRED:
                                aos_debug_print(__FUNCTION__, __LINE__,"OCSP request is not signed\n");
                                break;
                            case OCSP_RESPONSE_STATUS_UNAUTHORIZED:
                                aos_debug_print(__FUNCTION__, __LINE__,"OCSP client is unauthorised\n");
                                break;
                        }
                    }
                    OCSP_RESPONSE_free(resp);
                }
            }
            OPENSSL_free(host);
            OPENSSL_free(path);
            OPENSSL_free(port);
        }
        X509_email_free(ocsp_list);
        OCSP_REQUEST_free(req);
    }

    BIO_free(bio_out);
    BIO_free(bio_err);
    return is_revoked;
}
/*
 *
 */
char *getCertCommonName(X509 *pcert)
{
    X509_NAME *subject = X509_get_subject_name(pcert);
    int subject_position = X509_NAME_get_index_by_NID(subject, NID_commonName, 0);
    X509_NAME_ENTRY *entry = subject_position==-1 ? NULL : X509_NAME_get_entry(subject, subject_position);
    ASN1_STRING *d = X509_NAME_ENTRY_get_data(entry);
    if(d && d->data)
        return (char*)d->data;
    else
        return (char*)NULL;
}

void set_aos_ocsp_debug(int val)
{
    aos_ocsp_debug = val;
}
