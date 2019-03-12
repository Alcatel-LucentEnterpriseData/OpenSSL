/* Copyright 2019 ALE USA Inc.*/

#ifndef HEADER_OCSP_H


#define HEADER_OCSP_H

#ifdef  __cplusplus
extern "C" {
#endif
int checkCertOCSP(X509 *x509, X509 *issuer);    
char *getCertCommonName(X509 *pcert);   
X509 *getIssuerCert(SSL_CTX *ctx, X509 *pcert);     
void set_aos_ocsp_debug(int val);   
#ifdef  __cplusplus
}
#endif


#endif  /*HEADER_OCSP_H*/
