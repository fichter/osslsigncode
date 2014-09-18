/* 
   OpenSSL based Authenticode signing for PE files and Java CAB's. 

     Copyright (C) 2005-2008 mfive <mfive@users.sourceforge.net>


   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

static const char *rcsid = "$Id: osslsigncode.c,v 1.3.1 2009/08/07 10:00:00 mfive Exp $";

/*
   Implemented with good help from:

   * Peter Gutmann's analysis of Authenticode:
        
      http://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt
   
   * MS CAB SDK documentation
      
      http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dncabsdk/html/cabdl.asp

   * MS PE/COFF documentation

      http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx

   * tail -c, tcpdump, mimencode & openssl asn1parse :)

*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#if 0
#include <openssl/pem.h>
#endif
#include <openssl/asn1t.h>

#ifdef HAVE_CURL
#include <curl/curl.h>
#endif

/* MS Authenticode object ids */
#define SPC_INDIRECT_DATA_OBJID  "1.3.6.1.4.1.311.2.1.4"
#define SPC_STATEMENT_TYPE_OBJID "1.3.6.1.4.1.311.2.1.11"
#define SPC_SP_OPUS_INFO_OBJID   "1.3.6.1.4.1.311.2.1.12"
#define SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID "1.3.6.1.4.1.311.2.1.21"
#define SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID "1.3.6.1.4.1.311.2.1.22"
#define SPC_MS_JAVA_SOMETHING    "1.3.6.1.4.1.311.15.1"
#define SPC_PE_IMAGE_DATA_OBJID  "1.3.6.1.4.1.311.2.1.15"
#define SPC_CAB_DATA_OBJID       "1.3.6.1.4.1.311.2.1.25"
#define SPC_TIME_STAMP_REQUEST_OBJID "1.3.6.1.4.1.311.3.2.1"

/* 1.3.6.1.4.1.311.4... MS Crypto 2.0 stuff... */


/* 
   ASN1 definitions - they are probably not correct, but
   they are enough for our purposes.
*/

typedef struct {
    ASN1_TYPE *desc;
    ASN1_TYPE *url;

    ASN1_TYPE desc_s;
    ASN1_TYPE url_s;
} OpusInfo;

DECLARE_ASN1_FUNCTIONS(OpusInfo)

ASN1_SEQUENCE(OpusInfo) = {
    ASN1_EXP_OPT(OpusInfo, desc, ASN1_ANY, 0),
    ASN1_EXP_OPT(OpusInfo, url, ASN1_ANY, 1)
} ASN1_SEQUENCE_END(OpusInfo)

IMPLEMENT_ASN1_FUNCTIONS(OpusInfo)


#ifdef HAVE_CURL

typedef struct {
    ASN1_OBJECT *type;
    ASN1_OCTET_STRING *signature;
} SpcTimeStampRequestBlob;

DECLARE_ASN1_FUNCTIONS(SpcTimeStampRequestBlob)

ASN1_SEQUENCE(SpcTimeStampRequestBlob) = {
    ASN1_SIMPLE(SpcTimeStampRequestBlob, type, ASN1_OBJECT),
    ASN1_EXP_OPT(SpcTimeStampRequestBlob, signature, ASN1_OCTET_STRING, 0)
} ASN1_SEQUENCE_END(SpcTimeStampRequestBlob)

IMPLEMENT_ASN1_FUNCTIONS(SpcTimeStampRequestBlob)



typedef struct {
    ASN1_OBJECT *type;
    SpcTimeStampRequestBlob *blob;
} SpcTimeStampRequest;

DECLARE_ASN1_FUNCTIONS(SpcTimeStampRequest)

ASN1_SEQUENCE(SpcTimeStampRequest) = {
    ASN1_SIMPLE(SpcTimeStampRequest, type, ASN1_OBJECT),
    ASN1_SIMPLE(SpcTimeStampRequest, blob, SpcTimeStampRequestBlob)
} ASN1_SEQUENCE_END(SpcTimeStampRequest)

IMPLEMENT_ASN1_FUNCTIONS(SpcTimeStampRequest)

#endif /* HAVE_CURL */


static OpusInfo* createOpus(char *desc, char *url) 
{
    OpusInfo *info;
    ASN1_STRING *astr;
    u_char *buf;
    int i, len;
    
    info = OpusInfo_new();

    if (desc) {
        /* XXX: proper unicode conversion... */
        len = strlen(desc);
        buf = malloc(len*2);
        for (i=0; i<len; i++) {
            buf[i*2]   = 0x00;
            buf[i*2+1] = desc[i];
        }
        astr = ASN1_STRING_new();
        ASN1_STRING_set(astr, buf, len*2);
        len = i2d_ASN1_bytes
	    (astr, NULL, V_ASN1_UNIVERSAL, V_ASN1_CONTEXT_SPECIFIC);
        buf = OPENSSL_malloc(len);
        i2d_ASN1_bytes
	    (astr, &buf, V_ASN1_UNIVERSAL, V_ASN1_CONTEXT_SPECIFIC);
        buf -= len;
        ASN1_STRING_set(astr, buf, len);
        OPENSSL_free(buf);
        info->desc = &info->desc_s;
        info->desc->type = V_ASN1_SEQUENCE;
        info->desc->value.sequence = astr;
    }

    if (url) {
        astr = ASN1_STRING_new();
        ASN1_STRING_set(astr, url, strlen(url));
        len = i2d_ASN1_bytes
	    (astr, NULL, V_ASN1_UNIVERSAL, V_ASN1_CONTEXT_SPECIFIC);
        buf = OPENSSL_malloc(len);
        i2d_ASN1_bytes
	    (astr, &buf, V_ASN1_UNIVERSAL, V_ASN1_CONTEXT_SPECIFIC);
        buf -= len;
        ASN1_STRING_set(astr, buf, len);
        OPENSSL_free(buf);
        info->url = &info->url_s;
        info->url->type = V_ASN1_SEQUENCE;
        info->url->value.sequence = astr;
    }
    return info;
}

#ifdef HAVE_CURL

static size_t curl_write( void *ptr, size_t sz, size_t nmemb, void *stream)
{
    return BIO_write((BIO*)stream, ptr, sz*nmemb);
}

/*
  A timestamp request looks like this:

  POST <someurl> HTTP/1.1
  Content-Type: application/octet-stream
  Content-Length: ...
  Accept: application/octet-stream
  User-Agent: Transport
  Host: ...
  Cache-Control: no-cache
  
  <base64encoded blob>

  
  .. and the blob has the following ASN1 structure:
  
   0:d=0  hl=4 l= 291 cons: SEQUENCE          
   4:d=1  hl=2 l=  10 prim:  OBJECT            :1.3.6.1.4.1.311.3.2.1
  16:d=1  hl=4 l= 275 cons:  SEQUENCE          
  20:d=2  hl=2 l=   9 prim:   OBJECT            :pkcs7-data
  31:d=2  hl=4 l= 260 cons:   cont [ 0 ]        
  35:d=3  hl=4 l= 256 prim:    OCTET STRING      
           <signature>



  .. and it returns a base64 encoded PKCS#7 structure.

 */

static int add_timestamp(PKCS7 *sig, char *url, char *proxy) 
{
    CURL *curl;
    struct curl_slist *slist = NULL;
    CURLcode c;
    BIO *bout, *bin, *b64;
    u_char *p;
    int len;
    SpcTimeStampRequest *req;
    PKCS7_SIGNER_INFO *si = 
      sk_PKCS7_SIGNER_INFO_value
      (sig->d.sign->signer_info, 0);

    if (!url) return -1;

    curl = curl_easy_init();
 
    if (proxy) {
	curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
	if (!strncmp("http:", proxy, 5))
	    curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
	if (!strncmp("socks:", proxy, 6))
	    curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
/*    curl_easy_setopt(curl, CURLOPT_VERBOSE, 42);  */

    slist = curl_slist_append(slist, "Content-Type: application/octet-stream");
    slist = curl_slist_append(slist, "Accept: application/octet-stream");
    slist = curl_slist_append(slist, "User-Agent: Transport");
    slist = curl_slist_append(slist, "Cache-Control: no-cache");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

    req = SpcTimeStampRequest_new();
    req->type = OBJ_txt2obj(SPC_TIME_STAMP_REQUEST_OBJID, 1);
    req->blob = SpcTimeStampRequestBlob_new();
    req->blob->type = OBJ_nid2obj(NID_pkcs7_data);
    req->blob->signature = si->enc_digest;

    len = i2d_SpcTimeStampRequest(req, NULL);
    p = OPENSSL_malloc(len);
    len = i2d_SpcTimeStampRequest(req, &p);
    p -= len;

    bout = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    bout = BIO_push(b64, bout);
    BIO_write(bout, p, len);
    (void)BIO_flush(bout);
    OPENSSL_free(p);

    len = BIO_get_mem_data(bout, &p);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, p);

    bin = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(bin, 0);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, bin);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);

    c = curl_easy_perform(curl);

    curl_slist_free_all(slist);
    BIO_free_all(bout);

    if (c) {
	fprintf(stderr, "CURL failure: %s\n", curl_easy_strerror(c));
    } else {
	PKCS7 *p7;
	int i;
	PKCS7_SIGNER_INFO *info;
	ASN1_STRING *astr;

	(void)BIO_flush(bin);
	b64 = BIO_new(BIO_f_base64());
	bin = BIO_push(b64, bin);
	p7 = d2i_PKCS7_bio(bin, NULL);
	if (p7 == NULL) {
	  fprintf(stderr, "Failed to convert timestamp reply\n");
	  ERR_print_errors_fp(stderr);
	  return -1;
	}

	for(i = sk_X509_num(p7->d.sign->cert)-1; i>=0; i--)
	  PKCS7_add_certificate(sig, sk_X509_value(p7->d.sign->cert, i));

	info = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
	if (((len = i2d_PKCS7_SIGNER_INFO(info, NULL)) <= 0) ||
	    (p = OPENSSL_malloc(len)) == NULL) {
	  fprintf(stderr, "Failed to convert signer info: %d\n", len);
	  ERR_print_errors_fp(stderr);
	  return -1;
	}
	len = i2d_PKCS7_SIGNER_INFO(info, &p);
	p -= len;
	astr = ASN1_STRING_new();
	ASN1_STRING_set(astr, p, len);
	PKCS7_add_attribute
	  (si, NID_pkcs9_countersignature,
	   V_ASN1_SEQUENCE, astr);
    }

    BIO_free_all(bin);
    curl_easy_cleanup(curl);

    return (int)c;
}
#endif /* HAVE_CURL */


static void usage(const char *argv0) 
{
    fprintf(stderr, 
            "Usage: %s [ --version | -v ]\n\t-spc <spcfile> -key <keyfile>\n"
            "\t[ -n <desc> ] [ -i <url> ] [-jp <level>]\n"
#ifdef HAVE_CURL
	    "\t[ -t <timestampurl> [ -p <proxy> ]]\n"
#endif
	    "\t-in <infile> -out <outfile>\n",
            argv0);
    exit(-1);
}

#define DO_EXIT_0(x)    { fputs(x, stderr); goto err_cleanup; }
#define DO_EXIT_1(x, y) { fprintf(stderr, x, y); goto err_cleanup; }

#define GET_UINT16_LE(p) (((u_char*)(p))[0] | (((u_char*)(p))[1]<<8))

#define GET_UINT32_LE(p) (((u_char*)(p))[0] | (((u_char*)(p))[1]<<8) | \
                   (((u_char*)(p))[2]<<16) | (((u_char*)(p))[3]<<24))

#define PUT_UINT32_LE(i,p) \
        ((u_char*)(p))[0] = (i) & 0xff; \
        ((u_char*)(p))[1] = ((i)>>8) & 0xff; \
        ((u_char*)(p))[2] = ((i)>>16) & 0xff; \
        ((u_char*)(p))[3] = ((i)>>24) & 0xff


#ifdef HACK_OPENSSL
ASN1_TYPE *PKCS7_get_signed_attribute(PKCS7_SIGNER_INFO *si, int nid) 
    /* ARGSUSED */
{
    /* Ehhhm. Hack. The PKCS7 sign method adds NID_pkcs9_signingTime if
       it isn't there. But we don't want it since M$ barfs on it. 
       Sooooo... let's pretend it's here. */
    return (ASN1_TYPE*)0xdeadbeef;
}
#endif

int main(int argc, char **argv) 
{
    BIO *btmp, *sigdata, *hash, *outdata;
    PKCS7 *p7, *sig;
    EVP_PKEY *pkey;
    PKCS7_SIGNER_INFO *si;
    ASN1_TYPE dummy;
    ASN1_STRING *astr;

    const char *argv0 = argv[0];
    static char buf[64*1024];
    char *spcfile, *keyfile, *infile, *outfile, *desc, *url, *indata;
#ifdef HAVE_CURL 
    char *turl = NULL, *proxy = NULL;
#endif
    u_char *p;
    int i, len, is_cabinet = 0, jp = -1, fd = -1, pe32plus = 0;
    unsigned int tmp, peheader = 0, padlen;
    struct stat st;

    static u_char spcIndirectDataContext_blob_cab[] = {
        0x30, 0x50, 0x30, 0x2c, 
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x19,
        0xa2, 0x1e, 0x80, 0x1c, 
        0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 
        0x00, 0x74, 0x00, 0x65, 0x00, 0x3e, 0x00, 0x3e, 0x00, 0x3e, 
        0x30, 0x20, 0x30, 0x0c, 
        0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 
        0x05, 0x00, 
        0x04, 0x10 /* + md5 hash */
    };

    static u_char spcIndirectDataContext_blob_pe[] = {
        0x30, 0x57, 0x30, 0x33, 
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f,
        0x30, 0x25, 0x03, 0x01, 0x00, 0xa0, 0x20, 0xa2, 0x1e, 0x80, 0x1c, 
        0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 
        0x00, 0x74, 0x00, 0x65, 0x00, 0x3e, 0x00, 0x3e, 0x00, 0x3e, 
        0x30, 0x20, 0x30, 0x0c, 
        0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 
        0x05, 0x00, 
        0x04, 0x10 /* + md5 hash */
    };
    
    u_char purpose[] = {
        0x30, 0x0c,
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x16 
    };
    
    spcfile = keyfile = infile = outfile = desc = url = NULL;
    hash = outdata = NULL;

    for (argc--,argv++; argc >= 1; argc--,argv++) {
        if (!strcmp(*argv, "-spc")) {
            if (--argc < 1) usage(argv0);
            spcfile = *(++argv);
        } else if (!strcmp(*argv, "-key")) {
            if (--argc < 1) usage(argv0);
            keyfile = *(++argv);
        } else if (!strcmp(*argv, "-n")) {
            if (--argc < 1) usage(argv0);
            desc = *(++argv);
        } else if (!strcmp(*argv, "-i")) {
            if (--argc < 1) usage(argv0);
            url = *(++argv);
        } else if (!strcmp(*argv, "-in")) {
            if (--argc < 1) usage(argv0);
            infile = *(++argv);
        } else if (!strcmp(*argv, "-out")) {
            if (--argc < 1) usage(argv0);
            outfile = *(++argv);
#ifdef HAVE_CURL
        } else if (!strcmp(*argv, "-t")) {
            if (--argc < 1) usage(argv0);
            turl = *(++argv);
        } else if (!strcmp(*argv, "-p")) {
            if (--argc < 1) usage(argv0);
            proxy = *(++argv);
#endif
        } else if (!strcmp(*argv, "-v") || !strcmp(*argv, "--version")) {
            printf(PACKAGE_STRING ", using:\n\t%s\n\t%s\n\nPlease send bug-reports to "
                   PACKAGE_BUGREPORT
                   "\n\n",
                   SSLeay_version(SSLEAY_VERSION),
#ifdef HAVE_CURL
                   curl_version()
#else
                   "no libcurl available"
#endif
                );
        } else if (!strcmp(*argv, "-jp")) {
            char *ap;
            if (--argc < 1) usage(argv0);
            ap = *(++argv);
            for (i=0; ap[i]; i++) ap[i] = tolower((int)ap[i]);
            if (!strcmp(ap, "low")) {
                jp = 0;
            } else if (!strcmp(ap, "medium")) {
                jp = 1;
            } else if (!strcmp(ap, "high")) {
                jp = 2;
            }
	    if (jp != 0) usage(argv0); /* XXX */
        } else {
            fprintf(stderr, "Unknown option: %s\n", *argv);
            usage(argv0);
        }
    }

    if (!spcfile || !keyfile || !infile || !outfile)
        usage(argv0);

    /* Set up OpenSSL */
    ERR_load_crypto_strings();
    EVP_add_digest(EVP_md5());

    /* Read spc */
    if ((btmp = BIO_new_file(spcfile, "rb")) == NULL ||
        (p7 = d2i_PKCS7_bio(btmp, NULL)) == NULL) 
        DO_EXIT_1("Failed to read DER-encoded spc file: %s\n", spcfile);
    BIO_free(btmp);

    /* Read private key */
    if ((btmp = BIO_new_file(keyfile, "rb")) == NULL ||
        (pkey = d2i_PrivateKey_bio(btmp, NULL)) == NULL) 
        DO_EXIT_1("Failed to read DER-encoded private key file: %s\n", keyfile);
    BIO_free(btmp);

    /* Check if indata is cab or pe */
    if (stat(infile, &st))
        DO_EXIT_1("Failed to open file: %s\n", infile);
    
    if (st.st_size < 4)
        DO_EXIT_1("Unrecognized file type - file is too short: %s\n", infile);
    
    if ((fd = open(infile, O_RDONLY)) < 0)
        DO_EXIT_1("Failed to open file: %s\n", infile);

    indata = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (indata == NULL)
        DO_EXIT_1("Failed to open file: %s\n", infile);

    if (!memcmp(indata, "MSCF", 4))
        is_cabinet = 1;
    else if (memcmp(indata, "MZ", 2))
        DO_EXIT_1("Unrecognized file type: %s\n", infile);

    if (is_cabinet) {
        if (st.st_size < 44)
            DO_EXIT_1("Corrupt cab file - too short: %s\n", infile);
        if (indata[0x1e] != 0x00 || indata[0x1f] != 0x00)
            DO_EXIT_0("Cannot sign cab files with flag bits set!\n"); /* XXX */
    } else {
        if (st.st_size < 64)
            DO_EXIT_1("Corrupt DOS file - too short: %s\n", infile);
        peheader = GET_UINT32_LE(indata+60);
        if (st.st_size < peheader + 160)
            DO_EXIT_1("Corrupt PE file - too short: %s\n", infile);
        if (memcmp(indata+peheader, "PE\0\0", 4))
            DO_EXIT_1("Unrecognized DOS file type: %s\n", infile);
    }

    /* Create outdata file */
    outdata = BIO_new_file(outfile, "wb");
    if (outdata == NULL)
        DO_EXIT_1("Failed to create file: %s\n", outfile);
    
    hash = BIO_new(BIO_f_md());
    BIO_set_md(hash, EVP_md5());
    BIO_push(hash, outdata);
    
    if (is_cabinet) {
        unsigned short nfolders;

        u_char cabsigned[] = {
            0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 
            0xde, 0xad, 0xbe, 0xef, /* size of cab file */
            0xde, 0xad, 0xbe, 0xef, /* size of asn1 blob */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        BIO_write(hash, indata, 4);
        BIO_write(outdata, indata+4, 4);

        tmp = GET_UINT32_LE(indata+8) + 24;
        PUT_UINT32_LE(tmp, buf);
        BIO_write(hash, buf, 4);

        BIO_write(hash, indata+12, 4);

        tmp = GET_UINT32_LE(indata+16) + 24;
        PUT_UINT32_LE(tmp, buf+4);
        BIO_write(hash, buf+4, 4);

        memcpy(buf+4, indata+20, 14);
        buf[4+10] = 0x04; /* RESERVE_PRESENT */

        BIO_write(hash, buf+4, 14);
        BIO_write(outdata, indata+34, 2);

        memcpy(cabsigned+8, buf, 4);
        BIO_write(outdata, cabsigned, 20);
        BIO_write(hash, cabsigned+20, 4); /* ??? or possibly the previous 4 bytes instead? */

        nfolders = indata[26] | (indata[27] << 8);
        for (i = 36; nfolders; nfolders--, i+=8) {
            tmp = GET_UINT32_LE(indata+i);
            tmp += 24;
            PUT_UINT32_LE(tmp, buf);
            BIO_write(hash, buf, 4);
            BIO_write(hash, indata+i+4, 4);
        }

        /* Write what's left */
        BIO_write(hash, indata+i, st.st_size-i);
    } else {
	if (jp >= 0)
	    fprintf(stderr, "Warning: -jp option is only valid "
		    "for CAB files.\n");

	pe32plus = GET_UINT16_LE(indata + peheader + 24) == 0x20b ? 1 : 0;

	/* If the file has been signed already, this will let us pretend the file we are signing is
	 * only as big as the portion that exists before the signed data at the end of the file.
	 * This prevents adding more and more data to the end of the file with each signing.
	 */
	i = GET_UINT32_LE(indata + peheader + 152 + pe32plus*16);
	if( i > 0 ) st.st_size = i;

        BIO_write(hash, indata, peheader + 88);
        i = peheader + 88;
	memset(buf, 0, 4);
        BIO_write(outdata, buf, 4); /* zero out checksum */
        i += 4;
        BIO_write(hash, indata + i, 60+pe32plus*16);
        i += 60+pe32plus*16;
        BIO_write(outdata, indata + i, 8);
        i += 8;
        
        BIO_write(hash, indata + i, st.st_size - i);

	/* pad (with 0's) pe file to 8 byte boundary */
	len = 8 - st.st_size % 8;
	if (len > 0 && len != 8) {
	  memset(buf, 0, len);
	  BIO_write(hash, buf, len);
	  st.st_size += len;
	}
    }
    sig = PKCS7_new();
    PKCS7_set_type(sig, NID_pkcs7_signed);

    for (si=NULL, i=0; i<sk_X509_num(p7->d.sign->cert); i++) {
        X509 *signcert = sk_X509_value(p7->d.sign->cert, i);
        /* X509_print_fp(stdout, signcert); */
        si = PKCS7_add_signature(sig, signcert, pkey, EVP_md5());
        if (si != NULL) break;
    }

    if (si == NULL)
        DO_EXIT_0("Signing failed(PKCS7_add_signature)\n");

    /* create some MS Authenticode OIDS we need later on */
    if (!OBJ_create(SPC_STATEMENT_TYPE_OBJID, NULL, NULL) ||
        !OBJ_create(SPC_MS_JAVA_SOMETHING, NULL, NULL) ||
        !OBJ_create(SPC_SP_OPUS_INFO_OBJID, NULL, NULL)) 
        DO_EXIT_0("Failed to add objects\n");

    PKCS7_add_signed_attribute
      (si, NID_pkcs9_contentType, 
       V_ASN1_OBJECT, OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1));

    if (is_cabinet && jp >= 0) {
        const u_char *attrs = NULL;
        static const u_char java_attrs_low[] = {
            0x30, 0x06, 0x03, 0x02, 0x00, 0x01, 0x30, 0x00
        };

        switch (jp) {
            case 0:
                attrs = java_attrs_low;
                len = sizeof(java_attrs_low);
                break;
            case 1:
                /* XXX */
            case 2:
                /* XXX */
            default:
                break;
        }

        if (attrs) {
            astr = ASN1_STRING_new();
            ASN1_STRING_set(astr, attrs, len);
            PKCS7_add_signed_attribute
	      (si, OBJ_txt2nid(SPC_MS_JAVA_SOMETHING), 
	       V_ASN1_SEQUENCE, astr);
        }
    }

    /* XXX: individual code signing support */
    astr = ASN1_STRING_new();
    ASN1_STRING_set(astr, purpose, sizeof(purpose));
    PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_STATEMENT_TYPE_OBJID), 
                               V_ASN1_SEQUENCE, astr);

    if (desc || url) {
        OpusInfo *opus = createOpus(desc, url);
        if ((len = i2d_OpusInfo(opus, NULL)) <= 0 ||
            (p = OPENSSL_malloc(len)) == NULL) 
            DO_EXIT_0("Couldn't allocate memory for opus info\n");
        i2d_OpusInfo(opus, &p);
        p -= len;
        astr = ASN1_STRING_new();
        ASN1_STRING_set(astr, p, len);
            
        PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_SP_OPUS_INFO_OBJID), 
                                   V_ASN1_SEQUENCE, astr);
    }

    PKCS7_content_new(sig, NID_pkcs7_data);

#if 0
    for(i = 0; i < sk_X509_num(p7->d.sign->cert); i++)
        PKCS7_add_certificate(sig, sk_X509_value(p7->d.sign->cert, i));
#else
    for(i = sk_X509_num(p7->d.sign->cert)-1; i>=0; i--)
        PKCS7_add_certificate(sig, sk_X509_value(p7->d.sign->cert, i));
#endif
    
    if ((sigdata = PKCS7_dataInit(sig, NULL)) == NULL)
        DO_EXIT_0("Signing failed(PKCS7_dataInit)\n");

    if (is_cabinet) {
        p = (u_char*)spcIndirectDataContext_blob_cab;
        len = sizeof(spcIndirectDataContext_blob_cab);
    } else {
        p = (u_char*)spcIndirectDataContext_blob_pe;
        len = sizeof(spcIndirectDataContext_blob_pe);
    }
    
    memcpy(buf, p, len);
    i = BIO_gets(hash, buf + len, EVP_MAX_MD_SIZE);
    BIO_write(sigdata, buf+2, len-2+i);

    if (!PKCS7_dataFinal(sig, sigdata))
        DO_EXIT_0("Signing failed(PKCS7_dataFinal)\n");

    
    /* replace the data part with the MS Authenticode 
       spcIndirectDataContext blob */
    astr = ASN1_STRING_new();
    ASN1_STRING_set(astr, buf, len+i);
    dummy.type = V_ASN1_SEQUENCE;
    dummy.value.sequence = astr;
    sig->d.sign->contents->type = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1);
    sig->d.sign->contents->d.other = &dummy;

#ifdef HAVE_CURL
    /* add counter-signature/timestamp */
    if (turl && add_timestamp(sig, turl, proxy)) 
	DO_EXIT_0("timestamping failed\n");
#endif

#if 0   
    if (!PEM_write_PKCS7(stdout, sig)) 
        DO_EXIT_0("PKCS7 output failed\n");
#endif

    /* Append signature to outfile */
    if (((len = i2d_PKCS7(sig, NULL)) <= 0) ||
        (p = OPENSSL_malloc(len)) == NULL)
        DO_EXIT_1("i2d_PKCS - memory allocation failed: %d\n", len);
    i2d_PKCS7(sig, &p);
    p -= len;
    padlen = (8 - len%8) % 8;

    if (!is_cabinet) {
        static const char magic[] = {
            0x00, 0x02, 0x02, 0x00
        };
        PUT_UINT32_LE(len+8+padlen, buf);
        BIO_write(outdata, buf, 4);   
        BIO_write(outdata, magic, sizeof(magic));
    }

    BIO_write(outdata, p, len);

    /* pad (with 0's) asn1 blob to 8 byte boundary */
    if (padlen > 0) {
        memset(p, 0, padlen);
        BIO_write(outdata, p, padlen);
    }

    if (!is_cabinet) {
        (void)BIO_seek(outdata, peheader+152+pe32plus*16);
        PUT_UINT32_LE(st.st_size, buf);
        BIO_write(outdata, buf, 4);
        PUT_UINT32_LE(len+8+padlen, buf);
        BIO_write(outdata, buf, 4);
    } else {
        (void)BIO_seek(outdata, 0x30);
        PUT_UINT32_LE(len+padlen, buf);
        BIO_write(outdata, buf, 4);
    }

    BIO_free_all(hash);
    hash = outdata = NULL;

    printf("Succeeded\n");

    return 0;

 err_cleanup:
    ERR_print_errors_fp(stderr);
    if (hash != NULL)
        BIO_free_all(hash);
    unlink(outfile);
    fprintf(stderr, "\nFailed\n");
    return -1;
}


