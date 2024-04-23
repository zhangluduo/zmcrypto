/*
 *  The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  RSA was designed by Ron Rivest, Adi Shamir and Len Adleman.
 *
 *  http://theory.lcs.mit.edu/~rivest/rsapaper.pdf
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap8.pdf
 */

/* PolarSSL 1.3.9 */

#include "rsa.h"
#include <stdlib.h>
#include <stdio.h>

namespace polarssl{
    namespace{

        /*
        * Generate or update blinding values, see section 10 of:
        *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
        *  DSS, and other systems. In : Advances in Cryptology CRYPTO 96. Springer
        *  Berlin Heidelberg, 1996. p. 104-113.
        */
        static int rsa_prepare_blinding( rsa_key *key, mpi *Vi, mpi *Vf,
                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
        {
            int ret, count = 0;

            if( key->Vf.p != NULL )
            {
                /* We already have blinding values, just update them by squaring */
                MPI_CHK( mpi_mul_mpi( &key->Vi, &key->Vi, &key->Vi ) );
                MPI_CHK( mpi_mod_mpi( &key->Vi, &key->Vi, &key->N ) );
                MPI_CHK( mpi_mul_mpi( &key->Vf, &key->Vf, &key->Vf ) );
                MPI_CHK( mpi_mod_mpi( &key->Vf, &key->Vf, &key->N ) );

                goto done;
            }

            /* Unblinding value: Vf = random number, invertible mod N */
            do {
                if( count++ > 10 )
                    return( POLARSSL_ERR_RSA_RNG_FAILED );

                MPI_CHK( mpi_fill_random( &key->Vf, key->len - 1, f_rng, p_rng ) );
                MPI_CHK( mpi_gcd( &key->Vi, &key->Vf, &key->N ) );
            } while( mpi_cmp_int( &key->Vi, 1 ) != 0 );

            /* Blinding value: Vi =  Vf^(-e) mod N */
            MPI_CHK( mpi_inv_mod( &key->Vi, &key->Vf, &key->N ) );
            MPI_CHK( mpi_exp_mod( &key->Vi, &key->Vi, &key->E, &key->N, &key->RN ) );

        done:
            if( Vi != &key->Vi )
            {
                MPI_CHK( mpi_copy( Vi, &key->Vi ) );
                MPI_CHK( mpi_copy( Vf, &key->Vf ) );
            }

        cleanup:

            return ( ret );
        }
        /*
        * Do an RSA private key operation
        */
        int rsa_private( rsa_key *key,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng,
                        const unsigned char *input,
                        unsigned char *output )
        {
            int ret;
            size_t olen;
            mpi T, T1, T2;

            mpi *Vi, *Vf;

            Vi = &key->Vi;
            Vf = &key->Vf;

            mpi_init( &T ); mpi_init( &T1 ); mpi_init( &T2 );

            MPI_CHK( mpi_read_binary( &T, input, key->len ) );
            if( mpi_cmp_mpi( &T, &key->N ) >= 0 )
            {
                mpi_free( &T );
                return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            }

            if( f_rng != NULL )
            {
                /*
                * Blinding
                * T = T * Vi mod N
                */
                MPI_CHK( rsa_prepare_blinding( key, Vi, Vf, f_rng, p_rng ) );
                MPI_CHK( mpi_mul_mpi( &T, &T, Vi ) );
                MPI_CHK( mpi_mod_mpi( &T, &T, &key->N ) );
            }

            /*
            * faster decryption using the CRT
            *
            * T1 = input ^ dP mod P
            * T2 = input ^ dQ mod Q
            */
            MPI_CHK( mpi_exp_mod( &T1, &T, &key->DP, &key->P, &key->RP ) );
            MPI_CHK( mpi_exp_mod( &T2, &T, &key->DQ, &key->Q, &key->RQ ) );

            /*
            * T = (T1 - T2) * (Q^-1 mod P) mod P
            */
            MPI_CHK( mpi_sub_mpi( &T, &T1, &T2 ) );
            MPI_CHK( mpi_mul_mpi( &T1, &T, &key->QP ) );
            MPI_CHK( mpi_mod_mpi( &T, &T1, &key->P ) );

            /*
            * T = T2 + T * Q
            */
            MPI_CHK( mpi_mul_mpi( &T1, &T, &key->Q ) );
            MPI_CHK( mpi_add_mpi( &T, &T2, &T1 ) );

            if( f_rng != NULL )
            {
                /*
                * Unblind
                * T = T * Vf mod N
                */
                MPI_CHK( mpi_mul_mpi( &T, &T, Vf ) );
                MPI_CHK( mpi_mod_mpi( &T, &T, &key->N ) );
            }
    
            olen = key->len;
            MPI_CHK( mpi_write_binary( &T, output, olen ) );

        cleanup:
            mpi_free( &T ); mpi_free( &T1 ); mpi_free( &T2 );
        #if !defined(POLARSSL_RSA_NO_CRT) && defined(POLARSSL_THREADING_C)
            mpi_free( &Vi_copy ); mpi_free( &Vf_copy );
        #endif

            if( ret != 0 )
                return( POLARSSL_ERR_RSA_PRIVATE_FAILED + ret );

            return( POLARSSL_ERR_RSA_SUCCESSED );
        }
        /*
        * Do an RSA public key operation
        */
        int rsa_public( rsa_key *key,
                        const unsigned char *input,
                        unsigned char *output )
        {
            int ret;
            size_t olen;
            mpi T;

            mpi_init( &T );

            MPI_CHK( mpi_read_binary( &T, input, key->len ) );

            if( mpi_cmp_mpi( &T, &key->N ) >= 0 )
            {
                mpi_free( &T );
                return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            }

            olen = key->len;
            MPI_CHK( mpi_exp_mod( &T, &T, &key->E, &key->N, &key->RN ) );
            MPI_CHK( mpi_write_binary( &T, output, olen ) );

        cleanup:

            mpi_free( &T );

            if( ret != 0 )
                return( POLARSSL_ERR_RSA_PUBLIC_FAILED + ret );

            return( POLARSSL_ERR_RSA_SUCCESSED );
        }

        /*
        EM = 0x00 || 0x01 || PS || 0x00 || T.
        Zhang Luduo (zhangluduo@qq.com), 2022-07-02
        */

        /*
        md5 ("helloworld") = fc 5e 03 8d 38 a5 70 32 08 54 41 e7 fe 70 10 b0 
        emsa: 00 01 
        ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
        ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
        ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
        ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
        ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 00
        [30 20] [30 0c] [06 08] [2a 86 48 86 f7 0d 02 05] [05 00] [04 10] [fc 5e 03 8d 38 a5 70 32 08 54 41 e7 fe 70 10 b0]

        0  32: SEQUENCE {                                 // 30 20
        2  12:   SEQUENCE {                               // 30 0c
        4   8:     OBJECT IDENTIFIER '1 2 840 113549 2 5' // 2a 86 48 86 f7 0d 02 05
        14   0:     NULL                                   // 05 00
            :     }
        16  16:   OCTET STRING FC 5E 03 8D 38 A5 70 32 08 54 41 E7 FE 70 10 B0
            :   }


        sha1 ("helloworld") = 6a df b1 83 a4 a2 c9 4a 2f 92 da b5 ad e7 62 a4 78 89 a5 a1 
        emsa: 00 01 
        ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
        ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
        ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
        ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
        ff ff ff ff ff ff ff ff ff ff 00 
        [30 21] [30 09] [06 05] [2b 0e 03 02 1a] [05 00] [04 14] [6a df b1 83 a4 a2 c9 4a 2f 92 da b5 ad e7 62 a4 78 89 a5 a1]

        0  33: SEQUENCE {                            // 30 20
        2   9:   SEQUENCE {                          // 30 09
        4   5:     OBJECT IDENTIFIER '1 3 14 3 2 26' // 2b 0e 03 02 1a
        11   0:     NULL                             // 05 00
            :     }
        13  20:   OCTET STRING 6A DF B1 83 A4 A2 C9 4A 2F 92 DA B5 AD E7 62 A4 78 89 A5 A1
            :   }
        */

        /* Zhang Luduo */
        int rsa_emsa_pkcs1_v15_encode(rsa_digest_type digest_type, unsigned char* digest_value, unsigned char* output, unsigned int olen)
        {
            unsigned char *p = output;
            unsigned char* p_oid = NULL;
            size_t nb_pad = olen - 3;
            size_t digest_len = 0;
            size_t oid_size = 0;

            switch (digest_type)
            {
                case E_RSA_DIGEST_MD2: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_MD2; 
                    oid_size = OID_SIZE_MD2; 
                    digest_len = DIGEST_SIZE_MD2; 
                    break; 
                }
                case E_RSA_DIGEST_MD4: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_MD4; 
                    oid_size = OID_SIZE_MD4; 
                    digest_len = DIGEST_SIZE_MD4; 
                    break; 
                }
                case E_RSA_DIGEST_MD5: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_MD5; 
                    oid_size = OID_SIZE_MD5; 
                    digest_len = DIGEST_SIZE_MD5; 
                    break; 
                }
                case E_RSA_DIGEST_SHA1: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_SHA1; 
                    oid_size = OID_SIZE_SHA1; 
                    digest_len = DIGEST_SIZE_SHA1; 
                    break; 
                }
                case E_RSA_DIGEST_SHA256: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_SHA256; 
                    oid_size = OID_SIZE_SHA256; 
                    digest_len = DIGEST_SIZE_SHA256; 
                    break; 
                }
                case E_RSA_DIGEST_SHA384: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_SHA384; 
                    oid_size = OID_SIZE_SHA384; 
                    digest_len = DIGEST_SIZE_SHA384; 
                    break; 
                }
                case E_RSA_DIGEST_SHA512: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_SHA512; 
                    oid_size = OID_SIZE_SHA512; 
                    digest_len = DIGEST_SIZE_SHA512; 
                    break; 
                }
            }

            nb_pad -= 10;//[SEQUENCE][LEN][SEQUENCE][LEN][OID][LEN]...[05 00] [OCTET STRING][LEN]...
            nb_pad -= oid_size;
            nb_pad -= digest_len;

            if (nb_pad < 8)
                return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

            *p++ = 0x00;
            *p++ = RSA_SIGN;
            memset (p, 0xff, nb_pad);
            p += nb_pad;
            *p++ = 0x00;

            /*
                * DigestInfo ::= SEQUENCE {
                *   digestAlgorithm DigestAlgorithmIdentifier,
                *   digest Digest }
                *
                * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
                * Digest ::= OCTET STRING
                */
            *p++ = 0x30;
            *p++ = (unsigned char) ( 0x08 + oid_size + digest_len );
            *p++ = 0x30;
            *p++ = (unsigned char) ( 0x04 + oid_size );
            *p++ = 0x06;
            *p++ = oid_size & 0xff;
            memcpy( p, p_oid, oid_size );
            p += oid_size;
            *p++ = 0x05;
            *p++ = 0x00;
            *p++ = 0x04;
            *p++ = digest_len;
            memcpy( p, digest_value, digest_len );

            return POLARSSL_ERR_RSA_SUCCESSED;
        }

        /**
         * Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
         *
         * \param dst       buffer to mask
         * \param dlen      length of destination buffer
         * \param src       source of the mask generation
         * \param slen      length of the source buffer
         * \param md_ctx    message digest context to use
         */
        static void mgf_mask(unsigned char *dst, size_t dlen, unsigned char *src,
                            size_t slen, rsa_digest_fn* digest)
        {
            unsigned char mask[POLARSSL_MD_MAX_SIZE];
            unsigned char counter[4];
            unsigned char *p;
            unsigned int hlen;
            size_t i, use_len;

            memset( mask, 0, POLARSSL_MD_MAX_SIZE );
            memset( counter, 0, 4 );

            void* mdctx = digest->digest_create();
            digest->digest_init(mdctx);
            hlen = digest->digest_size();

            // Generate and apply dbMask
            //
            p = dst;

            while( dlen > 0 )
            {
                use_len = hlen;
                if( dlen < hlen )
                    use_len = dlen;

                digest->digest_starts(mdctx);
                digest->digest_update(mdctx, src, slen);
                digest->digest_update(mdctx, counter, 4);
                digest->digest_finish(mdctx, mask);

                for( i = 0; i < use_len; ++i )
                    *p++ ^= mask[i];

                counter[3]++;

                dlen -= use_len;
            }
            digest->digest_free(mdctx);
        }

        /* Zhang Luduo */
        int rsa_emsa_pkcs1_v15_decode(unsigned char* input, unsigned int ilen, rsa_digest_type digest_type, unsigned char* output, unsigned int* olen)
        {
            unsigned char *p = input;
            unsigned char* end = input + ilen;

            if( *p++ != 0 || *p++ != RSA_SIGN )
                return( POLARSSL_ERR_RSA_INVALID_PADDING );

            while(p <= end && *p != 0x00) { if (*p++ != 0xFF ) { return POLARSSL_ERR_RSA_INVALID_PADDING; } }
            p++; /* skip 0x00 */

            if( *p++ != 0x30){
                return POLARSSL_ERR_RSA_INVALID_PADDING;
            }

            if (*p != end - p - 1){
                return POLARSSL_ERR_RSA_INVALID_PADDING;
            }
            p++;

            if (*p++ != 0x30){
                return POLARSSL_ERR_RSA_INVALID_PADDING;
            }

            size_t digest_len = 0;
            unsigned char* p_oid = NULL;            
            size_t oid_size = 0;

            switch (digest_type)
            {
                case E_RSA_DIGEST_MD2: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_MD2; 
                    oid_size = OID_SIZE_MD2; 
                    digest_len = DIGEST_SIZE_MD2; 
                    break; 
                }
                case E_RSA_DIGEST_MD4: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_MD4; 
                    oid_size = OID_SIZE_MD4; 
                    digest_len = DIGEST_SIZE_MD4; 
                    break; 
                }
                case E_RSA_DIGEST_MD5: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_MD5; 
                    oid_size = OID_SIZE_MD5; 
                    digest_len = DIGEST_SIZE_MD5; 
                    break; 
                }
                case E_RSA_DIGEST_SHA1: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_SHA1; 
                    oid_size = OID_SIZE_SHA1; 
                    digest_len = DIGEST_SIZE_SHA1; 
                    break; 
                }
                case E_RSA_DIGEST_SHA256: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_SHA256; 
                    oid_size = OID_SIZE_SHA256; 
                    digest_len = DIGEST_SIZE_SHA256; 
                    break; 
                }
                case E_RSA_DIGEST_SHA384: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_SHA384; 
                    oid_size = OID_SIZE_SHA384; 
                    digest_len = DIGEST_SIZE_SHA384; 
                    break; 
                }
                case E_RSA_DIGEST_SHA512: 
                { 
                    p_oid = (unsigned char*)OID_DIGEST_SHA512; 
                    oid_size = OID_SIZE_SHA512; 
                    digest_len = DIGEST_SIZE_SHA512; 
                    break; 
                }
            }

            if (2 /* SEQUENCE_TAG, SEQUENCE_LEN */ + oid_size + 2 /* 0x05, 0x00 */ != *p){
                return POLARSSL_ERR_RSA_INVALID_PADDING;
            }
            p++; /* skip len of sequence */

            if (*p++ != 0x06){
                return POLARSSL_ERR_RSA_INVALID_PADDING;
            }

            if (*p++ != oid_size){
                return POLARSSL_ERR_RSA_INVALID_PADDING;
            }

            if (memcmp(p, p_oid, oid_size) != 0) {
                return POLARSSL_ERR_RSA_INVALID_PADDING;
            }

            p += oid_size;

            if (*p++ != 0x05 || *p++ != 0x00 ){
                return POLARSSL_ERR_RSA_INVALID_PADDING;
            }

            if (*p++ != 0x04 || *p++ != digest_len){
                return POLARSSL_ERR_RSA_INVALID_PADDING;
            }

            if (*olen < digest_len){
                *olen = digest_len;
                return POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE;
            }

            memcpy(output, p, digest_len);
            *olen = digest_len;
/*
            printf("emsa output: ");
            for (int i = 0; i < digest_len; i++){
                printf ("%02x ", output[i]);
            }   printf ("\n");
*/
            return POLARSSL_ERR_RSA_SUCCESSED;
        }

        /* 
        DB = lHash || PS || 0x01 || M.
        Zhang Luduo, 2022-11-01  */
        int construct_db(rsa_digest_fn* digest, 
            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
            unsigned char* msg, unsigned int mlen, unsigned char* label, 
            unsigned int llen, unsigned char* output, unsigned int olen)
        {
            int ret = 0;
            unsigned char *p = output;
            memset(output, 0, olen);

            void* mdctx = digest->digest_create();
            unsigned int hLen = digest->digest_size();

            digest->digest_init(mdctx);
            digest->digest_starts(mdctx);
            digest->digest_update(mdctx, ((label == NULL || llen == 0) ? (unsigned char*)"" : label), llen);
            digest->digest_finish(mdctx, p);
            digest->digest_free(mdctx);

            p += hLen;

            int PSLen = olen - hLen - 1 - mlen;
            if (PSLen < 0){
                return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
            }

            p += PSLen;
            *p++ = 0x01;
            memcpy(p, msg, mlen);

            return POLARSSL_ERR_RSA_SUCCESSED;
        }
    } /* end unnamed namespace */

    /*
    * Initialize an RSA context
    */
    void rsa_init( rsa_key *key)
    {
        memset(key, 0, sizeof(rsa_key));
    }

    /*
    * Generate an RSA keypair
    */
    int rsa_gen_key( rsa_key *key,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    unsigned int nbits, int exponent )
    {
        int ret;
        mpi P1, Q1, H, G;

        if( f_rng == NULL || nbits < 128 || exponent < 3 )
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

        mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );

        /*
        * find primes P and Q with Q < P so that:
        * GCD( E, (P-1)*(Q-1) ) == 1
        */
        MPI_CHK( mpi_lset( &key->E, exponent ) );

        do
        {
            MPI_CHK( mpi_gen_prime( &key->P, ( nbits + 1 ) >> 1, 0,
                                    f_rng, p_rng ) );

            MPI_CHK( mpi_gen_prime( &key->Q, ( nbits + 1 ) >> 1, 0,
                                    f_rng, p_rng ) );

            if( mpi_cmp_mpi( &key->P, &key->Q ) < 0 )
                mpi_swap( &key->P, &key->Q );

            if( mpi_cmp_mpi( &key->P, &key->Q ) == 0 )
                continue;

            MPI_CHK( mpi_mul_mpi( &key->N, &key->P, &key->Q ) );
            if( mpi_msb( &key->N ) != nbits )
                continue;

            MPI_CHK( mpi_sub_int( &P1, &key->P, 1 ) );
            MPI_CHK( mpi_sub_int( &Q1, &key->Q, 1 ) );
            MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
            MPI_CHK( mpi_gcd( &G, &key->E, &H  ) );
        }
        while( mpi_cmp_int( &G, 1 ) != 0 );

        /*
        * D  = E^-1 mod ((P-1)*(Q-1))
        * DP = D mod (P - 1)
        * DQ = D mod (Q - 1)
        * QP = Q^-1 mod P
        */
        MPI_CHK( mpi_inv_mod( &key->D , &key->E, &H  ) );
        MPI_CHK( mpi_mod_mpi( &key->DP, &key->D, &P1 ) );
        MPI_CHK( mpi_mod_mpi( &key->DQ, &key->D, &Q1 ) );
        MPI_CHK( mpi_inv_mod( &key->QP, &key->Q, &key->P ) );

        key->len = ( mpi_msb( &key->N ) + 7 ) >> 3;

    cleanup:

        mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );

        if( ret != 0 )
        {
            rsa_free( key );
            return( POLARSSL_ERR_RSA_KEY_GEN_FAILED + ret );
        }

        return( POLARSSL_ERR_RSA_SUCCESSED );
    }

    /*
    * Check a public RSA key
    */
    int rsa_check_pubkey( const rsa_key *key )
    {
        if( !key->N.p || !key->E.p )
            return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

        if( ( key->N.p[0] & 1 ) == 0 ||
            ( key->E.p[0] & 1 ) == 0 )
            return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

        if( mpi_msb( &key->N ) < 128 ||
            mpi_msb( &key->N ) > POLARSSL_MPI_MAX_BITS )
            return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

        if( mpi_msb( &key->E ) < 2 ||
            mpi_cmp_mpi( &key->E, &key->N ) >= 0 )
            return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

        return( POLARSSL_ERR_RSA_SUCCESSED );
    }

    /*
    * Check a private RSA key
    */
    int rsa_check_privkey( const rsa_key *key )
    {
        int ret;
        mpi PQ, DE, P1, Q1, H, I, G, G2, L1, L2, DP, DQ, QP;

        if ((ret = rsa_check_pubkey(key)) != 0){
            return ret;
        }

        if (!key->P.p || !key->Q.p || !key->D.p){
            return POLARSSL_ERR_RSA_KEY_CHECK_FAILED;
        }

        mpi_init( &PQ ); mpi_init( &DE ); mpi_init( &P1 ); mpi_init( &Q1 );
        mpi_init( &H  ); mpi_init( &I  ); mpi_init( &G  ); mpi_init( &G2 );
        mpi_init( &L1 ); mpi_init( &L2 ); mpi_init( &DP ); mpi_init( &DQ );
        mpi_init( &QP );

        MPI_CHK( mpi_mul_mpi( &PQ, &key->P, &key->Q ) );
        MPI_CHK( mpi_mul_mpi( &DE, &key->D, &key->E ) );
        MPI_CHK( mpi_sub_int( &P1, &key->P, 1 ) );
        MPI_CHK( mpi_sub_int( &Q1, &key->Q, 1 ) );
        MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
        MPI_CHK( mpi_gcd( &G, &key->E, &H  ) );

        MPI_CHK( mpi_gcd( &G2, &P1, &Q1 ) );
        MPI_CHK( mpi_div_mpi( &L1, &L2, &H, &G2 ) );
        MPI_CHK( mpi_mod_mpi( &I, &DE, &L1  ) );

        MPI_CHK( mpi_mod_mpi( &DP, &key->D, &P1 ) );
        MPI_CHK( mpi_mod_mpi( &DQ, &key->D, &Q1 ) );
        MPI_CHK( mpi_inv_mod( &QP, &key->Q, &key->P ) );
        /*
        * Check for a valid PKCS1v2 private key
        */
        if( mpi_cmp_mpi( &PQ, &key->N ) != 0 ||
            mpi_cmp_mpi( &DP, &key->DP ) != 0 ||
            mpi_cmp_mpi( &DQ, &key->DQ ) != 0 ||
            mpi_cmp_mpi( &QP, &key->QP ) != 0 ||
            mpi_cmp_int( &L2, 0 ) != 0 ||
            mpi_cmp_int( &I, 1 ) != 0 ||
            mpi_cmp_int( &G, 1 ) != 0 )
        {
            ret = POLARSSL_ERR_RSA_KEY_CHECK_FAILED;
        }

    cleanup:
        mpi_free( &PQ ); mpi_free( &DE ); mpi_free( &P1 ); mpi_free( &Q1 );
        mpi_free( &H  ); mpi_free( &I  ); mpi_free( &G  ); mpi_free( &G2 );
        mpi_free( &L1 ); mpi_free( &L2 ); mpi_free( &DP ); mpi_free( &DQ );
        mpi_free( &QP );

        if (ret == POLARSSL_ERR_RSA_KEY_CHECK_FAILED){
            return ret;
        }

        if (ret != 0){
            return (POLARSSL_ERR_RSA_KEY_CHECK_FAILED + ret);
        }

        return POLARSSL_ERR_RSA_SUCCESSED;
    }

    /*
    * Free the components of an RSA key
    */
    void rsa_free (rsa_key *key)
    {
        mpi_free( &key->QP ); mpi_free( &key->DQ ); mpi_free( &key->DP );
        mpi_free( &key->Q  ); mpi_free( &key->P  ); mpi_free( &key->D );
        mpi_free( &key->E  ); mpi_free( &key->N  );

        mpi_free( &key->RN);
        mpi_free( &key->RP);
        mpi_free( &key->RQ);
        mpi_free( &key->Vi);
        mpi_free( &key->Vf);
    }

    void rsa_digest_create(rsa_digest_context* digest_ctx, rsa_digest_fn* digest_fn)
    {
        digest_ctx->digest_fn = (*digest_fn);
        digest_ctx->digest_ctx = digest_fn->digest_create();
        digest_fn->digest_init(digest_ctx->digest_ctx);
    }

    void rsa_digest_free(rsa_digest_context* ctx)
    {
        if (ctx && ctx->digest_ctx)
        {
            ctx->digest_fn.digest_free (ctx->digest_ctx);
            ctx->digest_ctx = NULL;
        }
    }

    unsigned int rsa_helper_rsassa_pkcs1_v15_fixed_len(unsigned int klen)
    {
        return klen;
    }

    unsigned int rsa_helper_rsassa_pss_fixed_len(unsigned int klen)
    {
        return klen;
    }

    unsigned int rsa_helper_rsaes_pkcs1_v15_max_pt_len(unsigned int klen)
    {
        return klen < 11 ? 0 : klen - 11;
    }

    unsigned int rsa_helper_rsaes_pkcs1_v15_fixed_ct_len(unsigned int klen)
    {
        return klen;
    }

    unsigned int rsa_helper_rsaes_oaep_max_pt_len(unsigned int klen, unsigned int mgf_digest_size)
    {
        int max = klen  - (mgf_digest_size * 2 + 2);
        return max <= 0 ? 0 : max;
    }

    unsigned int rsa_helper_rsaes_oaep_fixed_ct_len(unsigned int klen)
    {
        return klen;
    }

    void rsa_rsassa_pkcs1_v15_sign_start(rsa_digest_context* ctx)
    {
        if (ctx){
            ctx->digest_fn.digest_starts(ctx->digest_ctx);
        }
    }

    void rsa_rsassa_pkcs1_v15_sign_update(rsa_digest_context* ctx, const unsigned char* data, unsigned int dlen)
    {
        if (ctx){
            ctx->digest_fn.digest_update(ctx->digest_ctx, (unsigned char*)data, dlen);
        }
    }

    int rsa_rsassa_pkcs1_v15_sign_finish(
            rsa_key* key, 
            rsa_digest_context* digest, 
            int (*f_rng)(void *, unsigned char *, size_t),
            void *p_rng,
            unsigned char* sig)
    {
        unsigned char md[POLARSSL_MD_MAX_SIZE];
        digest->digest_fn.digest_finish(digest->digest_ctx, md);
        uint32_t md_size = digest->digest_fn.digest_size();
        int ret = 0;
        ret = rsa_emsa_pkcs1_v15_encode(digest->digest_fn.digest_type, md, sig, key->len);
        if (ret != POLARSSL_ERR_RSA_SUCCESSED){
            return ret;
        }
        ret = rsa_private(key, f_rng, p_rng, sig, sig );
        return ret;
    }

    int rsa_rsassa_pkcs1_v15_sign_oneshot(rsa_key* key, rsa_digest_context* digest, int (*f_rng)(void *, unsigned char *, size_t),
            void *p_rng, unsigned char* md, unsigned char* sig)
    {
        uint32_t md_size = digest->digest_fn.digest_size();
        int ret = 0;
        ret = rsa_emsa_pkcs1_v15_encode(digest->digest_fn.digest_type, md, sig, key->len);
        if (ret != POLARSSL_ERR_RSA_SUCCESSED){
            return ret;
        }
        ret = rsa_private(key, f_rng, p_rng, sig, sig );
        return ret;
    }

    /*
    * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-ENCRYPT function
    */
    int rsa_rsaes_pkcs1_v15_encrypt( rsa_key *key,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
        size_t ilen, const unsigned char *input, unsigned char *output )
    {
        size_t nb_pad, olen;
        int ret;
        unsigned char *p = output;

        olen = key->len;

        if (olen < ilen + 11){
            return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
        }

        nb_pad = olen - 3 - ilen;

        *p++ = 0;
        *p++ = RSA_CRYPT;

        while( nb_pad-- > 0 )
        {
            int rng_dl = 100;

            do {
                ret = f_rng( p_rng, p, 1 );
            } while( *p == 0 && --rng_dl && ret == 0 );

            // Check if RNG failed to generate data
            //
            if( rng_dl == 0 || ret != 0 ){
                return( POLARSSL_ERR_RSA_RNG_FAILED + ret );
            }

            p++;
        }

        *p++ = 0;
        memcpy( p, input, ilen );
        return rsa_public(key, output, output );
    }

    /*
    * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-DECRYPT function
    */
    int rsa_rsaes_pkcs1_v15_decrypt( rsa_key *key,
        int (*f_rng)(void *, unsigned char *, size_t),void *p_rng,
        const unsigned char *input,unsigned char *output, size_t *olen)
    {
        int ret;
        size_t ilen, pad_count = 0, i;
        unsigned char *p, bad, pad_done = 0;
        unsigned char buf[POLARSSL_MPI_MAX_SIZE];
        memset(buf, 0, POLARSSL_MPI_MAX_SIZE);

        ilen = key->len;

        if (ilen < 16 || ilen > sizeof(buf)){
            return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
        }

        ret = rsa_private(key, f_rng, p_rng, input, buf );

        if (ret != 0)
            return ret;

        p = buf;
        bad = 0;

        /*
        * Check and get padding len in "constant-time"
        */
        bad |= *p++; /* First byte must be 0 */

        /* This test does not depend on secret data */

        bad |= *p++ ^ RSA_CRYPT;

        /* Get padding len, but always read till end of buffer
            * (minus one, for the 00 byte) */
        for( i = 0; i < ilen - 3; i++ )
        {
            pad_done |= ( p[i] == 0 );
            pad_count += ( pad_done == 0 );
        }

        p += pad_count;
        bad |= *p++; /* Must be zero */

        if (bad){
            return POLARSSL_ERR_RSA_INVALID_PADDING;
        }

        if (ilen - ( p - buf ) > *olen){
            return POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE;
        }

        *olen = ilen - (p - buf);
        memcpy( output, p, *olen );
        return POLARSSL_ERR_RSA_SUCCESSED;
    }

    void rsa_rsassa_pkcs1_v15_verify_start(rsa_digest_context* ctx)
    {
        if (ctx){
            ctx->digest_fn.digest_starts(ctx->digest_ctx);
        } 
    }
    void rsa_rsassa_pkcs1_v15_verify_update(rsa_digest_context* ctx, const unsigned char* data, unsigned int dlen)
    {
        if (ctx){
            ctx->digest_fn.digest_update(ctx->digest_ctx, (unsigned char*)data, dlen);
        }
    }

    int rsa_rsassa_pkcs1_v15_verify_finish(rsa_key* key, rsa_digest_context* digest, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, unsigned char* sig)
    {
        unsigned char buf[POLARSSL_MPI_MAX_SIZE];
        memset(buf, 0, POLARSSL_MPI_MAX_SIZE);

        unsigned char md[POLARSSL_MD_MAX_SIZE];
        memset(md, 0, POLARSSL_MD_MAX_SIZE);
        
        int siglen = key->len;
        if (siglen < 16 || siglen > sizeof (buf)){
            return (POLARSSL_ERR_RSA_BAD_INPUT_DATA);
        }

        int ret = rsa_public(key, sig, buf);
        if( ret != 0 ){
            return( ret );
        }
/*
        printf ("buf: ");
        for (int i = 0; i < key->len; i++){
            printf ("%02x ", buf[i]);
        }   printf ("\n");
*/

        unsigned char emsa_out[POLARSSL_MD_MAX_SIZE];
        unsigned int emsa_olen = POLARSSL_MD_MAX_SIZE;
        ret = rsa_emsa_pkcs1_v15_decode(buf, key->len, E_RSA_DIGEST_SHA1, emsa_out, &emsa_olen);
        if (ret < 0){
            /*printf("-0x%08x\n", 0 - ret);*/
            return ret;
        }

        digest->digest_fn.digest_finish(digest->digest_ctx, md);
        if (emsa_olen != digest->digest_fn.digest_size() || memcmp(emsa_out, md, emsa_olen) != 0){
            return POLARSSL_ERR_RSA_VERIFY_FAILED;
        }
        return 0; /* successed */
    }

    int rsa_rsassa_pkcs1_v15_verify_oneshot(rsa_key* key, rsa_digest_context* digest, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, unsigned char* md, unsigned char* sig)
    {
        unsigned char buf[POLARSSL_MPI_MAX_SIZE];
        memset(buf, 0, POLARSSL_MPI_MAX_SIZE);

        int siglen = key->len;
        if (siglen < 16 || siglen > sizeof (buf)){
            return (POLARSSL_ERR_RSA_BAD_INPUT_DATA);
        }

        int ret = rsa_public(key, sig, buf);
        if( ret != 0 ){
            return( ret );
        }
/*
        printf ("buf: ");
        for (int i = 0; i < key->len; i++){
            printf ("%02x ", buf[i]);
        }   printf ("\n");
*/

        unsigned char emsa_out[POLARSSL_MD_MAX_SIZE];
        unsigned int emsa_olen = POLARSSL_MD_MAX_SIZE;
        ret = rsa_emsa_pkcs1_v15_decode(buf, key->len, E_RSA_DIGEST_SHA1, emsa_out, &emsa_olen);
        if (ret < 0){
            /*printf("-0x%08x\n", 0 - ret);*/
            return ret;
        }

        if (emsa_olen != digest->digest_fn.digest_size() || memcmp(emsa_out, md, emsa_olen) != 0){
            return POLARSSL_ERR_RSA_VERIFY_FAILED;
        }
        return 0; /* successed */
    }

    int rsa_rsaes_oaep_encrypt(rsa_key *key, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
        rsa_digest_fn* mgf1,
        const unsigned char *label, size_t label_len, 
        const unsigned char *input, size_t ilen, unsigned char *output)
    {
        size_t olen = 0;
        int ret = 0;
        unsigned char *p = output;
        unsigned int hlen = 0;
        memset (output, 0, olen);

        if (f_rng == NULL) { return POLARSSL_ERR_RSA_BAD_INPUT_DATA; }

        olen = key->len;
        hlen = mgf1->digest_size();

        if (olen < ilen + 2 * hlen + 2) { return POLARSSL_ERR_RSA_BAD_INPUT_DATA; }

        *p++ = 0x00;

        /* Generate a random octet string seed 
        if ((ret = f_rng( p_rng, p, hlen)) != 0)
            return (POLARSSL_ERR_RSA_RNG_FAILED + ret);*/
        memset(p, 0xaa, hlen);

        /*printf ("output: "); for (int i = 0; i < olen; i++){ printf ("%02x ", output[i]); } printf ("\n");*/

        p += hlen;

        /*
            a. If the label L is not provided, let L be the empty string. Let
                lHash = Hash(L), an octet string of length hLen (see the note
                below).

            b. Generate an octet string PS consisting of k - mLen - 2hLen - 2
                zero octets.  The length of PS may be zero.

            c. Concatenate lHash, PS, a single octet with hexadecimal value
                0x01, and the message M to form a data block DB of length k -
                hLen - 1 octets as

                    DB = lHash || PS || 0x01 || M.
        */

        unsigned int dbLen = hlen + (olen - ilen - 2 * hlen - 2) + 1/*a single octet with hexadecimal value 0x01*/ + ilen;
        if ((ret = construct_db(mgf1, f_rng, p_rng, (unsigned char *)input, ilen, (unsigned char *)label, label_len, p, dbLen)) != POLARSSL_ERR_RSA_SUCCESSED){
            return ret;
        }

        /*printf ("construct db: "); for (int i = 0; i < dbLen; i++){ printf ("%02x ", p[i]); } printf ("\n");*/
        /*printf ("output: "); for (int i = 0; i < olen; i++){ printf ("%02x ", output[i]); } printf ("\n");*/

        p += dbLen;

        /* maskedDB: Apply dbMask to DB */
        mgf_mask (output + hlen + 1, olen - hlen - 1, output + 1, hlen, mgf1);
        /*printf ("maskedDB: "); for (int i = 0; i < (olen - hlen - 1); i++){ printf ("%02x ", (output + hlen + 1)[i]); } printf ("\n");*/
        /*printf ("output: "); for (int i = 0; i < olen; i++){ printf ("%02x ", output[i]); } printf ("\n");*/

        /* maskedSeed: Apply seedMask to seed */
        mgf_mask (output + 1, hlen, output + hlen + 1, olen - hlen - 1, mgf1);
        /*printf ("maskedSeed: "); for (int i = 0; i < hlen; i++){ printf ("%02x ", (output + 1)[i]); } printf ("\n");*/
        /*printf ("output: "); for (int i = 0; i < olen; i++){ printf ("%02x ", output[i]); } printf ("\n");*/

        return rsa_public (key, output, output);
    }

    int rsa_rsaes_oaep_decrypt( rsa_key *key, int (*f_rng)(void *, unsigned char *, size_t),void *p_rng,
                                rsa_digest_fn* mgf1,
                                const unsigned char *label, size_t llen,
                                const unsigned char *input,
                                unsigned char *output, size_t *olen)
    {
        int ret = 0;
        unsigned int hlen = 0;
        unsigned char* p = NULL, bad = NULL, pad_done = NULL;
        unsigned char buf[POLARSSL_MPI_MAX_SIZE];
        unsigned char lhash[POLARSSL_MD_MAX_SIZE];
        size_t ilen = key->len, pad_len = 0;
        size_t output_max_len = *olen;

        if (ilen < 16 || ilen > sizeof( buf)){
            return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
        }

        /*
        * RSA operation
        */
        ret = rsa_private(key, f_rng, p_rng, input, buf);
        if (ret != 0){
            return ret;
        }

        /*
        printf ("rsa_private output: ");
        for (int i = 0; i < ilen; i++){
            printf ("%02x ", (buf)[i]);
        }   printf ("\n");
        */

        /*
        * Unmask data and generate lHash
        */

        hlen = mgf1->digest_size();

        void* mdctx = mgf1->digest_create();
        mgf1->digest_init(mdctx);
        mgf1->digest_starts(mdctx);
        mgf1->digest_update(mdctx, ((label == NULL || llen == 0) ? (unsigned char*)"" : (unsigned char*)label), llen);
        mgf1->digest_finish(mdctx, lhash);
        mgf1->digest_free(mdctx);

        /* seed: Apply seedMask to maskedSeed */
        mgf_mask (buf + 1, hlen, buf + hlen + 1, ilen - hlen - 1, mgf1);

        /* DB: Apply dbMask to maskedDB */
        mgf_mask (buf + hlen + 1, ilen - hlen - 1, buf + 1, hlen, mgf1);

        /*
        * Check contents, in "constant-time"
        */
        p = buf;
        bad = 0;

        bad |= *p++; /* First byte must be 0 */

        p += hlen; /* Skip seed */

        /* Check lHash */
        for (int i = 0; i < hlen; i++){
            bad |= lhash[i] ^ *p++;
        }

        /* Get zero-padding len, but always read till end of buffer
        * (minus one, for the 01 byte) */
        pad_len = 0;
        pad_done = 0;
        for(int i = 0; i < ilen - 2 * hlen - 2; i++ )
        {
            pad_done |= p[i];
            pad_len += ( pad_done == 0 );
        }

        p += pad_len;
        bad |= *p++ ^ 0x01;

        /*
        * The only information "leaked" is whether the padding was correct or not
        * (eg, no data is copied if it was not correct). This meets the
        * recommendations in PKCS#1 v2.2: an opponent cannot distinguish between
        * the different error conditions.
        */
        if (bad != 0){
            return POLARSSL_ERR_RSA_INVALID_PADDING;
        }

        if (ilen - ( p - buf ) > output_max_len){
            return POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE;
        }

        *olen = ilen - (p - buf);
        memcpy (output, p, *olen);
        return 0;
    }

    void rsa_rsassa_pss_sign_start(rsa_digest_context* ctx)
    {
        if (ctx){
            ctx->digest_fn.digest_starts(ctx->digest_ctx);
        }
    }

    void rsa_rsassa_pss_sign_update(rsa_digest_context* ctx, const unsigned char* data, unsigned int dlen)
    {
        if (ctx){
            ctx->digest_fn.digest_update(ctx->digest_ctx, (unsigned char*)data, dlen);
        }
    }

    int rsa_rsassa_pss_sign_oneshot(rsa_key* key, rsa_digest_fn* digest, int (*f_rng)(void *, unsigned char *, size_t), 
            void *p_rng, unsigned char* md, unsigned char* sig)
    {
        int ret = 0;
        size_t olen = key->len;
        size_t msb = 0;
        unsigned char *p = sig;
        unsigned int slen, hlen, offset = 0;
        unsigned char salt[POLARSSL_MD_MAX_SIZE];

        hlen = digest->digest_size();
        slen = hlen;

        if (olen < hlen + slen + 2){
            return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
        }

        memset (sig, 0, olen);

        // Generate salt of length slen
        //
        if ((ret = f_rng( p_rng, salt, slen)) != 0)
            return (POLARSSL_ERR_RSA_RNG_FAILED + ret);

        // Note: EMSA-PSS encoding is over the length of N - 1 bits
        //
        msb = mpi_msb(&(key->N)) - 1;
        p += olen - hlen * 2 - 2;
        *p++ = 0x01;
        memcpy (p, salt, slen);
        p += slen;

        // Generate H = Hash( M' )
        //
        void* mdctx = digest->digest_create();
        digest->digest_init(mdctx);
        digest->digest_starts(mdctx);
        digest->digest_update(mdctx, p, 8);
        digest->digest_update(mdctx, md, hlen);
        digest->digest_update(mdctx, salt, slen);
        digest->digest_finish(mdctx, p);
        digest->digest_free(mdctx);

        // Compensate for boundary condition when applying mask
        //
        if (msb % 8 == 0){
            offset = 1;
        }

        // maskedDB: Apply dbMask to DB
        //
        mgf_mask (sig + offset, olen - hlen - 1 - offset, p, hlen, digest);

        sig[0] &= 0xFF >> ( olen * 8 - msb );
        p += hlen;
        *p++ = 0xBC;

        ret = rsa_private(key, f_rng, p_rng, sig, sig);
        return ret;
    }

    int rsa_rsassa_pss_sign_finish(rsa_key* key, rsa_digest_context* digest, 
        int (*f_rng)(void *, unsigned char *, size_t), 
        void *p_rng, unsigned char* sig)
    {
        unsigned char md[POLARSSL_MD_MAX_SIZE];
        digest->digest_fn.digest_finish(digest->digest_ctx, md);
        return rsa_rsassa_pss_sign_oneshot(key, &(digest->digest_fn), f_rng, p_rng, md, sig);
    }

    void rsa_rsassa_pss_verify_start(rsa_digest_context* ctx)
    {
        if (ctx){
            ctx->digest_fn.digest_starts(ctx->digest_ctx);
        }
    }

    void rsa_rsassa_pss_verify_update(rsa_digest_context* ctx, const unsigned char* data, unsigned int dlen)
    {
        if (ctx){
            ctx->digest_fn.digest_update(ctx->digest_ctx, (unsigned char*)data, dlen);
        }
    }

    int  rsa_rsassa_pss_verify_finish(rsa_key* key, rsa_digest_context* digest, int (*f_rng)(void *, unsigned char *, size_t), 
            void *p_rng, unsigned char* sig)
    {
        unsigned char md[POLARSSL_MD_MAX_SIZE]; memset (md, 0, POLARSSL_MD_MAX_SIZE);
        digest->digest_fn.digest_finish(digest->digest_ctx, md);
        return rsa_rsassa_pss_verify_oneshot(key, &(digest->digest_fn), f_rng, p_rng, md, sig);
    }

    int rsa_rsassa_pss_verify_oneshot(rsa_key* key, rsa_digest_fn* digest, int (*f_rng)(void *, unsigned char *, size_t), 
        void *p_rng, unsigned char* md, unsigned char* sig)
    {
        int ret = 0;
        size_t siglen = 0;
        unsigned char *p;
        unsigned char buf[POLARSSL_MPI_MAX_SIZE]; memset (buf, 0, POLARSSL_MPI_MAX_SIZE);
        unsigned char result[POLARSSL_MD_MAX_SIZE]; memset (result, 0, POLARSSL_MD_MAX_SIZE);
        unsigned char zeros[8]; memset (zeros, 0, 8);
        unsigned int hlen = 0;
        size_t slen = 0, msb = 0;

        siglen = key->len;
        if (siglen < 16 || siglen > sizeof(buf)){
            return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
        }

        ret = rsa_public(key, sig, buf);
        if (ret != 0){
            return ret;
        }

        p = buf;

        if (buf[siglen - 1] != 0xBC){
            return POLARSSL_ERR_RSA_INVALID_PADDING;
        }

        hlen = digest->digest_size();
        slen = siglen - hlen - 1; /* Currently length of salt + padding */

        // Note: EMSA-PSS verification is over the length of N - 1 bits
        //
        msb = mpi_msb (&key->N) - 1;

        // Compensate for boundary condition when applying mask
        //
        if (msb % 8 == 0)
        {
            p++;
            siglen -= 1;
        }
        if (buf[0] >> (8 - siglen * 8 + msb)){
            return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
        }
        mgf_mask (p, siglen - hlen - 1, p + siglen - hlen - 1, hlen, digest);

        buf[0] &= 0xFF >> ( siglen * 8 - msb );

        while (p < buf + siglen && *p == 0){
            p++;
        }

        if (p == buf + siglen || *p++ != 0x01){
            return POLARSSL_ERR_RSA_INVALID_PADDING;
        }

        /* Actual salt len */
        slen -= p - buf;

        // Generate H = Hash( M' )
        //
        void* mdctx = digest->digest_create();
        digest->digest_init(mdctx);
        digest->digest_starts(mdctx);
        digest->digest_update(mdctx, zeros, 8);
        digest->digest_update(mdctx, md, hlen);
        digest->digest_update(mdctx, p, slen);
        digest->digest_finish(mdctx, result);
        digest->digest_free(mdctx);

        if (memcmp (p + slen, result, hlen ) == 0){
            return 0;
        }
        else{
            return POLARSSL_ERR_RSA_VERIFY_FAILED;
        }
    }

    /*
    zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ valgrind ./test 
    ==1624049== Memcheck, a memory error detector
    ==1624049== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
    ==1624049== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
    ==1624049== Command: ./test
    ==1624049== 
    emsa encode: 00 01 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 00 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 6a df b1 83 a4 a2 c9 4a 2f 92 da b5 ad e7 62 a4 78 89 a5 a1 
    emsa decode: 6a df b1 83 a4 a2 c9 4a 2f 92 da b5 ad e7 62 a4 78 89 a5 a1 
    successed
    ==1624049== 
    ==1624049== HEAP SUMMARY:
    ==1624049==     in use at exit: 0 bytes in 0 blocks
    ==1624049==   total heap usage: 2 allocs, 2 frees, 73,728 bytes allocated
    ==1624049== 
    ==1624049== All heap blocks were freed -- no leaks are possible
    ==1624049== 
    ==1624049== For lists of detected and suppressed errors, rerun with: -s
    ==1624049== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
    zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ 
    */
    int test()
    {
#if 0
        unsigned char helloworld_sha1[20] = {0x6a, 0xdf, 0xb1, 0x83, 0xa4, 0xa2, 0xc9, 0x4a, 0x2f, 0x92, 0xda, 0xb5, 0xad, 0xe7, 0x62, 0xa4, 0x78, 0x89, 0xa5, 0xa1};
        unsigned char out[64];
        unsigned int olen = 64;
        int ret = rsa_emsa_pkcs1_v15_encode(E_RSA_DIGEST_SHA1, helloworld_sha1, out, olen);
        if (ret < 0){
            printf("-0x%08x\n", 0 - ret);
            return -1;
        }

        printf ("emsa encode: ");
        for (int i = 0; i < olen; i++){
            printf ("%02x ", out[i]);
        }   printf ("\n");

        unsigned char out2[64];
        unsigned int olen2 = 64;
        ret = rsa_emsa_pkcs1_v15_decode(out, olen, E_RSA_DIGEST_SHA1, out2, &olen2);
        if (ret < 0){
            printf("-0x%08x\n", 0 - ret);
            return -1;
        }

        printf ("emsa decode: ");
        for (int i = 0; i < olen2; i++){
            printf ("%02x ", out2[i]);
        }   printf ("\n");
#endif
        return 1;
    }

} /* namespace polarssl */