// openssl/ssl.h

typedef void* SSL; // TODO
typedef void* SSL_SESSION; // TODO
typedef void* SSL_CTX; // TODO

struct SSL_CIPHER {
    int valid;
    const char *name;
    unsigned long id;
    unsigned long algorithm_mkey;
    unsigned long algorithm_auth;
    unsigned long algorithm_enc;
    unsigned long algorithm_mac;
    unsigned long algorithm_ssl;
    unsigned long algo_strength;
    unsigned long algorithm2;
    int strength_bits;
    int alg_bits;
};


size_t SSL_get_client_random(const SSL *ssl, unsigned char *out, size_t outlen);
size_t SSL_get_server_random(const SSL *ssl, unsigned char *out, size_t outlen);
size_t SSL_SESSION_get_master_key(const SSL_SESSION *session, unsigned char *out, size_t outlen);
int SSL_SESSION_set1_master_key(SSL_SESSION *sess, const unsigned char *in, size_t len);

long SSL_CTX_set_max_send_fragment(SSL_CTX *ctx, long);
long SSL_set_max_send_fragment(SSL *ssl, long m);

long SSL_CTX_set_max_pipelines(SSL_CTX *ctx, long m);
long SSL_set_max_pipelines(SSL_CTX *ssl, long m);

long SSL_CTX_set_split_send_fragment(SSL_CTX *ctx, long m);
long SSL_set_split_send_fragment(SSL *ssl, long m);

void SSL_CTX_set_default_read_buffer_len(SSL_CTX *ctx, size_t len);
void SSL_set_default_read_buffer_len(SSL *s, size_t len);

int SSL_CTX_set_tlsext_max_fragment_length(SSL_CTX *ctx, uint8_t mode);
int SSL_set_tlsext_max_fragment_length(SSL *ssl, uint8_t mode);
uint8_t SSL_SESSION_get_max_fragment_length(SSL_SESSION *session);


typedef void* EVP_MD;

const char *SSL_CIPHER_get_name(const SSL_CIPHER *cipher);
const char *SSL_CIPHER_standard_name(const SSL_CIPHER *cipher);
const char *OPENSSL_cipher_name(const char *stdname);
int SSL_CIPHER_get_bits(const SSL_CIPHER *cipher, int *alg_bits);
char *SSL_CIPHER_get_version(const SSL_CIPHER *cipher);
char *SSL_CIPHER_description(const SSL_CIPHER *cipher, char *buf, int size);
int SSL_CIPHER_get_cipher_nid(const SSL_CIPHER *c);
int SSL_CIPHER_get_digest_nid(const SSL_CIPHER *c);
const EVP_MD *SSL_CIPHER_get_handshake_digest(const SSL_CIPHER *c);
int SSL_CIPHER_get_kx_nid(const SSL_CIPHER *c);
int SSL_CIPHER_get_auth_nid(const SSL_CIPHER *c);
int SSL_CIPHER_is_aead(const SSL_CIPHER *c);
const SSL_CIPHER *SSL_CIPHER_find(SSL *ssl, const unsigned char *ptr);
uint32_t SSL_CIPHER_get_id(const SSL_CIPHER *c);
uint32_t SSL_CIPHER_get_protocol_id(const SSL_CIPHER *c);

void SSL_CTX_set_info_callback(SSL_CTX *ctx, void (*callback)());
// void (*SSL_CTX_get_info_callback(const SSL_CTX *ctx))();

void SSL_set_info_callback(SSL *ssl, void (*callback)());
// void (*SSL_get_info_callback(const SSL *ssl))();

int SSL_export_keying_material(SSL *s, unsigned char *out, size_t olen,
                                const char *label, size_t llen,
                                const unsigned char *context,
                                size_t contextlen, int use_context);

int SSL_export_keying_material_early(SSL *s, unsigned char *out, size_t olen,
                                        const char *label, size_t llen,
                                        const unsigned char *context,
                                        size_t contextlen);

int SSL_clear(SSL *ssl);

void SSL_CTX_set_security_level(SSL_CTX *ctx, int level);
void SSL_set_security_level(SSL *s, int level);

int SSL_CTX_get_security_level(const SSL_CTX *ctx);
int SSL_get_security_level(const SSL *s);

void SSL_CTX_set_security_callback(SSL_CTX *ctx,
                                    int (*cb)(SSL *s, SSL_CTX *ctx, int op,
                                    int bits, int nid,
                                    void *other, void *ex));

void SSL_set_security_callback(SSL *s, int (*cb)(SSL *s, SSL_CTX *ctx, int op,
                                    int bits, int nid,
                                    void *other, void *ex));

// int (*SSL_CTX_get_security_callback(const SSL_CTX *ctx))(SSL *s, SSL_CTX *ctx, int op,
//                                     int bits, int nid, void *other,
//                                     void *ex);
// int (*SSL_get_security_callback(const SSL *s))(SSL *s, SSL_CTX *ctx, int op,
//                                     int bits, int nid, void *other,
//                                     void *ex);

void SSL_CTX_set0_security_ex_data(SSL_CTX *ctx, void *ex);
void SSL_set0_security_ex_data(SSL *s, void *ex);

void *SSL_CTX_get0_security_ex_data(const SSL_CTX *ctx);
void *SSL_get0_security_ex_data(const SSL *s);

int SSL_CTX_up_ref(SSL_CTX *ctx);


typedef void* SSL_METHOD; // TODO
// struct SSL_METHOD {
//     int version;
//     int (*ssl_new) (SSL *s);
//     void (*ssl_clear) (SSL *s);
//     void (*ssl_free) (SSL *s);
//     int (*ssl_accept) (SSL *s);
//     int (*ssl_connect) (SSL *s);
//     int (*ssl_read) (SSL *s, void *buf, int len);
//     int (*ssl_peek) (SSL *s, void *buf, int len);
//     int (*ssl_write) (SSL *s, const void *buf, int len);
//     int (*ssl_shutdown) (SSL *s);
//     int (*ssl_renegotiate) (SSL *s);
//     int (*ssl_renegotiate_check) (SSL *s);
//     long (*ssl_get_message) (SSL *s, int st1, int stn, int mt, long
//                              max, int *ok);
//     int (*ssl_read_bytes) (SSL *s, int type, unsigned char *buf, int len,
//                            int peek);
//     int (*ssl_write_bytes) (SSL *s, int type, const void *buf_, int len);
//     int (*ssl_dispatch_alert) (SSL *s);
//     long (*ssl_ctrl) (SSL *s, int cmd, long larg, void *parg);
//     long (*ssl_ctx_ctrl) (SSL_CTX *ctx, int cmd, long larg, void *parg);
//     const SSL_CIPHER *(*get_cipher_by_char) (const unsigned char *ptr);
//     int (*put_cipher_by_char) (const SSL_CIPHER *cipher, unsigned char *ptr);
//     int (*ssl_pending) (const SSL *s);
//     int (*num_ciphers) (void);
//     const SSL_CIPHER *(*get_cipher) (unsigned ncipher);
//     const struct SSL_METHOD *(*get_ssl_method) (int version);
//     long (*get_timeout) (void);
//     struct ssl3_enc_method *ssl3_enc;
//     int (*ssl_version) (void);
//     long (*ssl_callback_ctrl) (SSL *s, int cb_id, void (*fp) (void));
//     long (*ssl_ctx_callback_ctrl) (SSL_CTX *s, int cb_id, void (*fp) (void));
// };

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);

const SSL_METHOD *TLS_method(void);
const SSL_METHOD *TLS_server_method(void);
const SSL_METHOD *TLS_client_method(void);

const SSL_METHOD *SSLv23_method(void);
const SSL_METHOD *SSLv23_server_method(void);
const SSL_METHOD *SSLv23_client_method(void);

const SSL_METHOD *SSLv3_method(void);
const SSL_METHOD *SSLv3_server_method(void);
const SSL_METHOD *SSLv3_client_method(void);

const SSL_METHOD *TLSv1_method(void);
const SSL_METHOD *TLSv1_server_method(void);
const SSL_METHOD *TLSv1_client_method(void);

const SSL_METHOD *TLSv1_1_method(void);
const SSL_METHOD *TLSv1_1_server_method(void);
const SSL_METHOD *TLSv1_1_client_method(void);

const SSL_METHOD *TLSv1_2_method(void);
const SSL_METHOD *TLSv1_2_server_method(void);
const SSL_METHOD *TLSv1_2_client_method(void);

const SSL_METHOD *DTLS_method(void);
const SSL_METHOD *DTLS_server_method(void);
const SSL_METHOD *DTLS_client_method(void);

const SSL_METHOD *DTLSv1_method(void);
const SSL_METHOD *DTLSv1_server_method(void);
const SSL_METHOD *DTLSv1_client_method(void);

const SSL_METHOD *DTLSv1_2_method(void);
const SSL_METHOD *DTLSv1_2_server_method(void);
const SSL_METHOD *DTLSv1_2_client_method(void);

int SSL_set_session_ticket_ext(SSL *s, void *ext_data, int ext_len);
int SSL_set_purpose(SSL *ssl, int purpose);
int SSL_use_psk_identity_hint(SSL *s, const char *identity_hint);