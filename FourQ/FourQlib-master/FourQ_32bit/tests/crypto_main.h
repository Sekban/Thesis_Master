#define PRIVATE_LOCATION "/tmp/secret" /* where the secret key are stored */
#define PUBLIC_LOCATION "/tmp/public" /* where the public key are stored */
#define NEW_PRIVATE_LOCATION PRIVATE_LOCATION "~" /* protect against IO failures during overwrites*/
#define NEW_PUBLIC_LOCATION PUBLIC_LOCATION "~" /* protect against IO failures during overwrites*/