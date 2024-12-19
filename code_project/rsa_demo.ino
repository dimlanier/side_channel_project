#ifndef _QQQ_RSA_H_
#define _QQQ_RSA_H_

#include <stdint.h>

#ifndef RSA_BITS
  //#define RSA_BITS 1024
  //#define RSA_BITS 768
  #define RSA_BITS 512
#endif


#define RSA_BYTES ((RSA_BITS)/8)

#define RSA_OK 0
#define RSA_BUFFER_TO_SMALL_FOR_BIGNUM 1
#define RSA_DATA_TOO_LARGE_FOR_MODULUS 2
#define RSA_DATA_TOO_LARGE_FOR_PADDING 3

// RSA512 encrypt raw
// plain text msg_enc[64] to encrypted msg_enc[RSA_BYTES], using modulus[RSA_BYTES]. modulus[RSA_BYTES] is unchanged
// NOTE: msg_enc should not be larger than modulus - use the rsa_pkcs_encrypt for correct padding.
// Input to rsa_ functions is MSB first as in openssl, bignum8 stores numbers LSB first
uint8_t rsa_encrypt_raw(uint8_t* modulus, uint8_t* msg_enc, uint8_t* expo,int expo_size);

// RSA512 encrypt with PKCS#1 v1.5 padding
// encrypt plain text msg[msglen] and random bytes rnd_enc[RSA_BYTES] to encrypted rnd_enc[RSA_BYTES], using modulus[RSA_BYTES]. modulus[RSA_BYTES] and msg[msglen] are unchanged
// NOTE: maximum msglen is RSA_BYTES-11


#endif // _QQQ_RSA_H_

#include <string.h>
#include <stdlib.h>


//============================================
//bignum8 header
typedef struct bignum8 {
  int length;
  int capacity;
  uint8_t* data;
} bignum8;

bignum8* bignum8_init(int capacity);
void bignum8_free(bignum8* b);
void bignum8_copy(bignum8* source, bignum8* dest);
void bignum8_multiply(bignum8* result, bignum8* b1, bignum8* b2);
int bignum8_bitlen(bignum8* v);
void bignum8_imodulate(bignum8* v, bignum8* n);
void bignum8_setlength(bignum8* b, int len);
void bignum8_setminlen(bignum8* v);
uint8_t bignum8_getminlen(bignum8* v);
bignum8* bignum8_encode(bignum8* m, bignum8* n,bignum8 exp);
bignum8* bignum8_frombin(uint8_t* bin, int len);
//============================================

bignum8* bignum8_init(int capacity) {
  bignum8* b = malloc(sizeof(bignum8));
  b->length = 0;
  b->capacity = capacity;
  b->data = calloc(capacity, sizeof(uint8_t));
  return b;
}

void bignum8_free(bignum8* b) {
  free(b->data);
  free(b);
}

//copy value with adjusting capacity, returns 0 on success.
void bignum8_copy(bignum8* source, bignum8* dest) {
  int minlen = bignum8_getminlen(source);
  bignum8_setlength(dest, minlen);
  dest->length = minlen;
  memcpy(dest->data, source->data, minlen);
}

void bignum8_multiply(bignum8* result, bignum8* a, bignum8* b) {
  //result value: allocate and zero memory
  bignum8_setlength(result, a->length + b->length);
  for(int i = 0; i < a->length + b->length; i++) result->data[i] = 0;
  
  for(int i = 0; i < a->length; i++) {
    for(int j = 0; j < b->length; j++) {
      uint16_t carry = ((uint16_t)a->data[i] * b->data[j]);
      int k = 0;
      while(carry > 0) {
        carry += result->data[i+j+k];
        result->data[i+j+k] = carry;
        carry >>= 8;
        k++;
      }
    }
  }
}

//#####################################################

//shift right 1 bit
void shift_r1(unsigned char *a, int len) {
  if(a[0]&1) return; // printf("ERROR"); //TODO
  for(int i=0;i<len-1;i++) a[i]= (a[i]>>1) | ((a[i+1]&0x01)<<7);
  a[len-1]= (a[len-1]>>1);
}

//shift left 1 bit
void shift_l1(unsigned char *a, int len) {
  for(int i=len-1;i>0;i--) a[i]= (a[i]<<1) | ((a[i-1]&0x80)>>7);
  a[0]= (a[0]<<1);
}

//shift left 8 bits
void shift_l8(unsigned char *a, int len){
  for(int i=len-1;i>0;i--) a[i]=a[i-1];
  a[0]=0;
}

//get minimum length to hold number (left trim zeroes)
uint8_t bignum8_getminlen(bignum8* v){
  return (bignum8_bitlen(v)+7)/8;
}

//count number of bits
int bignum8_bitlen(bignum8* v){
  for(int i=v->length-1;i>=0;i--) {
    if(v->data[i]!=0) {
      int bit = 7;
      uint8_t mask = 1<<bit;
      while(mask) {
        if(v->data[i]&mask) return i*8+bit+1;
        mask >>= 1;
        bit--;
      }
    }
  }
  return 0;
}

void bignum8_imodulate(bignum8* v, bignum8* n){
  int vlen = bignum8_bitlen(v);
  int nlen = bignum8_bitlen(n);
  int shift = vlen-nlen; //v is this many bits shifted from n
  if(shift<0) return; //v<n -> all done

  //make sure one byte additional is available for shifting/subtracting/adding
  bignum8_setlength(n, (nlen+7)/8+1);
  bignum8_setlength(v, (vlen+7)/8+1);

  //shift n into bit position
  for(int i=0;i<shift%8;i++) {
    shift_l1(n->data,n->length);
  }

  while(shift>=0) {
    int byteshift = shift / 8;

    //subtract shifted n from v
    uint16_t carry = 0;
    for(int i=0;i<n->length;i++) {
      carry += v->data[byteshift+i];
      carry -= n->data[i];
      v->data[byteshift+i] = carry & 0xff;
      if(carry&0x100) carry=0xffff; else carry=0;
    }

    if(carry!=0) {
      //too much subtracted -> restore v by adding shifted n to v
      carry=0;
      for(int i=0;i<n->length;i++) {
        carry += v->data[byteshift+i];
        carry += n->data[i];
        v->data[byteshift+i] = carry & 0xff;
        if(carry&0x100) carry=1; else carry=0;
      }
    }

    shift--;
    if(shift>=0) {
      if((shift%8)==7) shift_l8(n->data,n->length);
      shift_r1(n->data,n->length);
    }
  }
  
  //set length
  v->length = bignum8_bitlen(v)/8+1;
  n->length = bignum8_bitlen(n)/8+1;
}

//adjust length
void bignum8_setlength(bignum8* b, int len) {
  if(b->capacity < len) {
//    Serial.print("setlength() WITH realloc from ");
//    Serial.print(b->capacity);
//    Serial.print(" to ");    
//    Serial.println(len);
    b->capacity = len;
    b->data = realloc(b->data, b->capacity);
  }else{
//    Serial.println("setlength() NO realloc\n");
  }
  for(int i=b->length; i<len; i++) b->data[i]=0; //zero the new bytes
  b->length = len;
}
// Check if bignum8 is zero
int bignum8_is_zero(bignum8* b) {
  for (int i = 0; i < b->length; i++) {
    if (b->data[i] != 0) {
      return 0;
    }
  }
  return 1;
}
// Set the minimum length of bignum8
void bignum8_setminlen(bignum8* v) {
  int minlen = bignum8_getminlen(v);
  bignum8_setlength(v, minlen);
}
// Print bignum8 in decimal form
void bignum8_print(bignum8* b) {
  bignum8* temp = bignum8_init(b->capacity);
  bignum8_copy(b, temp);

  if (bignum8_is_zero(temp)) {
    printf("0\n");
    bignum8_free(temp);
    return;
  }

  char* str = malloc(temp->length * 3 + 1); // Allocate enough space for decimal digits
  int pos = 0;

  while (!bignum8_is_zero(temp)) {
    uint16_t remainder = 0;
    for (int i = temp->length - 1; i >= 0; i--) {
      uint16_t value = (remainder << 8) + temp->data[i];
      temp->data[i] = value / 10;
      remainder = value % 10;
    }
    str[pos++] = remainder + '0';
    bignum8_setminlen(temp);
  }

  for (int i = pos - 1; i >= 0; i--) {
    putchar(str[i]);
  }
  putchar('\n');

  free(str);
  bignum8_free(temp);
}
// Shift bignum8 right by 1 bit
void bignum8_shift_right1(bignum8* b) {
  uint8_t carry = 0;
  for (int i = b->length - 1; i >= 0; i--) {
    uint8_t new_carry = b->data[i] & 1;
    b->data[i] = (b->data[i] >> 1) | (carry << 7);
    carry = new_carry;
  }
  if (b->length > 0 && b->data[b->length - 1] == 0) {
    b->length--;
  }
}
//encode with exponent=3
bignum8* bignum8_encode(bignum8* m, bignum8* n,bignum8 exp) {
  bignum8 *ans=bignum8_init(n->capacity);
  bignum8 *v = bignum8_init(n->capacity);
  bignum8 *v2 = bignum8_init(n->capacity);
  bignum8_setlength(ans, 1);
  ans->data[0] = 1;
  bignum8_copy(m, v);
    while (!bignum8_is_zero(&exp)) {
      if (exp.data[0]%2==1) {
        digitalWrite(LED_BUILTIN,HIGH);
        bignum8_multiply(v2, v, ans);
        bignum8_imodulate(v2, n);
        bignum8_copy(v2, ans);  
        digitalWrite(LED_BUILTIN,LOW);
      }
      bignum8_multiply(v2, v, v);
      bignum8_imodulate(v2, n);
      bignum8_copy(v2, v);
      bignum8_shift_right1(&exp);
    }
    bignum8_free(v);
    bignum8_free(v2);
  return ans;
}

//reverse bin
bignum8* bignum8_frombin(uint8_t* bin, int len) {
  bignum8* v = bignum8_init(len+1); //alloc 1 byte extra to prevent reallocs when doing operations
  v->length = len; 
  for(int i = len-1; i>=0; i--) v->data[i] = bin[len-1-i];

  return v;
}
//returns 1 on success, 0 on failure
uint8_t bignum8_tobin(bignum8* v, uint8_t* bin, int len) {
  uint8_t minlen = bignum8_getminlen(v);
  if(minlen>len) return RSA_BUFFER_TO_SMALL_FOR_BIGNUM;
  memset(bin, 0, len);
  for(int i = minlen-1; i>=0; i--) bin[minlen-1-i] = v->data[i]; 
  return RSA_OK;
}
uint8_t rsa_encrypt_raw(uint8_t* modulus, uint8_t* msg_enc,uint8_t* exp,int exp_size) {
  uint8_t retval;
  //check msg < modulus CAUTION : This ligne have to be decommented for debugging
  //if(msg_enc[0] >= modulus[0]) return RSA_DATA_TOO_LARGE_FOR_MODULUS;
  
  
  bignum8* exp_bignum = bignum8_frombin(exp, exp_size);


  //load modulus
  bignum8 *n8 = bignum8_frombin(modulus, RSA_BYTES);

  bignum8 *m8 = bignum8_frombin(msg_enc, RSA_BYTES);
  
  
 
   // adjust the delay corresponding to what we want (let the time for the signal to reach)
  //compute crypt
  bignum8 *c8 = bignum8_encode(m8,n8,*exp_bignum);
  



  //store result
  retval = bignum8_tobin(c8, msg_enc, RSA_BYTES);

  bignum8_free(c8);
  bignum8_free(m8);
  bignum8_free(n8);
  

  return retval;
}








/*
RSA: 2408 bytes flash 
RSA512 needs 5 * (64+1 + 4) =  345 bytes RAM (//alloc 1 byte extra to prevent reallocs when doing operations + 2 byte len + 2 byte capacity)
440ms @ 16MHz = 2.7M Cycles

#generate rsa keys on linux for example a Raspberry Pi:
openssl genrsa -3 -out rsa512.pem 512
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKLIhiD7MXmki18SbXDYEpIqLhUWdZFeC3UvLeFzwaiRyi1pZMtE
GQF8Y3gMnjk5SjEOy1KbAfOu928KFC7Vpg8CAQMCQGyFrsCndlEYXOoMSPXlYbbG
yWNkTmDpXPjKHpZNK8W1dlDCzL07C+pqAEo9lG+a26YoCKKisKuE2g5blWfkPQsC
IQDVsWmTpyOuiZyJmjV1A6wJMiMrafWS3udFK+XHGGrnGQIhAMMC254IR9iYQNlu
esqOJPeFr5L0sWYTgGstmuz6lGNnAiEAjnZGYm9tHwZoW7wjo1fIBiFsx5v5DJSa
Lh1D2hBHRLsCIQCCAee+sC/lutXmSacxtBilA8ph+HZEDQBHc7yd/GLs7wIhAJwj
RYacHiwKw4Fh91C2P7GWGzYhcIAX6s/Y/USkTycp
-----END RSA PRIVATE KEY-----

#get modulus as hex string
openssl rsa -in rsa512.pem -noout -modulus | sed 's/Modulus=//'
A2C88620FB3179A48B5F126D70D812922A2E151675915E0B752F2DE173C1A891CA2D6964CB4419017C63780C9E39394A310ECB529B01F3AEF76F0A142ED5A60F

#raw encrypt
echo '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' | xxd -r -p - | openssl rsautl -raw -encrypt -inkey rsa512.pem | xxd -p -c256 -
299da147204aaab26f8c26fb9f11b7f92365fe083d10a87ebab49dbc787d01a4178fb5d8c07d6732ca3258e739222d7ad1473ad7b6fc14f929a6737d1856d29f

#raw decrypt
echo '299da147204aaab26f8c26fb9f11b7f92365fe083d10a87ebab49dbc787d01a4178fb5d8c07d6732ca3258e739222d7ad1473ad7b6fc14f929a6737d1856d29f' | xxd -r -p - | openssl rsautl -raw -decrypt -inkey rsa512.pem | xxd -p -c256 -
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f

#pkcs decrypt for raw encrypted plain text
echo '299da147204aaab26f8c26fb9f11b7f92365fe083d10a87ebab49dbc787d01a4178fb5d8c07d6732ca3258e739222d7ad1473ad7b6fc14f929a6737d1856d29f' | xxd -r -p - | openssl rsautl -pkcs -decrypt -inkey rsa512.pem | xxd -p -c256 -
RSA operation error - padding check failed

#pkcs decrypt for pkcs encrypted plain text
echo '0B91BCE41408BC687F0C45495410ECFBA0592FB61AF7DBAD26FDF4F806912286740FB64161266F3697473F8BC8E4D9FAC1F37D7F4251956ECB4CA909B492583B' | xxd -r -p - | openssl rsautl -pkcs -decrypt -inkey rsa512.pem | xxd -p -c256 -
0001020304
#raw decrypt for pkcs encrypted plain text
echo '0B91BCE41408BC687F0C45495410ECFBA0592FB61AF7DBAD26FDF4F806912286740FB64161266F3697473F8BC8E4D9FAC1F37D7F4251956ECB4CA909B492583B' | xxd -r -p - | openssl rsautl -raw -decrypt -inkey rsa512.pem | xxd -p -c256 -
0002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000001020304

#show info
openssl rsa -in rsa512.pem -text


PKCS1-V1_5-ENCRYPT ((n, e), M)

   Input:
   (n, e)   recipient's RSA public key (k denotes the length in octets
            of the modulus n)
   M        message to be encrypted, an octet string of length mLen,
            where mLen <= k - 11

   Output:
   C        ciphertext, an octet string of length k

   Error: "message too long"

   Steps:

   1. Length checking: If mLen > k - 11, output "message too long" and
      stop.

   2. EME-PKCS1-v1_5 encoding:

      a. Generate an octet string PS of length k - mLen - 3 consisting
         of pseudo-randomly generated nonzero octets.  The length of PS
         will be at least eight octets.

      b. Concatenate PS, the message M, and other padding to form an
         encoded message EM of length k octets as

            EM = 0x00 || 0x02 || PS || 0x00 || M.


RSA768 e=3 key used in example:

-----BEGIN RSA PRIVATE KEY-----
MIIByQIBAAJhAKuFrORWoerYrwycoe5OzqrfPZoRRuaK6zP3N4E01y3KxwKuqYUy
kA0GPptUS3z/L/wjENTAGdd9+uZMJjkrED+ygZ/+Ec+7Pmln2rOggJwhTnsw61TY
RFTSUU+KsiS4YQIBAwJgclkd7Y8WnJB0sxMWnt80ceopEWDZ7wdHd/olAM3kyTHa
AcnGWMxgCK7UZ42HqKoe5RzGbzpdmJPPCaOuWYIjPzbZyBlbDaA3idgYxzF6fbq3
RxpdzEaOCqCvAIHiA/gDAjEA4zn5ZryhAKeH2RN2R0YJj0CYJgNfjp+w+6M1lWzy
//eI2oNgP6totmBR3kPwQG5nAjEAwT3txyvscfi8fsMqa6HR0Z+izdSprKs6HwB/
82lV35GytgX+YsMGjoD48IPu3lX3AjEAl3v7mdMWAG+v5gz5hNlbtNW6xAI/tGp1
/Rd5Dkih//pbPFeVf8ebJEA2lC1K1Z7vAjEAgNPz2h1IS/soVIIcR8E2i7/B3o3G
cxzRagBVTPDj6mEhzq6plyyvCatQoFf0lDlPAjBapuYCuaMv8wvL0IfaaOOtuIb+
h4rLUKG82YhyDzcesqf3rV4utaOZWDasUBEcuqM=
-----END RSA PRIVATE KEY-----


RSA1024 e=3 key used in example:

-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDY4UB1dtkQAyZEVs8ZNuSa1w+nXPOox8Dqgyuvg79p7mdce7PD
gpTtzr5izPHqooyJb0hhuG+P0Wp3eKlDtxd1OaE1zNQX6sgrT4BuE+VJCmoxu3ES
FUiEK/p05RVYIxd5Wg3GHAfxcizdJ6IkU6dBhcFRsMARE0ewLpZyFp7FpwIBAwKB
gQCQlir4+eYKrMQtjzS7ee28j1/E6KJwhStHAh0frSpGnu+S/SKCVw3z3ymXM0vx
wbMGSjBBJZ+1Nkb6UHDXz2T3lrizAhFKwOUi/J/WKp7jeTATvkUnjcvo1vR9hFD4
kFOQpTOkpQhjfjFtSIT+bL0HRxpuPobDSPSmBcLU37Vh2wJBAPQFRl8jN/iekH0D
68Byuw1ybcr2xbtbWUxwNmNC/Nv/Pgf3QCcIydyuFgBd9WfdGBKo3NZZOYWYx/Oa
58pNMksCQQDjhuLqlu/Q0eZXjMEThDjHL6ZTEpEFO02dG4I7WOZumuJaSQ79cpJY
NKM6fLFIrp6IcM98nLKgP+8yV0r8wYCVAkEAoq4u6hd6pb8K/gKdKvcnXkxJMfnZ
J5I7iErO7NdTPVTUBU+AGgXb6HQOqulORT4QDHCTOZDRA7sv97yaht4hhwJBAJev
QfG59TXhRDpd1g0C0ITKbuIMYK4niRNnrCeQmZ8R7DwwtKj3DDrNwib9y4XJvwWg
ilMTIcAqn3bk3KiBAGMCQQDEy+xBwYrguJl7PBAuMHOPfAogczQwUpycRlWCwZUu
xtl7xqLuXNDNLxvp8RYynbaEtAHFxHNVqivMEDM/Tlif
-----END RSA PRIVATE KEY-----

RSA1024 e=65537 key used in example:

-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDD0yqK4/r6zkSpbutQ1ru/vAlYLd5cdTLuqwVK4iWUoPWI2DU+
dko/uDBP6dVYFq4MuVLNxZlkVxUBUuLxy1lT/HEMt/G22wJypfWClqqSScfr5j/a
UOI1CYTXCZlfDTiVbHV+P9Vo9yTq1GLTyHclpGojyc6ldPP4DJObPd5crwIDAQAB
AoGAD8hbK2qIdeJeAlHgQVmtNBzRm/vGaik/+6BpAsoLQVlfsLHMSMZ74XrU2fv8
p+bcDEZ7d/4vCLlEBiFKDTbYchop5YEhmb+han3x9x4wez1IbyrWZcDqTrwfqyv/
01PDtL0balE1i7AJ5s3pNFPrfyNqttvYw8sdxW9oZS6WVKECQQD2oIJpyW3JRSi9
kFXV9CfUZSzpf1+dEZN6GfCZUNgBQsGbGKAnNqRpHOLyKqdc11t+WDuu+1nQBmGc
9HZSDg+nAkEAy0RkKSwevzFokc/YtFMWVQajTL4f0AT96pypMWwicz2hX45Uzw4A
3gVfbFk3UcBnntsHe9+fmA6ddHn9hMwruQJBAKy26525+rChRk667eHQArSzxigf
k44j6OvxjpVQEHWRkpRTQpUzpyAVormFNX/HMcPhdqqsS9FrJqEMcnA0eLECQHyV
Zm51xEKbHeSA5+leI4npj50xyn3NEXQCoRDRnivT0lym+AQQKSfrUxktdWJ98wTC
akvaPA8OpiMFwgTqvsECQQCqg7p8YdYZkgQxr4/2uSFxKz7jrJhAOT2JCKndQfei
R5gQ3k+RnG2uDA3EHhztddN5AzPrZV90gMtBfzlcWAEg
-----END RSA PRIVATE KEY-----

            
*/



//RSA512 example
const char* modulus_s= "A2C88620FB3179A48B5F126D70D812922A2E151675915E0B752F2DE173C1A891CA2D6964CB4419017C63780C9E39394A310ECB529B01F3AEF76F0A142ED5A60F";
const char* crypt_s=   "299DA147204AAAB26F8C26FB9F11B7F92365FE083D10A87EBAB49DBC787D01A4178FB5D8C07D6732CA3258E739222D7AD1473AD7B6FC14F929A6737D1856D29F"; 
const char* pkcs_s=    "0B91BCE41408BC687F0C45495410ECFBA0592FB61AF7DBAD26FDF4F806912286740FB64161266F3697473F8BC8E4D9FAC1F37D7F4251956ECB4CA909B492583B";
/*
//RSA768 example
const char* modulus_s= "AB85ACE456A1EAD8AF0C9CA1EE4ECEAADF3D9A1146E68AEB33F7378134D72DCAC702AEA98532900D063E9B544B7CFF2FFC2310D4C019D77DFAE64C26392B103FB2819FFE11CFBB3E6967DAB3A0809C214E7B30EB54D84454D2514F8AB224B861";
const char* crypt_s=   "";
const char* pkcs_s=    "";
*/

/*//RSA1024 example
const char* modulus_s= "D8E1407576D91003264456CF1936E49AD70FA75CF3A8C7C0EA832BAF83BF69EE675C7BB3C38294EDCEBE62CCF1EAA28C896F4861B86F8FD16A7778A943B7177539A135CCD417EAC82B4F806E13E5490A6A31BB71121548842BFA74E515582317795A0DC61C07F1722CDD27A22453A74185C151B0C0111347B02E9672169EC5A7";
//note: strings commented out as it does not fit in memory...
const char* crypt_s= ""; // "42D37E36C30F12959E7FEBA2CA1C887DFE1F1000211D879ECEB1F47F9DB74802B740D5BABCBF3AFBF502F86B1B6CBB3FD210F456928F8FDEB4B569FC9FE8C45C68A8FEE3DD50D71E1521DA96A6C9206E92AB77010345E09FBC0BFF3849F87137577D5F9F7611A67C3CF8F82E5844D4A9DB759DBC3683082D4FCD072E61951B6B";
const char* pkcs_s= ""; //   "54DBCFFA88C301182644E30E5B91926675FC23D93DB6968A1253968665210A3815B4E07E32A612C9D5691C594DC81045133FCB7F5919337D74AD89B5986026010E8EB583964ECB8101503EDAB36BC34772E6ABE56A69D4FBA29C71A0A94FFA79C7FA3283FF06BEFD81B35A7EE5D447A587D619F3B0BAE849027D975FE0234F72";
*/
/*
//RSA1024 e=65537 example
const char* modulus_s= "C3D32A8AE3FAFACE44A96EEB50D6BBBFBC09582DDE5C7532EEAB054AE22594A0F588D8353E764A3FB8304FE9D55816AE0CB952CDC5996457150152E2F1CB5953FC710CB7F1B6DB0272A5F58296AA9249C7EBE63FDA50E2350984D709995F0D38956C757E3FD568F724EAD462D3C87725A46A23C9CEA574F3F80C939B3DDE5CAF";
const char* crypt_s= "";
const char* pkcs_s= "";
*/

//convert hex string to binary, returns len
uint8_t hex2bin(const char* string, uint8_t *bin, uint8_t binlen) { 
  int i=0;   
  uint8_t b=0;
  int nibble = 0;
  int pos=0;
  while(string[i] != '\0' && pos < binlen) {
    char c = string[i];
    if(c>='0' && c<='9') {
      nibble++;
      b = b*0x10 + c - '0'; 
    }else if(c>='A' && c<='F'){
      nibble++;
      b = b*0x10 + c - 'A' + 10; 
    }else if(c>='a' && c<='f'){
      nibble++;
      b = b*0x10 + c - 'a' + 10; 
    }
    i++;
    if(nibble==2) {
      bin[pos++] = b;
      b=0;
      nibble=0;
    }
  }
  //trailing nibble
  if(nibble>0) bin[pos++] = b;
  return pos;
}

void printbin(uint8_t* b, uint8_t len) {
  for (int i=0; i<len; i++) { 
    if (b[i]<0x10) Serial.print("0");
    Serial.print(b[i],HEX); 
  }
  Serial.print(" len=");
  Serial.print(len);
}

void printbinreverse(uint8_t* b, uint8_t len) {
  for (int i=len-1; i>=0; i--) { 
    if (b[i]<0x10) Serial.print("0");
    Serial.print(b[i],HEX); 
  }
  Serial.print(" len=");
  Serial.print(len);
}


void setup() {
  Serial.begin(9600);
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.println("RSA Test v8");
}

int i;
void loop() {
  
  
  test512();
  delay(10000);
  
 
 
 
}



void test512(void){

  uint8_t modulus[RSA_BYTES];
  uint8_t expo[3] = {0xf6,0x1d,0x11};



 

  uint8_t msg[RSA_BYTES] ; // message is 456
  memset(msg, 0, RSA_BYTES);
  msg[RSA_BYTES-3]=0xf3;
  msg[RSA_BYTES-2]=0x01;
  msg[RSA_BYTES-1]=0xC8;
  
 

  uint8_t rv = rsa_encrypt_raw(modulus, msg,expo,3);
  
  
  
 
}
