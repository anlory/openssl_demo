#include <openssl/sha.h>   
#include <openssl/crypto.h>  // OPENSSL_cleanse  
#include <stdio.h>  
#include <string.h>  
#include<openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>


#define PRIVATEKEY "private_key"
#define PUBLICKEY "public_key"

void sha256(const char *string, char outputBuffer[65])
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, string, strlen(string));
  SHA256_Final(hash, &sha256);
  int i = 0;
  for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    sprintf( &outputBuffer[i * 2], "%02x", hash[i]);
  }
  outputBuffer[64] = 0;

}

int sha256_file(char *path, char outputBuffer[65])
{
  FILE *file = fopen(path, "rb");
  if(!file) return -534;

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  const int bufSize = 32768;
  unsigned char *buffer = malloc(bufSize);
  int bytesRead = 0;
  if(!buffer) 
    return -1;
  while((bytesRead = fread(buffer, 1, bufSize, file)))
  {
    SHA256_Update(&sha256, buffer, bytesRead);

  }
  SHA256_Final(hash, &sha256);
  int i = 0;
  for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
  }
  outputBuffer[64] = 0;

  //sha256_hash_string(hash, outputBuffer);
  fclose(file);
  free(buffer);
  return 0;

}


char *public_encrypt(char *str,char *path_key){
    char *p_en;
    RSA *p_rsa = NULL;
    FILE *file;
    int flen,rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        perror("open key file error");
        return NULL;    
    }   
    if((PEM_read_RSA_PUBKEY(file,&p_rsa,NULL,NULL))==NULL){
   // if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){
        ERR_print_errors_fp(stdout);
        return NULL;
    }   
    flen=strlen(str);
    rsa_len=RSA_size(p_rsa);
    p_en=(unsigned char *)malloc(rsa_len+1);
    memset(p_en,0,rsa_len+1);
    if(RSA_public_encrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING)<0){
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_en;
}


char *public_decrypt(char *str,char *path_key){
    char *p_en;
    RSA *p_rsa = NULL;
    FILE *file;
    int flen,rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        perror("open key file error");
        return NULL;    
    }   
    if((PEM_read_RSA_PUBKEY(file,&p_rsa,NULL,NULL))==NULL){
   // if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){
        ERR_print_errors_fp(stdout);
        return NULL;
    }   
    flen=strlen(str);
    rsa_len=RSA_size(p_rsa);
    p_en=(unsigned char *)malloc(rsa_len+1);
    memset(p_en,0,rsa_len+1);
    if(RSA_public_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING)<0){
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_en;
}

char *private_encrypt(char *str,char *path_key){
    char *p_de;
    RSA *p_rsa;
    FILE *file;
    int rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        perror("open key file error");
        return NULL;
    }
    if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    rsa_len=RSA_size(p_rsa);
    p_de=(unsigned char *)malloc(rsa_len+1);
    memset(p_de,0,rsa_len+1);
    if(RSA_private_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_de;
}

char *private_decrypt(char *str,char *path_key){
    char *p_de;
    RSA *p_rsa;
    FILE *file;
    int rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        perror("open key file error");
        return NULL;
    }
    if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    rsa_len=RSA_size(p_rsa);
    p_de=(unsigned char *)malloc(rsa_len+1);
    memset(p_de,0,rsa_len+1);
    if(RSA_private_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_de;
}



int main(int argc, char** argv) {  

  const char* string = "hello";  
  
  char mdString[SHA256_DIGEST_LENGTH*2+1];  
  char *ptr_en,*ptr_de;
  if(argc < 2){
    sha256(string,mdString);
    printf("SHA256 digest: %s\n", mdString);  
  }
  else
  {
    sha256_file(argv[1],mdString);
    printf("SHA256 digest: %s\n", mdString);  
  }
    ptr_en=public_encrypt(mdString,PUBLICKEY);
    printf("after encrypt:%d\n",strlen(ptr_en));
    ptr_de=private_decrypt(ptr_en,PRIVATEKEY);
    printf("after decrypt:%s\n",ptr_de);
    if(ptr_en!=NULL){
        free(ptr_en);
    }   
    if(ptr_de!=NULL){
        free(ptr_de);
    }   
	printf("------------------------\n");
	ptr_en=private_encrypt(mdString,PRIVATEKEY);
    printf("after encrypt:%d\n",strlen(ptr_en));
    ptr_de=public_decrypt(ptr_en,PUBLICKEY);
    printf("after decrypt:%s\n",ptr_de);
    if(ptr_en!=NULL){
        free(ptr_en);
    }   
    if(ptr_de!=NULL){
        free(ptr_de);
    }  
  
  
  return 0;  

}

