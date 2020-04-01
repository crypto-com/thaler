/* ctest.cpp */

#include <jni.h>
#include <stdio.h>
#include <string.h>

void jsonrpc( const char* storage, const char* url, const char* request,  char* buf, int buf_len);
  JNIEXPORT jstring JNICALL Java_CroBindings_jsonrpc
  (JNIEnv * e , jobject jobj, jstring storage, jstring url, jstring request)
  {
    const char *storage_str = (*e)->GetStringUTFChars(e,storage, 0);
    printf("C  storage=%s\n", storage_str);
    const char *url_str = (*e)->GetStringUTFChars(e,url, 0);
    printf("C  url=%s\n", url_str);    
    const char *request_str = (*e)->GetStringUTFChars(e,request, 0);
    printf("C  request=%s\n", request_str);
    char msg[1000] ;
    memset(msg, 0, sizeof(msg));
    jsonrpc(storage_str, url_str, request_str, msg, sizeof(msg));    
    jstring result=result = (*e)->NewStringUTF(e,msg); 
    (*e)->ReleaseStringUTFChars(e, storage, storage_str);
    (*e)->ReleaseStringUTFChars(e, url, url_str);
    (*e)->ReleaseStringUTFChars(e, url, request_str);
    return result;  
  }