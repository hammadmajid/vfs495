/* Minimal LD_PRELOAD logger for libusb-0.1 bulk I/O, for tracing HP's
 * validity-sensor during live RE. Logs to $VFS_USBLOG (default stderr).
 * Ours (not HP's); safe to commit. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
static FILE *lg(void){ static FILE*f; if(!f){ const char*p=getenv("VFS_USBLOG");
  f=p?fopen(p,"w"):stderr; if(!f)f=stderr; } return f; }
static void hex(const char*tag,int ep,const char*b,int n){
  FILE*f=lg(); fprintf(f,"%s ep=0x%02x len=%d ",tag,ep,n);
  for(int i=0;i<n && i<20000;i++) fprintf(f,"%02x",(unsigned char)b[i]);
  fprintf(f,"\n"); fflush(f);
}
typedef int (*bw_t)(void*,int,char*,int,int);
int usb_bulk_write(void*d,int ep,char*b,int n,int t){
  static bw_t r; if(!r)r=(bw_t)dlsym(RTLD_NEXT,"usb_bulk_write");
  hex("W",ep,b,n); return r(d,ep,b,n,t);
}
int usb_bulk_read(void*d,int ep,char*b,int n,int t){
  static bw_t r; if(!r)r=(bw_t)dlsym(RTLD_NEXT,"usb_bulk_read");
  int rc=r(d,ep,b,n,t); if(rc>0) hex("R",ep,b,rc); else hex("R(err)",ep,b,0); return rc;
}
