//  Sentinel-R1  – Prototype
//  Build :  gcc sentinel_r1.c -o sentinel_r1 -lcrypto -lpthread -lssl
//  Hash  :  sha256sum sentinel_r1 | head -c 64 > sentinel_r1.hash
//  Run   :  nohup ./sentinel_r1 > /dev/null 2>&1 &
//  Kill  :  kill -USR1 $(pidof sentinel_r1)  →  enter 4269

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/inotify.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <time.h>

// CONFIG
#define SECRET_CODE      4269
#define CYCLE_SEC        4
#define MEM_SZ           4096
#define BIN_PATH         "./sentinel_r1"
#define HASH_PATH        "sentinel_r1.hash"
#define LOG_PATH         "sentinel.log"
#define QUAR_DIR         "/tmp/quarantine"

// GLOBALS
static volatile sig_atomic_t g_quit=0, g_ask_exit=0;
static unsigned char        *g_mem=NULL;  static unsigned long g_mem_sum;

// LOGGING
static pthread_mutex_t log_mtx = PTHREAD_MUTEX_INITIALIZER;
static void log_line(const char *tag,const char *fmt,...)
{
    FILE *f=fopen(LOG_PATH,"a"); if(!f) return;
    pthread_mutex_lock(&log_mtx);
    va_list v; va_start(v,fmt);
    time_t t=time(NULL); struct tm tm; localtime_r(&t,&tm);
    fprintf(f,"[%s] %04d-%02d-%02d %02d:%02d:%02d  ",
            tag,tm.tm_year+1900,tm.tm_mon+1,tm.tm_mday,
            tm.tm_hour,tm.tm_min,tm.tm_sec);
    vfprintf(f,fmt,v);  fputc('\n',f);
    va_end(v);
    pthread_mutex_unlock(&log_mtx);
    fclose(f);
}

// HASH / IMMUTABILITY
static void lock_code_ro(void){
    extern char __executable_start, _etext;
    size_t len=&_etext-&__executable_start;
    mprotect(&__executable_start,len,PROT_READ|PROT_EXEC);
}
static int sha256_file(const char *p,unsigned char out[SHA256_DIGEST_LENGTH]){
    FILE *fp=fopen(p,"rb"); if(!fp) return -1;
    unsigned char buf[32768]; size_t n;
    SHA256_CTX ctx; SHA256_Init(&ctx);
    while((n=fread(buf,1,sizeof buf,fp))) SHA256_Update(&ctx,buf,n);
    fclose(fp); SHA256_Final(out,&ctx); return 0;
}
static int verify_self(void){
    unsigned char ref[SHA256_DIGEST_LENGTH],cur[SHA256_DIGEST_LENGTH];
    FILE*f=fopen(HASH_PATH,"rb");
    if(!f||fread(ref,1,sizeof ref,f)!=sizeof ref){return -1;} fclose(f);
    if(sha256_file(BIN_PATH,cur)) return -1;
    return memcmp(ref,cur,sizeof ref)?-1:0;
}

// MEMORY GUARD
static unsigned long mem_sum(const unsigned char*m,size_t s)
{ unsigned long v=0; for(size_t i=0;i<s;i++) v+=m[i]; return v; }
static void heal_mem(void){
    for(size_t i=0;i<MEM_SZ;i++) g_mem[i]=rand()%256;
    g_mem_sum=mem_sum(g_mem,MEM_SZ);
    log_line("HEAL","protected memory reset");
}

// CPU LOAD
static int cpu_pct(void){
    FILE*f=fopen("/proc/stat","r"); if(!f) return 0;
    char l[128]; fgets(l,sizeof l,f); fclose(f);
    unsigned long u,n,s,i; sscanf(l,"cpu %lu %lu %lu %lu",&u,&n,&s,&i);
    static unsigned long pu, pn, ps, pi;
    unsigned long du=u-pu, dn=n-pn, ds=s-ps, di=i-pi;
    pu=u; pn=n; ps=s; pi=i;
    unsigned long busy=du+dn+ds, total=busy+di;
    return total? (int)(busy*100/total):0;
}

// PROCESS SWEEP
static const char *bad_words[]={"virus","crypt","mal",NULL};
static int cmd_bad(const char*c){
    for(int i=0;bad_words[i];i++)
        if(strcasestr(c,bad_words[i]))return 1;
    return 0;
}
static void sweep_proc(void){
    DIR*d=opendir("/proc"); if(!d) return;
    struct dirent*e; char p[256],c[256];
    while((e=readdir(d))){
        if(e->d_type!=DT_DIR)continue;
        int pid=atoi(e->d_name); if(pid<=0||pid==getpid())continue;
        snprintf(p,sizeof p,"/proc/%d/cmdline",pid);
        int fd=open(p,O_RDONLY); if(fd==-1)continue;
        int n=read(fd,c,sizeof c-1); close(fd); if(n<=0)continue; c[n]='\0';
        if(cmd_bad(c)){ kill(pid,SIGKILL); log_line("STRIKE","%s",c);}
    }closedir(d);
}

// INOTIFY FILE WATCH
static const char *watch_dirs[]={"/tmp",NULL};
static const char *bad_names[] ={"virus","crypt",".exe",".sh",NULL};
static int bad_file(const char*f){
    for(int i=0;bad_names[i];i++)
        if(strcasestr(f,bad_names[i]))return 1;
    return 0;
}
static void* watch_thread(void*arg){
    int fd=inotify_init1(IN_NONBLOCK); if(fd<0){perror("inotify");return NULL;}
    for(int i=0;watch_dirs[i];i++)
        inotify_add_watch(fd,watch_dirs[i],IN_CLOSE_WRITE);
    char buf[4096];
    mkdir(QUAR_DIR,0700);

    while(!g_quit){
        int len=read(fd,buf,sizeof buf);
        if(len<=0){sleep(1);continue;}
        for(char*p=buf;p<buf+len;){
            struct inotify_event *ev=(struct inotify_event*)p;
            if(ev->len && (ev->mask&IN_CLOSE_WRITE)){
                if(bad_file(ev->name)){
                    char src[512],dst[512];
                    snprintf(src,sizeof src,"%s/%s",watch_dirs[0],ev->name);
                    snprintf(dst,sizeof dst,"%s/%s.%ld",QUAR_DIR,ev->name,time(NULL));
                    rename(src,dst);
                    log_line("QUAR","%s",ev->name);
                }
            }
            p+=sizeof *ev+ev->len;
        }
    }return NULL;
}

// SIGNALS
static void s_usr1(int s){ g_ask_exit=1;}
static void s_nop (int s){}

// EXIT
static void ask_exit(void){
    int c; printf("kill-code: "); fflush(stdout);
    if(scanf("%d",&c)==1 && c==SECRET_CODE) g_quit=1;
    else log_line("INTRUDE","wrong kill code");
    g_ask_exit=0;
}

int main(void)
{
    srand(time(NULL));
    if(verify_self()){fprintf(stderr,"hash fail\n");return 1;}
    lock_code_ro();
    g_mem=malloc(MEM_SZ); for(size_t i=0;i<MEM_SZ;i++) g_mem[i]=rand()%256;
    g_mem_sum=mem_sum(g_mem,MEM_SZ);

    pthread_t th; pthread_create(&th,NULL,watch_thread,NULL);

    signal(SIGUSR1,s_usr1);
    signal(SIGINT ,s_nop);
    signal(SIGTERM,s_nop);

    log_line("BOOT","Sentinel online");

    int cpu_alert=0;
    while(!g_quit){
        sleep(CYCLE_SEC);

        // memory
        if(mem_sum(g_mem,MEM_SZ)!=g_mem_sum) heal_mem();

        // cpu
        int load=cpu_pct();
        if(load>90){ if(++cpu_alert>=3){
            log_line("CPU","overload %d%%",load); cpu_alert=0;} }
        else cpu_alert=0;

        // processes
        sweep_proc();

        // exit?
        if(g_ask_exit) ask_exit();
    }
    g_quit=1; pthread_join(th,NULL);
    log_line("EXIT","Sentinel shutdown");
    return 0;
}
