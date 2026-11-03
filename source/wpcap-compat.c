/* App-local 32-bit compatibility adapter for ipsendwin 2.4.
 * Does not modify Npcap, Windows configuration, or ipsendwin.exe.
 * Calls the installed Npcap by absolute path and moves the first
 * IPv4-capable non-loopback interface to the front of its returned list.
 */
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef int BOOL;
typedef void *HANDLE;
#define WINAPI __attribute__((stdcall))
#define CDECL __attribute__((cdecl))
__declspec(dllimport) unsigned int WINAPI GetSystemDirectoryW(WORD *, unsigned int);
__declspec(dllimport) HANDLE WINAPI LoadLibraryW(const WORD *);
__declspec(dllimport) void * WINAPI GetProcAddress(HANDLE, const char *);
typedef struct Address { struct Address *next; void *addr, *netmask, *broadaddr, *dstaddr; } Address;
typedef struct Device { struct Device *next; char *name, *description; Address *addresses; unsigned int flags; } Device;
static HANDLE library;
static void *lookup(const char *name) {
    WORD path[300];
    static const WORD suffix[] = {'\\','N','p','c','a','p','\\','w','p','c','a','p','.','d','l','l',0};
    unsigned int n, i;
    if (!library) {
        n = GetSystemDirectoryW(path, 280);
        if (!n || n >= 280) return 0;
        for (i=0; i<sizeof(suffix)/sizeof(suffix[0]); ++i) path[n+i] = suffix[i];
        library = LoadLibraryW(path);
    }
    return library ? GetProcAddress(library, name) : 0;
}
static int ipv4(Device *d) {
    Address *a;
    if (d->flags & 1) return 0; /* PCAP_IF_LOOPBACK */
    for (a=d->addresses; a; a=a->next)
        if (a->addr && *(WORD *)a->addr == 2) return 1;
    return 0;
}
int CDECL pcap_findalldevs(Device **head, char *error) {
    typedef int (CDECL *Fn)(Device **, char *);
    Fn fn=(Fn)lookup("pcap_findalldevs");
    Device *prev, *d;
    int r;
    if (!fn) { if (head) *head=0; if(error) error[0]=0; return -1; }
    r=fn(head,error);
    if (r || !head || !*head || ipv4(*head)) return r;
    for (prev=*head, d=prev->next; d; prev=d, d=d->next) {
        if(ipv4(d)) { prev->next=d->next; d->next=*head; *head=d; break; }
    }
    return r;
}
void * CDECL pcap_open_live(const char *name, int length, int promiscuous, int timeout, char *error) {
    typedef void *(CDECL *Fn)(const char *, int, int, int, char *);
    Fn fn=(Fn)lookup("pcap_open_live");
    return fn ? fn(name,length,promiscuous,timeout,error) : (void *)0;
}
int CDECL pcap_sendpacket(void *handle, const unsigned char *data, int size) {
    typedef int (CDECL *Fn)(void *,const unsigned char *,int);
    Fn fn=(Fn)lookup("pcap_sendpacket");
    return fn ? fn(handle,data,size) : -1;
}
void CDECL pcap_close(void *handle) {
    typedef void (CDECL *Fn)(void *);
    Fn fn=(Fn)lookup("pcap_close");
    if(fn) fn(handle);
}
const char * CDECL pcap_lib_version(void) {
    typedef const char *(CDECL *Fn)(void);
    Fn fn=(Fn)lookup("pcap_lib_version");
    return fn ? fn() : "Installed Npcap could not be loaded";
}
void CDECL pcap_freealldevs(Device *head) {
    typedef void (CDECL *Fn)(Device *);
    Fn fn=(Fn)lookup("pcap_freealldevs");
    if(fn) fn(head);
}
BOOL WINAPI DllMain(HANDLE instance, DWORD reason, void *reserved) { return 1; }
