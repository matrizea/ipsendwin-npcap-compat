/* App-local 32-bit compatibility adapter for ipsendwin 2.4.
 * Does not modify Npcap, Windows configuration, or ipsendwin.exe.
 * Calls the installed Npcap by absolute path and moves the first
 * IPv4-capable non-loopback interface to the front of its returned list.
 */
#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef struct Address { struct Address *next; void *addr, *netmask, *broadaddr, *dstaddr; } Address;
typedef struct Device { struct Device *next; char *name, *description; Address *addresses; unsigned int flags; } Device;
typedef struct Api {
    int (__cdecl *findalldevs)(Device **, char *);
    void *(__cdecl *open_live)(const char *, int, int, int, char *);
    int (__cdecl *sendpacket)(void *, const unsigned char *, int);
    void (__cdecl *close)(void *);
    const char *(__cdecl *lib_version)(void);
    void (__cdecl *freealldevs)(Device *);
} Api;
static INIT_ONCE initialization = INIT_ONCE_STATIC_INIT;
static Api api;
static BOOL WINAPI initialize(PINIT_ONCE once, PVOID parameter, PVOID *context) {
    WCHAR path[300];
    static const WCHAR suffix[] = L"\\Npcap\\wpcap.dll";
    unsigned int n, i;
    HMODULE library;
    Api candidate;
    (void)once; (void)parameter; (void)context;
    n = GetSystemDirectoryW(path, 280);
    if (!n || n >= 280) return FALSE;
    for (i=0; i<sizeof(suffix)/sizeof(suffix[0]); ++i) path[n+i] = suffix[i];
    library = LoadLibraryExW(path, NULL,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!library) return FALSE;
    candidate.findalldevs = (int (__cdecl *)(Device **, char *))GetProcAddress(library, "pcap_findalldevs");
    candidate.open_live = (void *(__cdecl *)(const char *, int, int, int, char *))GetProcAddress(library, "pcap_open_live");
    candidate.sendpacket = (int (__cdecl *)(void *, const unsigned char *, int))GetProcAddress(library, "pcap_sendpacket");
    candidate.close = (void (__cdecl *)(void *))GetProcAddress(library, "pcap_close");
    candidate.lib_version = (const char *(__cdecl *)(void))GetProcAddress(library, "pcap_lib_version");
    candidate.freealldevs = (void (__cdecl *)(Device *))GetProcAddress(library, "pcap_freealldevs");
    if (!candidate.findalldevs || !candidate.open_live || !candidate.sendpacket ||
        !candidate.close || !candidate.lib_version || !candidate.freealldevs) {
        FreeLibrary(library);
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    /* The successful module reference stays loaded for the process lifetime. */
    api = candidate;
    return TRUE;
}
static const Api *get_api(void) {
    return InitOnceExecuteOnce(&initialization, initialize, NULL, NULL) ? &api : NULL;
}
static void load_error(char *error) {
    static const char message[] = "Could not load the installed 32-bit Npcap library.";
    unsigned int i;
    if (error) for (i=0; i<sizeof(message); ++i) error[i]=message[i];
}
static int ipv4(Device *d) {
    Address *a;
    if (d->flags & 1) return 0; /* PCAP_IF_LOOPBACK */
    for (a=d->addresses; a; a=a->next)
        if (a->addr && *(WORD *)a->addr == 2) return 1;
    return 0;
}
int __cdecl pcap_findalldevs(Device **head, char *error) {
    const Api *a;
    Device *prev, *d;
    int r;
    if (!head) { SetLastError(ERROR_INVALID_PARAMETER); load_error(error); return -1; }
    *head=0;
    a=get_api();
    if (!a) { load_error(error); return -1; }
    r=a->findalldevs(head,error);
    if (r || !*head || ipv4(*head)) return r;
    for (prev=*head, d=prev->next; d; prev=d, d=d->next) {
        if(ipv4(d)) { prev->next=d->next; d->next=*head; *head=d; break; }
    }
    return r;
}
void * __cdecl pcap_open_live(const char *name, int length, int promiscuous, int timeout, char *error) {
    const Api *a=get_api();
    if (!a) { load_error(error); return NULL; }
    return a->open_live(name,length,promiscuous,timeout,error);
}
int __cdecl pcap_sendpacket(void *handle, const unsigned char *data, int size) {
    const Api *a=get_api();
    return a ? a->sendpacket(handle,data,size) : -1;
}
void __cdecl pcap_close(void *handle) {
    const Api *a;
    if (!handle) return;
    a=get_api();
    if(a) a->close(handle);
}
const char * __cdecl pcap_lib_version(void) {
    const Api *a=get_api();
    return a ? a->lib_version() : "Installed Npcap could not be loaded";
}
void __cdecl pcap_freealldevs(Device *head) {
    const Api *a;
    if (!head) return;
    a=get_api();
    if(a) a->freealldevs(head);
}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
