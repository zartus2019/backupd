/* vsscreate.c — создание VSS-теневого снимка через IVssBackupComponents.
 *
 * В Windows 11 команда `vssadmin create shadow` удалена из vssadmin
 * (остались только list/delete/resize). Создание снимка доступно
 * через VSS API (vssapi.dll, CreateVssBackupComponents).
 *
 * Статический Win32 x64-билд, зависимости только системные DLL
 * (kernel32, msvcrt, ole32).
 *
 * Использование:
 *   vsscreate.exe create C:\
 *
 * Вывод при успехе (exit 0):
 *   SHADOW_ID={XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
 *   DEVICE=\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
 *   INSTALL=\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyM
 *
 * При ошибке — exit != 0, сообщение в stderr.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    unsigned long Data1;
    unsigned short Data2, Data3;
    unsigned char Data4[8];
} G;

/* VSS_SNAPSHOT_PROP из vss.h (SDK) */
typedef struct {
    G      m_SnapshotId;
    G      m_SnapshotSetId;
    long   m_lSnapshotsCount;
    LPWSTR m_pwszSnapshotDeviceObject;
    LPWSTR m_pwszOriginalVolumeName;
    LPWSTR m_pwszOriginatingMachine;
    LPWSTR m_pwszServiceMachine;
    LPWSTR m_pwszExposedName;
    LPWSTR m_pwszExposedPath;
    G      m_ProviderId;
    long   m_lSnapshotAttributes;
    LONGLONG m_tsCreationTimestamp;
    long   m_eStatus;
} VSS_SNAP_PROP;

/* Индексы в виртуальной таблице IVssBackupComponents (плоский
 * интерфейс, IID {665c1d5f-c218-414d-a05d-7fef5f9d5c86}; порядок
 * методов сверен по рабочему comtypes-описанию VSS API). После
 * IUnknown(3): 3 GetWriterComponentsCount, 4 GetWriterComponents,
 * 5 InitializeForBackup, 6 SetBackupState, 7 InitializeForRestore,
 * 8 SetRestoreState, 9 GatherWriterMetadata, 10 GetWriterMetadataCount,
 * 11 GetWriterMetadata, 12 FreeWriterMetadata, 13 AddComponent,
 * 14 PrepareForBackup, 15 AbortBackup, 16 GatherWriterStatus,
 * 17 GetWriterStatusCount, 18 FreeWriterStatus, 19 GetWriterStatus,
 * 20 SetBackupSucceeded, 21 SetBackupOptions, 22 SetSelectedForRestore,
 * 23 SetRestoreOptions, 24 SetAdditionalRestores, 25 SetPreviousBackupStamp,
 * 26 SaveAsXML, 27 BackupComplete, 28 AddAlternativeLocationMapping,
 * 29 AddRestoreSubcomponent, 30 SetFileRestoreStatus, 31 AddNewTarget,
 * 32 SetRangesFilePath, 33 PreRestore, 34 PostRestore, 35 SetContext,
 * 36 StartSnapshotSet, 37 AddToSnapshotSet, 38 DoSnapshotSet,
 * 39 DeleteSnapshots, 40 ImportSnapshots, 41 BreakSnapshotSet,
 * 42 GetSnapshotProperties, 43 Query, 44 IsVolumeSupported, … */
#define VT_InitForBackup         5
#define VT_SetBackupState        6
#define VT_GatherWriterMetadata  9
#define VT_PrepareForBackup      14
#define VT_StartSnapshotSet      36
#define VT_AddToSnapshotSet      37
#define VT_DoSnapshotSet         38
#define VT_SetContext            35
#define VT_GetSnapshotProperties 42
#define VT_ExposeSnapshot        48
#define VSS_VOLSNAP_ATTR_EXPOSED_LOCALLY 0x100000

typedef long HRESULT2;
typedef HRESULT2 (WINAPI *F_Init)(void *self, BSTR xml);
typedef HRESULT2 (WINAPI *F_SetCtx)(void *self, long ctx);
typedef HRESULT2 (WINAPI *F_SetBS)(void *self, int select,
                                   int bootable, int type,
                                   int partial);
typedef HRESULT2 (WINAPI *F_Gather)(void *self, void **ppAsync);
typedef HRESULT2 (WINAPI *F_Prep)(void *self, void **ppAsync);
typedef HRESULT2 (WINAPI *F_StartSet)(void *self, G *setId);
typedef HRESULT2 (WINAPI *F_AddToSet)(void *self, LPCWSTR vol,
                                      const G *prov, G *snapId);
typedef HRESULT2 (WINAPI *F_DoSet)(void *self, void **ppAsync);
typedef HRESULT2 (WINAPI *F_GetProp)(void *self, const G *snapId,
                                     VSS_SNAP_PROP *prop);
typedef HRESULT2 (WINAPI *F_Expose)(void *self, const G *snapId,
                                    LPCWSTR pathFromRoot, long attrs,
                                    LPCWSTR expose, LPWSTR *pwszExposed);
typedef HRESULT2 (WINAPI *F_AsyncWait)(void *self, unsigned long ms);
typedef ULONG (WINAPI *F_Release)(void *self);
typedef HRESULT2 (WINAPI *F_CreateBC)(void **ppBC);
typedef void (WINAPI *F_FreeProp)(VSS_SNAP_PROP *prop);

typedef unsigned long long *VTAB;

static void die(const char *what, HRESULT hr)
{
    fprintf(stderr, "%s: HRESULT 0x%08lX\n", what,
            (unsigned long)(unsigned long)hr);
    exit(1);
}

static void w2a(const LPWSTR w, char *dst, size_t n)
{
    int k = WideCharToMultiByte(CP_UTF8, 0, w, -1, dst, (int)n - 1,
                                NULL, NULL);
    if (k <= 0)
        die("WideCharToMultiByte", (HRESULT)1);
    dst[k - 1] = 0; /* без завершающего NUL из MultiByte */
}

static void print_guid(const char *label, const G *g)
{
    printf("%s={%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n",
           label, (unsigned long)g->Data1, g->Data2, g->Data3,
           g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
           g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
}

static void trace(const char *s)
{
    fprintf(stderr, "step: %s\n", s);
    fflush(stderr);
}

/* IVssAsync: IUnknown(3) + Cancel(3) + WaitForCompletion(4) */
static HRESULT async_wait(void *async, unsigned long ms)
{
    VTAB vt = *(VTAB *)async;
    F_AsyncWait fn = (F_AsyncWait)vt[4];
    return fn(async, ms);
}

int main(int argc, char **argv)
{
    if (argc != 3 || strcmp(argv[1], "create") != 0) {
        fprintf(stderr,
                "usage: vsscreate.exe create <том> "
                "(например, vsscreate.exe create C:\\)\n");
        return 2;
    }
    char vol[64];
    strncpy(vol, argv[2], sizeof(vol) - 1);
    vol[sizeof(vol) - 1] = 0;
    size_t vl = strlen(vol);
    if (vl < 2 || vol[1] != ':') {
        fprintf(stderr, "том должен иметь вид C: или C:\\\n");
        return 2;
    }
    if (vol[vl - 1] != '\\') {
        if (vl + 2 >= sizeof(vol))
            return 2;
        vol[vl++] = '\\';
        vol[vl] = 0;
    }

    trace("args ok");
    /* В широкой строке (VSS API ждёт UTF-16) */
    WCHAR volw[64];
    if (!MultiByteToWideChar(CP_UTF8, 0, vol, -1, volw, 64))
        die("MultiByteToWideChar", (HRESULT)1);

    if (CoInitializeEx(NULL, COINIT_MULTITHREADED) != S_OK)
        die("CoInitializeEx", (HRESULT)1);
    trace("co init");

    HMODULE vssapi = LoadLibraryA("vssapi.dll");
    if (!vssapi)
        die("LoadLibrary(vssapi.dll)", (HRESULT)GetLastError());
    trace("loaded");

    /* Экспорт в vssapi.dll имеет C++ mangled-имя (подтверждено по
     * импортной библиотеке libvssapi.a); пробуем его, затем plain. */
    F_CreateBC create_bc = (F_CreateBC)GetProcAddress(
        vssapi,
        "?CreateVssBackupComponents@@YAJPEAPEAVIVssBackupComponents@@@Z");
    if (!create_bc)
        create_bc = (F_CreateBC)
            GetProcAddress(vssapi, "CreateVssBackupComponents");
    F_FreeProp free_prop = (F_FreeProp)
        GetProcAddress(vssapi, "VssFreeSnapshotProperties");
    if (!create_bc || !free_prop)
        die("GetProcAddress(vssapi.dll)", (HRESULT)1);
    trace("procs found");

    void *bc = NULL;
    HRESULT hr = create_bc(&bc);
    if (FAILED(hr) || !bc)
        die("CreateVssBackupComponents", hr ? hr : (HRESULT)1);
    trace("bc created");
    /* bc — указатель на объект; vtable в первом поле объекта.
     * self-аргумент метода — сам bc. */
    VTAB vt = *(VTAB *)bc;
    hr = ((F_Init)vt[VT_InitForBackup])(bc, NULL);
    if (FAILED(hr)) die("InitializeForBackup", hr);
    trace("init");

    /* VSS_CTX_APP_ROLLBACK (0x9 = PERSISTENT | NO_AUTO_RELEASE):
     * только PERSISTENT-снимок можно экспонировать локально на букву
     * диска (ExposeSnapshot). Writers при этом замораживаются — снимок
     * последовательный. VSS_CTX_BACKUP (0) не persistent -> expose
     * вернул бы E_INVALIDARG. */
    hr = ((F_SetCtx)vt[VT_SetContext])(bc, 0x9 /*VSS_CTX_APP_ROLLBACK*/);
    if (FAILED(hr)) die("SetContext", hr);
    trace("setctx");

    /* (bSelectComponents, bBackupBootableSystemState, backupType,
     *  bPartialFileSupport) — как в vssadmin create shadow */
    hr = ((F_SetBS)vt[VT_SetBackupState])(
        bc, 0, 0, 1 /*VSS_BT_FULL*/, 0);
    if (FAILED(hr)) die("SetBackupState", hr);
    trace("setbs");

    void *am = NULL;
    hr = ((F_Gather)vt[VT_GatherWriterMetadata])(bc, &am);
    if (FAILED(hr)) die("GatherWriterMetadata", hr);
    if (am) {
        hr = async_wait(am, INFINITE);
        if (FAILED(hr)) die("GatherWriterMetadata.wait", hr);
    }
    trace("gather");

    G set_id;
    hr = ((F_StartSet)vt[VT_StartSnapshotSet])(bc, &set_id);
    if (FAILED(hr)) die("StartSnapshotSet", hr);
    trace("startset");

    G null_prov;
    memset(&null_prov, 0, sizeof(null_prov));
    G snap_id;
    hr = ((F_AddToSet)vt[VT_AddToSnapshotSet])(bc, volw,
                                               &null_prov /*провайдер по
                                                   умолчанию*/, &snap_id);
    if (FAILED(hr)) die("AddToSnapshotSet", hr);
    trace("addtoset ok");

    void *pm = NULL;
    hr = ((F_Prep)vt[VT_PrepareForBackup])(bc, &pm);
    if (FAILED(hr)) die("PrepareForBackup", hr);
    if (pm) {
        hr = async_wait(pm, INFINITE);
        if (FAILED(hr)) die("PrepareForBackup.wait", hr);
    }
    trace("prep");

    void *dm = NULL;
    hr = ((F_DoSet)vt[VT_DoSnapshotSet])(bc, &dm);
    if (FAILED(hr)) die("DoSnapshotSet", hr);
    if (dm) {
        hr = async_wait(dm, INFINITE);
        if (FAILED(hr)) die("DoSnapshotSet.wait", hr);
    }
    trace("do");

    VSS_SNAP_PROP prop;
    memset(&prop, 0, sizeof(prop));
    hr = ((F_GetProp)vt[VT_GetSnapshotProperties])(bc, &snap_id, &prop);
    if (FAILED(hr)) die("GetSnapshotProperties", hr);
    trace("prop");

    if (!prop.m_pwszSnapshotDeviceObject)
        die("GetSnapshotProperties: нет device object", (HRESULT)1);

    print_guid("SHADOW_ID", &prop.m_SnapshotId);
    char buf[512];
    w2a(prop.m_pwszSnapshotDeviceObject, buf, sizeof(buf));
    printf("DEVICE=%s\n", buf);
    if (prop.m_pwszExposedName) {
        w2a(prop.m_pwszExposedName, buf, sizeof(buf));
        printf("INSTALL=%s\n", buf);
    }
    fflush(stdout);

    /* Экспонируем снимок на свободную букву диска, чтобы удалённый
     * rsync (MSYS2/Cygwin) мог читать его как обычный путь
     * /cygdrive/<l>/... — VSS-путь \\?\GLOBALROOT\... недоступен
     * MSYS2 rsync из-за его конвертации путей.
     * Expose the snapshot on a free drive letter so the remote
     * (MSYS2/Cygwin) rsync can read it as a normal /cygdrive/<l>/...
     * path — the \\?\GLOBALROOT\... VSS path is unusable by MSYS2
     * rsync because of its path conversion.
     */
    {
        unsigned long drv = GetLogicalDrives();
        WCHAR expose_path[4];
        int found = 0;
        for (int li = 25; li >= 2 && !found; li--) { /* Z..C */
            if (drv & (1ul << li))
                continue; /* буква занята / letter in use */
            expose_path[0] = (WCHAR)('A' + li);
            expose_path[1] = L':';
            expose_path[2] = 0;
            LPWSTR exposed = NULL;
            hr = ((F_Expose)vt[VT_ExposeSnapshot])(
                bc, &snap_id, NULL /*локально / local*/,
                VSS_VOLSNAP_ATTR_EXPOSED_LOCALLY, expose_path, &exposed);
            if (SUCCEEDED(hr)) {
                char ebuf[64];
                if (exposed) {
                    w2a(exposed, ebuf, sizeof(ebuf));
                    CoTaskMemFree(exposed);
                } else {
                    w2a(expose_path, ebuf, sizeof(ebuf));
                }
                printf("EXPOSED=%s\n", ebuf);
                fflush(stdout);
                found = 1;
            } else {
                fprintf(stderr, "ExposeSnapshot(%c:) hr=0x%08lX\n",
                        (char)('A' + li), (unsigned long)(long)hr);
                fflush(stderr);
            }
        }
        if (!found)
            die("ExposeSnapshot: no drive letter", (HRESULT)1);
    }

    free_prop(&prop);
    ((F_Release)vt[2])(bc); /* Release */
    CoUninitialize();
    return 0;
}
