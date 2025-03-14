//
//  libinfect.c
//  libinfect
//
//  Created by bedtime on 11/19/23.
//

#include <bootstrap.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreServices/CoreServices.h>
#include <ApplicationServices/ApplicationServices.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <libproc.h>
#include <spawn.h>
#include <sys/_pthread/_pthread_t.h>
#include <sys/_types/_null.h>
#include <sys/_types/_pid_t.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include "../CoreSymbolication.h"
#include "ammonia.h"
#include "frida-gum.h"

void LogToFile(const char *format, ...)
{
    // Open the file in append mode
    FILE *file = fopen("/tmp/infect.log", "a");
    
    if (file == NULL) {
        // Failed to open the file
        perror("Error opening file");
        return;
    }

    // Initialize variable arguments
    va_list args;
    va_start(args, format);

    // Use vfprintf to write to the file
    vfprintf(file, format, args);

    // Clean up variable arguments
    va_end(args);

    // Close the file
    fclose(file);
}

// https://github.com/evelyneee/ellekit/blob/24033cc3cfa78cfd64908fc9f4b63f1880adeb93/ellekitc/ellekitc.c#L53
// thanks siguza
int (*SandboxCheckOld)(audit_token_t au, const char *operation, int sandbox_filter_type, ...) ;
int SandboxCheck(audit_token_t au, const char *operation, int sandbox_filter_type, ...) 
{    
    va_list a;
    va_start(a, sandbox_filter_type);
    const char *name = va_arg(a, const char *);
    const void *arg2 = va_arg(a, void *);
    const void *arg3 = va_arg(a, void *);
    const void *arg4 = va_arg(a, void *);
    const void *arg5 = va_arg(a, void *);
    const void *arg6 = va_arg(a, void *);
    const void *arg7 = va_arg(a, void *);
    const void *arg8 = va_arg(a, void *);
    const void *arg9 = va_arg(a, void *);
    const void *arg10 = va_arg(a, void *);
    if (name && operation) {
        if (strcmp(operation, "mach-lookup") == 0) {
            if (strstr(name, "ammonia")) {
                return 0; // yas ! allow mach ports
            }
        }
    }
    return SandboxCheckOld(au, operation, sandbox_filter_type, name, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);;
}

int Pid2Name(const char *proc_name) {
    int mib[4];
    size_t len;
    struct kinfo_proc *proc_list;
    size_t proc_count;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_ALL;
    mib[3] = 0;

    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
        perror("sysctl 1");
        return -1;
    }

    proc_list = malloc(len);
    if (proc_list == NULL) {
        perror("malloc");
        return -1;
    }

    if (sysctl(mib, 4, proc_list, &len, NULL, 0) < 0) {
        perror("sysctl 2");
        free(proc_list);
        return -1;
    }

    proc_count = len / sizeof(struct kinfo_proc);
    for (size_t i = 0; i < proc_count; i++) {
        if (strcmp(proc_list[i].kp_proc.p_comm, proc_name) == 0) {
            int pid = proc_list[i].kp_proc.p_pid;
            free(proc_list);
            return pid;
        }
    }

    free(proc_list);
    return -1; // Process not found
}

int (*SpawnOld)(pid_t * pid, const char * path, const posix_spawn_file_actions_t * ac, const posix_spawnattr_t * ab, char *const __argv[], char *const __envp[]);

bool LoadsAppKit(const char *path, const char *framework) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size == -1) {
        perror("lseek");
        close(fd);
        return -1;
    }
    
    void *map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return -1;
    }

    struct mach_header_64 *mh = (struct mach_header_64 *)map;
    if (mh->magic != MH_MAGIC_64) {
        fprintf(stderr, "Unsupported file format or architecture\n");
        munmap(map, file_size);
        close(fd);
        return -1;
    }

    struct load_command *cmd = (struct load_command *)((char *)mh + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (cmd->cmd == LC_LOAD_DYLIB || cmd->cmd == LC_LOAD_WEAK_DYLIB) {
            struct dylib_command *dylib = (struct dylib_command *)cmd;
            const char *dylib_name = (char *)dylib + dylib->dylib.name.offset;
            if (strstr(dylib_name, framework)) {
                munmap(map, file_size);
                close(fd);
                return 1; // Framework found
            }
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }

    munmap(map, file_size);
    close(fd);
    return 0; // Framework not found
}

bool PathRestricted(const char *path) {
    if (!path) return false;
    
    const char *framework = strstr(path, ".framework/");
    if (!framework) return false; // Not inside a framework

    // Ensure it's not inside an .app bundle
    const char *app = strstr(path, ".app/");
    if (app && app < framework) return false; // If .app appears before .framework, it's inside an app

    return true;
}

bool PathDriver(const char *path) {
    return (strstr(path, "Driver") != NULL);
}

int SpawnNew(pid_t * pid, const char * path, const posix_spawn_file_actions_t * ac, const posix_spawnattr_t * ab, char *const __argv[], char *const __envp[]) {
    char *fakeEnvVar;
    
    if (strcmp(path, "/usr/libexec/xpcproxy") == 0) {
        fakeEnvVar = "DYLD_INSERT_LIBRARIES="SupportFolderP"liblibinfect.dylib";
    } else if (PathRestricted(path) == false) {
        if (LoadsAppKit(path, "AppKit") == 1) {
            if (!PathDriver(path)) {
                fakeEnvVar = "DYLD_INSERT_LIBRARIES="SupportFolderP"libopener.dylib";
            } else {
                return SpawnOld(pid, path, ac, ab, __argv, __envp);
            }
        } else {
            return SpawnOld(pid, path, ac, ab, __argv, __envp);
        }
    } else {
        return SpawnOld(pid, path, ac, ab, __argv, __envp);
    }
    
    int envCount = 0;
    while (__envp[envCount] != NULL) { envCount++; }

    char **newEnvp = (char **)malloc((envCount + 2) * sizeof(char *));
    if (newEnvp == NULL) { return -1; }

    for (int i = 0; i < envCount; i++) 
    {
        newEnvp[i] = strdup(__envp[i]);
        if (newEnvp[i] == NULL)
        {
            for (int j = 0; j < i; j++) 
            {
                free(newEnvp[j]);
            }
            free(newEnvp);
            return -1;
        }
    }
    
    newEnvp[envCount] = strdup(fakeEnvVar);
    if (newEnvp[envCount] == NULL)
    {
        for (int i = 0; i <= envCount; i++) { free(newEnvp[i]); }
        free(newEnvp);
        return -1;
    }
    newEnvp[envCount + 1] = NULL;
    
    LogToFile("---- %s\n", path);
    for (int i = 0; i < envCount + 1; i++) { LogToFile("-- %s\n", newEnvp[i]); }
    LogToFile("\n");
    
    int k = SpawnOld(pid, path, ac, ab, __argv, (char *const *)newEnvp);
    for (int i = 0; i <= envCount; i++) { free(newEnvp[i]); }
    free(newEnvp);

    return k;
}

int SpawnPNew(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t * ac, const posix_spawnattr_t *restrict ab, char *const *restrict argv, char *const *restrict envp)
{
    return SpawnNew(pid, path, ac, ab, argv, envp);
}

int (*_CSOps)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
int HookedCSOps(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int result = _CSOps(pid, ops, useraddr, usersize);
    if (result != 0) return result;
    if (ops == 0) { // CS_OPS_STATUS
       *((uint32_t *)useraddr) |= 0x4000001; // CS_PLATFORM_BINARY
    }
    return result;
}

int (*_CSOpsAuditToken)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token);
int HookedCSOpsAuditToken(pid_t pid, unsigned int ops, void * useraddr, size_t usersize, audit_token_t * token) {
    int result = _CSOpsAuditToken(pid, ops, useraddr, usersize, token);
    if (result != 0) return result;
    if (ops == 0) { // CS_OPS_STATUS
       *((uint32_t *)useraddr) |= 0x4000001; // CS_PLATFORM_BINARY
    }
    return result;
}

void __attribute__((constructor)) Infect(void)
{
    gum_init_embedded();
    GumInterceptor *interceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction (interceptor);
    gum_interceptor_replace (interceptor, (gpointer)gum_module_find_export_by_name(NULL, "posix_spawn"), (gpointer)SpawnNew, NULL, (gpointer *)&SpawnOld);
    gum_interceptor_replace (interceptor, (gpointer)gum_module_find_export_by_name(NULL, "posix_spawnp"), (gpointer)SpawnPNew, NULL, (gpointer *)(NULL));
    gum_interceptor_replace (interceptor, (gpointer)gum_module_find_export_by_name(NULL, "sandbox_check_by_audit_token"), (gpointer)SandboxCheck, NULL, (gpointer *)&SandboxCheckOld);
    gum_interceptor_replace (interceptor, (gpointer)gum_module_find_export_by_name(NULL, "csops"), (gpointer)HookedCSOps, NULL, (gpointer *)&_CSOps);
    gum_interceptor_replace (interceptor, (gpointer)gum_module_find_export_by_name(NULL, "csops_audittoken"), (gpointer)HookedCSOpsAuditToken, NULL, (gpointer *)&_CSOpsAuditToken);
    gum_interceptor_end_transaction (interceptor);
}
