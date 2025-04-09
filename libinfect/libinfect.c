//
//  libinfect.c
//  libinfect
//
//  Created by bedtime on 11/19/23.
//


#include "ammonia.h"
#include "frida-gum.h"
#include "envbuf.h"

#include "../SandboxSPI.h"

#include <mach-o/loader.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/mman.h>

void LogToFile(const char *format, ...) {
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

const char *GenerateMachExtensions(void) {
    const char *rw_file = sandbox_extension_issue_file(
        APP_SANDBOX_READ_WRITE,
        "/tmp/",
        0);

    return rw_file; // caller must free this
}

int SpawnNew(pid_t * pid, const char * path, const posix_spawn_file_actions_t * ac, const posix_spawnattr_t * ab, char *const __argv[], char *const __envp[]) {
    char **playground = envbuf_mutcopy((const char **)__envp);

    if (strcmp(path, "/usr/libexec/xpcproxy") == 0) {
        envbuf_setenv(&playground, "DYLD_INSERT_LIBRARIES", SupportFolderP"liblibinfect.dylib");
    } else if (PathRestricted(path) == false) {
        if (LoadsAppKit(path, "AppKit") == 1) {
            if (!PathDriver(path)) {
                const char * blob = GenerateMachExtensions();
                envbuf_setenv(&playground, "DYLD_INSERT_LIBRARIES", SupportFolderP"libopener.dylib");
                envbuf_setenv(&playground, "AMMONIA_SANDBOX_EXT", blob);
                free((void *)blob);
            }
        }
    }
    
    int k = SpawnOld(pid, path, ac, ab, __argv, (char *const *)playground);
    return k;
}

int SpawnPNew(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t * ac, const posix_spawnattr_t *restrict ab, char *const *restrict argv, char *const *restrict envp) {
    return SpawnNew(pid, path, ac, ab, argv, envp);
}

void __attribute__((constructor)) Infect(void) {
    gum_init_embedded();
    GumInterceptor *interceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction (interceptor);
    gum_interceptor_replace (interceptor, (gpointer)gum_module_find_export_by_name(NULL, "posix_spawn"), (gpointer)SpawnNew, NULL, (gpointer *)&SpawnOld);
    gum_interceptor_replace (interceptor, (gpointer)gum_module_find_export_by_name(NULL, "posix_spawnp"), (gpointer)SpawnPNew, NULL, (gpointer *)(NULL));
    gum_interceptor_end_transaction (interceptor);
}
