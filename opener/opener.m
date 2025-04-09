//
//  opener.c
//  opener
//
//  Created by whisper on 9/2/23.
//
#include <Foundation/Foundation.h>
#include "opener.h"
#include <mach/task_policy.h>
#include <string.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <libproc.h>

#include "../SandboxSPI.h"

#define DYLD_INTERPOSE(_replacement, _replacee)                                 \
    __attribute__((used)) static struct {                                       \
        const void *replacement;                                                \
        const void *replacee;                                                   \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&_replacement,                             \
        (const void *)(unsigned long)&_replacee};

const char *GetExePath(void) {
    uint32_t bufsize = 0;
    _NSGetExecutablePath(NULL, &bufsize);
    char *executablePath = malloc(bufsize);
    _NSGetExecutablePath(&executablePath[0], &bufsize);
    return executablePath;
}

void Open(void * interceptor) { 
    DIR *dr;
    struct dirent *en;
    dr = opendir(SupportFolderP"tweaks/"); // Open the directory
    if (dr) {
        while ((en = readdir(dr)) != NULL) {
            if (en->d_type == DT_REG) { // Check if it's a regular file
                char full_path[PATH_MAX];
                snprintf(full_path, sizeof(full_path), "%stweaks/%s", SupportFolderP, en->d_name);

                // Load the blacklist file for the current dylib
                char blacklist_file[PATH_MAX];
                snprintf(blacklist_file, sizeof(blacklist_file), "%stweaks/%s.blacklist", SupportFolderP, en->d_name);

                // Check if the blacklist file exists and open it
                FILE *blacklist_fp = fopen(blacklist_file, "r");
                if (blacklist_fp) {
                    char process_name[256]; // Adjust the buffer size as needed
                    while (fgets(process_name, sizeof(process_name), blacklist_fp) != NULL) {
                        // Remove newline characters from the process_name
                        size_t len = strlen(process_name);
                        if (len > 0 && process_name[len - 1] == '\n') {
                            process_name[len - 1] = '\0';
                        }

                        // Check if the current process name is blacklisted
                        if (strstr(GetExePath(), process_name) != NULL)
                        {
                            // Process name is blacklisted, skip loading the dylib
                            syslog(LOG_INFO, "Process name %s is blacklisted for %s.", process_name, en->d_name);
                            fclose(blacklist_fp);
                            goto cleanup;
                        }
                    }
                    fclose(blacklist_fp); // Close the blacklist file

                    // If not blacklisted, attempt to dynamically load the shared library
                    void *handle = dlopen(full_path, RTLD_NOW | RTLD_GLOBAL);
                    if (handle == NULL)
                    {
                        syslog(LOG_ERR, "Error loading %s: %s", full_path, dlerror());
                    }
                    
                    void (*LoadFunction)(void *) = dlsym(handle, "LoadFunction");
                    if (LoadFunction != NULL)
                    {
                        LoadFunction(interceptor);
                    }
                }

            cleanup:
                continue; // Continue with the next file
            }
        }
        closedir(dr); // Close the directory
    } else {
        syslog(LOG_ERR, "Error opening directory.");
    }
    closelog();
}

int IsForegroundProcess()
{
    task_t currentTask = mach_task_self();
    task_category_policy_data_t category_policy;
    mach_msg_type_number_t task_info_count = TASK_CATEGORY_POLICY_COUNT;
    boolean_t get_default = FALSE;
    kern_return_t result = task_policy_get(currentTask, TASK_CATEGORY_POLICY, (task_policy_t)&category_policy, &task_info_count, &get_default);
    
    if (result != KERN_SUCCESS)
    {
        fprintf(stderr, "Error getting task category policy: %s\n", mach_error_string(result));
        return -1; // or handle the error appropriately
    }

    return !(category_policy.role & TASK_BACKGROUND_APPLICATION) ||
           !(category_policy.role & TASK_FOREGROUND_APPLICATION) ||
    //       !(category_policy.role & TASK_UNSPECIFIED) || // a gamble
           !(category_policy.role & TASK_DEFAULT_APPLICATION);
}

NSString *AppendMachRegister(NSString *profileStr) {
    if (IsForegroundProcess() != 0) 
        return profileStr;

    if ([profileStr hasPrefix:@"com.apple."]) 
        return profileStr;

    return [profileStr stringByAppendingString:@"\n\n(allow mach-register)"];
}

int SandboxInitHook(const char *profile, uint64_t flags, char **errorbuf) {
    // Convert the profile C string to NSString and modify it
    NSString *originalProfile = [NSString stringWithUTF8String:profile ?: "(null)"];
    NSLog(@"[sandbox] Original Profile: %@", originalProfile);

    NSString *modifiedProfile = AppendMachRegister(originalProfile);
    NSLog(@"[sandbox] Modified Profile: %@", modifiedProfile);

    const char *modifiedCProfile = [modifiedProfile UTF8String];
    int retval = sandbox_init(modifiedCProfile, flags, errorbuf);
    return retval;
}

int SandboxInitWithParametersHook(const char *profile, uint64_t flags,
                                  const char *const parameters[],
                                  char **errorbuf) {
    // Convert the profile C string to NSString and modify it
    NSString *originalProfile = [NSString stringWithUTF8String:profile ?: "(null)"];
    NSLog(@"[sandbox] Original Profile: %@", originalProfile);

    NSString *modifiedProfile = AppendMachRegister(originalProfile);
    NSLog(@"[sandbox] Modified Profile: %@", modifiedProfile);

    const char *modifiedCProfile = [modifiedProfile UTF8String];
    int retval = sandbox_init_with_parameters(modifiedCProfile, flags, parameters, errorbuf);
    return retval;
}

int SandboxInitWithExtHook(const char *profile, uint64_t flags,
                                  const char *const ext[],
                                  char **errorbuf) {
    // Convert the profile C string to NSString and modify it
    NSString *originalProfile = [NSString stringWithUTF8String:profile ?: "(null)"];
    NSLog(@"[sandbox] Original Profile: %@", originalProfile);

    NSString *modifiedProfile = AppendMachRegister(originalProfile);
    NSLog(@"[sandbox] Modified Profile: %@", modifiedProfile);

    const char *modifiedCProfile = [modifiedProfile UTF8String];
    int retval = sandbox_init_with_extensions(modifiedCProfile, flags, ext, errorbuf);
    return retval;
}

DYLD_INTERPOSE(SandboxInitWithExtHook, sandbox_init_with_extensions) 
DYLD_INTERPOSE(SandboxInitWithParametersHook, sandbox_init_with_parameters) 
DYLD_INTERPOSE(SandboxInitHook, sandbox_init) 

void __attribute__((constructor)) ctor_main(void) {
    // Make frida interceptor availible to tweaks
    void *hooking = dlopen("/private/var/ammonia/core/fridagum.dylib", RTLD_NOW | RTLD_GLOBAL);
    void (*GumInitEmbeddedFunc)(void) = dlsym(hooking, "gum_init_embedded");
    void *(*GumInterceptorObtainFunc)(void) = dlsym(hooking, "gum_interceptor_obtain");
    
    GumInitEmbeddedFunc();

    const char *keys = getenv("AMMONIA_SANDBOX_EXT");
    int64_t handle = sandbox_extension_consume(keys);
    if (handle > 0) {
        printf("Got token: %s\r\n", keys);
    }
    
    Open(GumInterceptorObtainFunc());
}