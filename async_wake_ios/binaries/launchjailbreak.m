#include <stdlib.h>
#include <unistd.h>
#define BOOTSTRAP_PREFIX "bootstrap"

int main(int argc, char **argv, char **envp) {
    setpgid(getpid(), 0);
    
    pid_t p1 = fork();
    if (p1 != 0){
        int status;
        waitpid(p1, &status, 0);
    } else {
        pid_t p2 = fork();
        if (p2 != 0){
            exit(0);
        } else {
            char *environ[] = {
                "BOOTSTRAP_PREFIX=/"BOOTSTRAP_PREFIX"",
                "PATH=/"BOOTSTRAP_PREFIX"/usr/local/bin:/"BOOTSTRAP_PREFIX"/usr/sbin:/"BOOTSTRAP_PREFIX"/usr/bin:/"BOOTSTRAP_PREFIX"/sbin:/"BOOTSTRAP_PREFIX"/bin:/bin:/usr/bin:/sbin",
                "PS1=\\h:\\w \\u\\$ ",
                NULL
            };
            
            char *dbear = "/"BOOTSTRAP_PREFIX"/usr/local/bin/dropbear";
            execve(dbear, (char **)&(const char*[]){dbear, "-S", "/bootstrap", "-p", "2222", "-p", "22", NULL}, (char **)&environ);
        }
    }
    return 0;
}

// vim:ft=objc

