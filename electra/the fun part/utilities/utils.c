//
//  utils.c
//  electra
//
//  Created by Jamie on 27/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>

#define PROC_PIDPATHINFO_MAXSIZE (4*MAXPATHLEN)

extern char **environ;

static int file_exist(const char *filename) {
    struct stat buffer;
    int r = stat(filename, &buffer);
    return (r == 0);
}

static char *searchpath(const char *binaryname){
    if (strstr(binaryname, "/") != NULL){
        if (file_exist(binaryname)){
            char *foundpath = malloc((strlen(binaryname) + 1) * (sizeof(char)));
            strcpy(foundpath, binaryname);
            return foundpath;
        } else {
            return NULL;
        }
    }
    
    char *pathvar = getenv("PATH");
    
    char *dir = strtok(pathvar,":");
    while (dir != NULL){
        char searchpth[PROC_PIDPATHINFO_MAXSIZE];
        strcpy(searchpth, dir);
        strcat(searchpth, "/");
        strcat(searchpth, binaryname);
        
        if (file_exist(searchpth)){
            char *foundpath = malloc((strlen(searchpth) + 1) * (sizeof(char)));
            strcpy(foundpath, searchpth);
            return foundpath;
        }
        
        dir = strtok(NULL, ":");
    }
    return NULL;
}

static int isShellScript(const char *path){
    FILE *file = fopen(path, "r");
    uint8_t header[2];
    if (fread(header, sizeof(uint8_t), 2, file) == 2){
        if (header[0] == '#' && header[1] == '!'){
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return -1;
}

static char *getInterpreter(char *path){
    FILE *file = fopen(path, "r");
    char *interpreterLine = NULL;
    unsigned long lineSize = 0;
    getline(&interpreterLine, &lineSize, file);
    
    char *rawInterpreter = (interpreterLine+2);
    rawInterpreter = strtok(rawInterpreter, " ");
    rawInterpreter = strtok(rawInterpreter, "\n");
    
    char *interpreter = malloc((strlen(rawInterpreter)+1) * sizeof(char));
    strcpy(interpreter, rawInterpreter);
    
    free(interpreterLine);
    fclose(file);
    return interpreter;
}

static char *fixedCmd(const char *cmdStr){
    char *cmdCpy = malloc((strlen(cmdStr)+1) * sizeof(char));
    strcpy(cmdCpy, cmdStr);
    
    char *cmd = strtok(cmdCpy, " ");
    
    uint8_t size = strlen(cmd) + 1;
    
    char *args = cmdCpy + size;
    if ((strlen(cmdStr) - strlen(cmd)) == 0)
        args = NULL;
    
    char *abs_path = searchpath(cmd);
    if (abs_path){
        int isScript = isShellScript(abs_path);
        if (isScript == 1){
            char *interpreter = getInterpreter(abs_path);
            
            uint8_t commandSize = strlen(interpreter) + 1 + strlen(abs_path);
            
            if (args){
                commandSize += 1 + strlen(args);
            }
            
            char *rawCommand = malloc(sizeof(char) * (commandSize + 1));
            strcpy(rawCommand, interpreter);
            strcat(rawCommand, " ");
            strcat(rawCommand, abs_path);
            
            if (args){
                strcat(rawCommand, " ");
                strcat(rawCommand, args);
            }
            rawCommand[(commandSize)+1] = '\0';
            
            free(interpreter);
            free(abs_path);
            free(cmdCpy);
            
            return rawCommand;
        } else {
            uint8_t commandSize = strlen(abs_path);
            
            if (args){
                commandSize += 1 + strlen(args);
            }
            
            char *rawCommand = malloc(sizeof(char) * (commandSize + 1));
            strcat(rawCommand, abs_path);
            
            if (args){
                strcat(rawCommand, " ");
                strcat(rawCommand, args);
            }
            rawCommand[(commandSize)+1] = '\0';
            
            free(abs_path);
            free(cmdCpy);
            
            return rawCommand;
        }
    }
    return cmdCpy;
}

int run(const char *cmd) {
    char *myenviron[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/X11:/usr/games",
        "PS1=\\h:\\w \\u\\$ ",
        NULL
    };
    
    pid_t pid;
    char *rawCmd = fixedCmd(cmd);
    char *argv[] = {"sh", "-c", (char*)rawCmd, NULL};
    int status;
    status = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, (char **)&myenviron);
    if (status == 0) {
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
        }
    } else {
        printf("posix_spawn: %s\n", strerror(status));
    }
    free(rawCmd);
    return status;
}

char *itoa(long n) {
    int len = n==0 ? 1 : floor(log10l(labs(n)))+1;
    if (n<0) len++; // room for negative sign '-'
    
    char    *buf = calloc(sizeof(char), len+1); // +1 for null
    snprintf(buf, len+1, "%ld", n);
    return   buf;
}

