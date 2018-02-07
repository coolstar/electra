//
//  utils.c
//  electra
//
//  Created by Jamie on 27/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "utils.h"
#include "file_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/param.h>

// runCmd + shell script fixup
// Copyright 2017, (C) CoolStar. All Rights Reserved

#define PROC_PIDPATHINFO_MAXSIZE  (4*MAXPATHLEN)

static char *searchpath(const char *binaryname){
    if (strstr(binaryname, "/") != NULL){
        if (file_exists(binaryname)){
            char *foundpath = malloc((strlen(binaryname) + 1) * (sizeof(char)));
            strcpy(foundpath, binaryname);
            return foundpath;
        }
    }
    
    char *pathvar = getenv("PATH");
    
    char *dir = strtok(pathvar,":");
    while (dir != NULL){
        char searchpath[PROC_PIDPATHINFO_MAXSIZE];
        strcpy(searchpath, dir);
        strcat(searchpath, "/");
        strcat(searchpath, binaryname);
        
        if (file_exists(searchpath)){
            char *foundpath = malloc((strlen(searchpath) + 1) * (sizeof(char)));
            strcpy(foundpath, searchpath);
            return foundpath;
        }
        
        dir = strtok(NULL, ":");
    }
    return NULL;
}

static bool isShellScript(const char *path){
    FILE *file = fopen(path, "r");
    uint8_t header[2];
    if (fread(header, sizeof(uint8_t), 2, file) == 2){
        if (header[0] == '#' && header[1] == '!'){
            fclose(file);
            return true;
        }
    }
    fclose(file);
    return false;
}

static char *getInterpreter(char *path){
    FILE *file = fopen(path, "r");
    char *interpreterLine = NULL;
    unsigned long lineSize = 0;
    getline(&interpreterLine, &lineSize, file);
    
    char *rawInterpreter = (interpreterLine+2);
    rawInterpreter = strtok(rawInterpreter, " ");
    rawInterpreter = strtok(rawInterpreter, "\n");
    
    char *interpreter = malloc(strlen(rawInterpreter) * sizeof(char));
    strcpy(interpreter, rawInterpreter);
    
    free(interpreterLine);
    fclose(file);
    return interpreter;
}

static char *fixedCmd(const char *cmdStr){
    char *cmdCpy = malloc(strlen(cmdStr) * sizeof(char));
    strcpy(cmdCpy, cmdStr);
    
    char *cmd = strtok(cmdCpy, " ");
    
    uint8_t size = strlen(cmd);
    
    char *args = cmdCpy + (size + 1);
    if ((strlen(cmdStr) - strlen(cmd)) == 0)
        args = NULL;
    
    char *abs_path = searchpath(cmd);
    if (abs_path){
        bool isScript = isShellScript(abs_path);
        if (isScript){
            char *interpreter = getInterpreter(abs_path);
            
            uint8_t commandSize = strlen(interpreter) + 1 + strlen(abs_path);
            
            if (args){
                commandSize += 1 + strlen(args);
            }
            
            char *rawCommand = malloc(sizeof(char) * commandSize);
            strcpy(rawCommand, interpreter);
            strcat(rawCommand, " ");
            strcat(rawCommand, abs_path);
            
            if (args){
                strcat(rawCommand, " ");
                strcat(rawCommand, args);
            }
            
            free(interpreter);
            free(abs_path);
            free(cmdCpy);
            
            return rawCommand;
        } else {
            uint8_t commandSize = strlen(abs_path);
            
            if (args){
                commandSize += 1 + strlen(args);
            }
            
            char *rawCommand = malloc(sizeof(char) * commandSize);
            strcat(rawCommand, abs_path);
            
            if (args){
                strcat(rawCommand, " ");
                strcat(rawCommand, args);
            }
            
            free(abs_path);
            free(cmdCpy);
            
            return rawCommand;
        }
    }
    return cmdCpy;
}

extern char **environ;
int run(const char *cmd) {
    pid_t pid;
    char *rawCmd = fixedCmd(cmd);
    char *argv[] = {"sh", "-c", (char*)rawCmd, NULL};
    int status;
    status = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ);
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
