#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <unistd.h>
#include <errno.h>
#include <sys/attr.h>
#include <sys/snapshot.h>

int
do_create(const char *vol, const char *snap)
{
    int dirfd = open(vol, O_RDONLY, 0);
    if (dirfd < 0) {
        perror("open");
        exit(1);
    }
    
    int ret = fs_snapshot_create(dirfd, snap, 0);
    if (ret != 0)
        perror("fs_snapshot_create");
    return (ret);
}


int
main(int argc, char **argv)
{
    unlink("/createSnapshot");
    do_create("/", "electra-prejailbreak");
    
    return (0);
}

