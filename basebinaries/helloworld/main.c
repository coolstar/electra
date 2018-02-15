#import <stdio.h>

int main(){
    FILE *f = fopen("/.amfid_success", "w");
    fprintf(f,"Hello World!\n");
    fclose(f);
    return 0;
}
