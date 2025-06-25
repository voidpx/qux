#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
int not_shared = 0;
int main(int argc, char **argv, char **envp) {
  printf("hello from C in user space, args:\n");
 // for (int i= 0; i < argc; i++) {
 //   printf("%s ", argv[i]);
 // }
 // printf("\n");
 // 
 // for (char **env = envp;*env;env++) {
 //   printf("%s\n", *env);
 // }
 void testThread() ;
  testThread();
  struct timespec ts = {.tv_sec = 2, .tv_nsec = 0};
  struct timespec rts;
  int pid = fork();
  if (pid) {
    for (int i = 0;;++i) {
      not_shared++;
      printf("parent...%d...\n", not_shared);
      nanosleep(&ts, &rts);
    }
  }
  for (int i = 0;;++i) {
      not_shared++;
      printf("child...%d...\n", not_shared);
      nanosleep(&ts, &rts);
  }

}
int shared = 0;
void *newThread(void *unused) {
  struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};
  struct timespec rts;
   for (int i = 0;;i++) {
    shared += 1;
     printf("shared var: %d\n", shared);
    nanosleep(&ts, &rts); 

  }

  return NULL;
}
void testThread() {
  pthread_t t1, t2;
  pthread_create(&t1, NULL, &newThread, NULL);
  pthread_create(&t2, NULL, &newThread, NULL);
}


