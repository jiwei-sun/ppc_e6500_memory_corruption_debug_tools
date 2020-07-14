#include <sys/shm.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

/* This struct need to be added in the monitored app */
struct shared_st {
	unsigned long write;
	unsigned long start_addr;
	unsigned long len;
};

/* notice_monitor - notice the monitored address and length 
 * notice the monitor. The function needs to be added to the
 * monitored app after the memory allocate finished.
 * @start: the start address
 * @len: the length of monitored memory, in bytes.
 *
 * For example, the monitored memory is 0x10001000-0x10001010
 * @start is 0x10001000, @length is 16.
 *
 * */
void notice_monitor(void *start, unsigned long len)
{
	void *shm = NULL;
	int shmid;
	struct shared_st *shared;

	/* "WIND"'s ASCII is 87737868 */
	shmid = shmget((key_t)87737868, sizeof(struct shared_st), 0666 | IPC_CREAT);
	if(shmid == -1) {
		fprintf(stderr, "shmget failed\n");
		exit(EXIT_FAILURE);
	}

	shm = shmat(shmid, (void*)0, 0);
	if(shm == (void*)-1) {
		fprintf(stderr, "shmat failed\n");
		exit(EXIT_FAILURE);
	}

	shared = (struct shared_st*)shm;

	shared->write = 1;
	shared->start_addr = (unsigned long) start;
	shared->len = len;
	raise(SIGUSR1);
	while (shared->write)
		sleep(1);

	if (shmdt(shm) == -1) {
		fprintf(stderr, "shmdt failed\n");
		exit(EXIT_FAILURE);
	}
}

/* This function needes to be added to the begining of
 * the monitored app's main().
 * It is a function for synchronization with the monitor.
 * */
void wait_for_attach(void)
{
	void *shm = NULL;
	int shmid;
	struct shared_st *shared;

	/* "WINE"'s ASCII is 87737869 = 87737868 + 1 */
	shmid = shmget((key_t)87737869, sizeof(struct shared_st), 0666 | IPC_CREAT);
	if(shmid == -1) {
		fprintf(stderr, "shmget failed\n");
		exit(EXIT_FAILURE);
	}

	shm = shmat(shmid, (void*)0, 0);
	if(shm == (void*)-1) {
		fprintf(stderr, "shmat failed\n");
		exit(EXIT_FAILURE);
	}
	shared = (struct shared_st*)shm;

	while(shared->write != 87737869)
		sleep(1);

	shared->write = 0;

	if (shmdt(shm) == -1) {
		fprintf(stderr, "shmdt failed\n");
		exit(EXIT_FAILURE);
	}
}

#include <fcntl.h>
#include <sys/syscall.h>
#include <malloc.h>
#include <memory.h>
#include <pthread.h>
#include <time.h>
#include <sys/prctl.h>

static unsigned char *test_mem = NULL;
#define LEN (1024*sizeof(char))

static void * pthread0(void *arg)
{
	unsigned int t;
	unsigned char val;
	char name[30];
	unsigned int i;

	srand((unsigned)time(0));
	t = rand() % 10;
	val = rand() % 0xff;
	sleep(t);
	sprintf(name, "thread_%d", val);
	prctl(PR_SET_NAME, name);
	printf("%s Thread(%lu) now firstly modify memory, val is 0x%x\n",
			__FILE__, pthread_self(), val);
	for (i = 0; i < LEN; i++) {
		*(test_mem + i) = val;
	}
	printf("%s Thread(%lu) now secondly modify memory, val is 0x%x\n",
			__FILE__, pthread_self(), val);
	for (i = 0; i < LEN; i++) {
		*(test_mem + i) = 0;
	}
	sleep(2);

	return NULL;
}

static void * pthread1(void *arg)
{
	unsigned int t;
	unsigned char val;
	char name[30];
	unsigned int i;

	srand((unsigned)time(0));
	t = rand() % 10;
	val = rand() % 0xff;
	sleep(t);
	sprintf(name, "thread_%d", val);
	prctl(PR_SET_NAME, name);
	printf("%s Thread(%lu) now firstly modify memory, val is 0x%x\n",
			__FILE__, pthread_self(), val);
	for (i = 0; i < LEN; i++) {
		*(test_mem + i) = val;
	}
	printf("%s Thread(%lu) now secondly modify memory, val is 0x%x\n",
			__FILE__, pthread_self(), val);
	for (i = 0; i < LEN; i++) {
		*(test_mem + i) = 0;
	}
	sleep(2);

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t tidp1, tidp2, tidp3, tidp4, tidp5, tidp6;
	unsigned int i;

	printf("%s now wait_for_attach\n", __FILE__);
	wait_for_attach();
	printf("%s now running\n", __FILE__);

	test_mem = malloc(LEN);
	printf("%s test_mem is 0x%lx\n", __FILE__, test_mem);
	/* adding the function in monitored app */
	notice_monitor(test_mem, 1 * sizeof(char));

	printf("%s First, the test memory is set to 0, in main thread\n", __FILE__);
	memset(test_mem, 0x0, LEN);

	printf("%s the test memory is secondly set to 0x5a, in main thread\n", __FILE__);
	for (i = 0; i < LEN; i++) {
		*(test_mem + i) = 0x5a;
	}

	printf("%s the test memory is thirdly set to 0xa5, in main thread\n", __FILE__);
	for (i = 0; i < LEN; i++) {
		*(test_mem + i) = 0xa5;
	}

	if (pthread_create(&tidp1, NULL, pthread0, NULL) == -1){
		printf("create error!\n");
	}
	sleep(1);

	if (pthread_create(&tidp2, NULL, pthread1, NULL) == -1){
		printf("create error!\n");
	}

	sleep(1);
	if (pthread_create(&tidp3, NULL, pthread1, NULL) == -1){
		printf("create error!\n");
	}

	sleep(1);
	if (pthread_create(&tidp4, NULL, pthread1, NULL) == -1){
		printf("create error!\n");
		printf("create error!\n");
	}

	sleep(1);
	if (pthread_create(&tidp5, NULL, pthread1, NULL) == -1){
		printf("create error!\n");
	}
	sleep(1);
	if (pthread_create(&tidp6, NULL, pthread1, NULL) == -1){
		printf("create error!\n");
	}

	pthread_join(tidp1, NULL);
	pthread_join(tidp2, NULL);
	pthread_join(tidp3, NULL);
	pthread_join(tidp4, NULL);
	pthread_join(tidp5, NULL);
	pthread_join(tidp6, NULL);

	return 0;
}
