/* monitor: monitoring userspace process's memory for e6500 core
 *
 * 1 What is it?
 * It is used to record which thread has modified the shared memory.
 * It can monitor a single memory(for example 0x10013010) or
 * a range of memory(for example, 0x10013010-0x10013110).
 * If you want to monitor a range of memory, the watchpoint kernel module
 * is needed.
 * It need to add some codes in the monitored process's source code,
 * as test.c.
 *
 * 2 How to use it?
 * 2.1 Modifying the monitored task's source code, as test.c
 *
 * 2.2 Do not use watchpoint module
 * It can just monitor a address with 4-byte aligned, such as
 * 0x10013010, 0x10013014, 0x10013018, 0x1001301c and so on.
 *
 * # ./test &
 * [1] 466
 * # ./monitor -f /var/log/monitor_log -p 466
 * 466 is test process pid, /var/log/monitor_log is a file for recording
 * the information
 * And if a thread has modified the monitored memory, the log is as following
 * Thu Jan  1 17:57:24 1970				---------> The is time
 *	 The monitorted memory(0x10013010) is modifying by ------> what is the address
 *	 task(pid:466, command:test)			  -------> which process and it's name
 *	 thread(tid:470, command:thread_174)		  -------> which thread has modified, and it's name
 *	 the current instruction address:0x10001378	---------> which instruction
 *	 the old value:0xae				---------> the current value(before modified)
 *
 * 2.2 using watchpoint module
 * If you want to monitor any userspace address(not just 4-byte aligned),
 * Please using the watchpoint module.
 * # insmod watchpoint.ko
 * # ./test &
 * [1] 477
 * # ./monitor -f /var/log/monitor_log -p 477
 * waiting for the monitor finished
 *
 * Copyright (C) 2017 WindRiver
 *      http://www.windriver.com
 * Author: Sun Jiwei <jiwei.sun@windriver.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

//#define DEBUG_getopt
#ifdef DEBUG_getopt
#define dbg_opt(f, a...)	fprintf(stdout, f, ## a)
#else
#define dbg_opt(f, a...)
#endif

#define BUF_SIZE (1024)

struct shared_st {
	unsigned long write;
	unsigned long start_addr;
	unsigned long len;
};

static inline void print_usage(FILE *stream, char *progname)
{
	fprintf(stream, "Usage: %s [-p monitorted task's pid] [-f log file]"
			" [-h] \n"
			"For example, \n"
			"%s -f /var/log/monitor_log -p 1134\n",
			progname, progname);
}

static int is_exist(pid_t pid)
{
	FILE* fp;
	char proc_pid_path[128];

	sprintf(proc_pid_path, "/proc/%d/", pid);
	fp = fopen(proc_pid_path, "r");
	if (NULL != fp) {
		fclose(fp);
		return 1;
	}

	return 0;
}

static void getnamebypid(pid_t pid, pid_t tid, char *task_name)
{
	FILE* fp;
	char proc_pid_path[128];
	char buf[BUF_SIZE];

	sprintf(proc_pid_path, "/proc/%d/task/%d/comm", pid, tid);

	fp = fopen(proc_pid_path, "r");
	if (NULL != fp) {
		if (fgets(buf, BUF_SIZE - 1, fp) == NULL) {
			goto out;
		}
		sscanf(buf, "%s", task_name);
out:
		fclose(fp);
	}
}

#define DIR_PATH	"/sys/kernel/debug/watchpoint/range_watchpoint"
#define PID_NAME	(DIR_PATH"/pid")
#define START_ADDR_NAME	(DIR_PATH"/start_addr")
#define END_ADDR_NAME	(DIR_PATH"/end_addr")
#define WRITE_NAME	(DIR_PATH"/write")
#define READ_NAME	(DIR_PATH"/read")
#define ENABLE_NAME	(DIR_PATH"/enable")

static int is_watchpoint(void)
{
	FILE* fp;

	fp = fopen(PID_NAME, "r");
	if (NULL != fp) {
		fclose(fp);
		return 1;
	}

	return 0;
}

static void monitor(char *pid, char *start_addr, char *end_addr)
{
	int fd;

	fd = open(PID_NAME, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open %s error", PID_NAME);
		exit(1);
	}
	write(fd, pid, strlen(pid));
	close(fd);

	fd = open(START_ADDR_NAME, O_RDWR);
	if (fd < 0) {
		printf("open %s error", START_ADDR_NAME);
		exit(1);
	}
	write(fd, start_addr, strlen(start_addr));
	close(fd);

	fd = open(END_ADDR_NAME, O_RDWR);
	if (fd < 0) {
		printf("open %s error", END_ADDR_NAME);
		exit(1);
	}
	write(fd, end_addr, strlen(end_addr));
	close(fd);

	fd = open(READ_NAME, O_RDWR);
	if (fd < 0) {
		printf("open %s error", READ_NAME);
		exit(1);
	}
	write(fd, "0", 1);
	close(fd);

	fd = open(WRITE_NAME, O_RDWR);
	if (fd < 0) {
		printf("open %s error", WRITE_NAME);
		exit(1);
	}
	write(fd, "1", 1);
	close(fd);

	fd = open(ENABLE_NAME, O_RDWR);
	if (fd < 0) {
		printf("open %s error", ENABLE_NAME);
		exit(1);
	}
	write(fd, "1", 1);
	close(fd);
}

static inline int monitor_memory(pid_t child_pid,
		unsigned long start_addr, unsigned long len)
{
	if (is_watchpoint()) {
		char pid[11] = {0};
		char s_addr[25] = {0};
		char e_addr[25] = {0};

		sprintf(pid, "%d", child_pid);
		sprintf(s_addr, "0x%lx", start_addr);
		//start_addr <= monitor_addr < end_addr
		sprintf(e_addr, "0x%lx", start_addr + len);
		monitor(pid, s_addr, e_addr);

	} else {
		fprintf(stdout, "Warnning, there is no watchpoint module,\n"
				" using ptrace, and only monitor a single address\n"
				" the monitored address is (start_addr(0x%lx) & (~0x3)) = 0x%lx\n",
				start_addr, start_addr & (~0x3UL));
		start_addr &= ~0x3;
		ptrace(PTRACE_SET_DEBUGREG, child_pid, 0, start_addr | 2);
	}
	return 0;
}

static inline void monitor_created_thread(pid_t child_pid,
		unsigned long addr, unsigned long length)
{
	char proc_pid_path[128];
	DIR *d;
	struct dirent *file;

	sprintf(proc_pid_path, "/proc/%d/task/", child_pid);
	if (!(d = opendir(proc_pid_path))) {
		fprintf(stderr, "error opendir %s!!!/n", proc_pid_path);
		exit(EXIT_FAILURE);
	}

	while ((file = readdir(d)) != NULL) {
		pid_t thread_pid;
		if (strncmp(file->d_name, ".", 1) == 0)
			continue;
		if (strncmp(file->d_name, "..", 1) == 0)
			continue;
		thread_pid = atoi(file->d_name);
		monitor_memory(thread_pid, addr, length);
	}
	closedir(d);
}

static void get_addr(pid_t child_pid, unsigned long *start_addr, unsigned long *len)
{
	void *shm = NULL;
	struct shared_st *shared = NULL;
	int shmid;

	/* "WIND"'s ASCII is 87737868 */
	shmid = shmget((key_t)87737868, sizeof(struct shared_st),
			0666 | IPC_CREAT);
	if (shmid == -1) {
		fprintf(stderr, "shmget failed\n");
		exit(EXIT_FAILURE);
	}

	shm = shmat(shmid, (void*)0, 0);
	if (shm == (void*)(-1)) {
		fprintf(stderr, "shmat failed\n");
		exit(EXIT_FAILURE);
	}
	shared = (struct shared_st*)shm;
	*start_addr = shared->start_addr;
	*len = shared->len;
	monitor_created_thread(child_pid, *start_addr, *len);
	shared->write = 0;

	if(shmdt(shm) == -1) {
		fprintf(stderr, "shmdt failed\n");
		exit(EXIT_FAILURE);
	}
	if(shmctl(shmid, IPC_RMID, 0) == -1) {
		fprintf(stderr, "shmctl(IPC_RMID) failed\n");
		exit(EXIT_FAILURE);
	}

}

static void try_to_attach_child_pid(void)
{
	int shmid;
	void *shm = NULL;
	struct shared_st *shared = NULL;

	/* "WINE"'s ASCII is 87737869 = 87737868 + 1 */
	shmid = shmget((key_t)87737869, sizeof(struct shared_st),
			0666 | IPC_CREAT);
	if (shmid == -1) {
		fprintf(stderr, "shmget failed\n");
		exit(EXIT_FAILURE);
	}

	shm = shmat(shmid, (void*)0, 0);
	if (shm == (void*)(-1)) {
		fprintf(stderr, "shmat failed\n");
		exit(EXIT_FAILURE);
	}
	shared = (struct shared_st*)shm;

	shared->write = 87737869;

	if (shmdt(shm) == -1) {
		fprintf(stderr, "shmdt failed\n");
		exit(EXIT_FAILURE);
	}

	if (shmctl(shmid, IPC_RMID, 0) == -1) {
		fprintf(stderr, "shmctl(IPC_RMID) failed\n");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	int opt;
	char *log_file = NULL;
	pid_t child_pid;
	unsigned long addr = 0;
	unsigned long length = 0;
	int status = 0;
	char task_name[BUF_SIZE];
	siginfo_t child_sig;
	long ptraceoption = PTRACE_O_TRACECLONE;
	pid_t child_waited;
	FILE* fp;

	while ((opt = getopt(argc, argv, "p:f:h")) != -1) {
		switch (opt) {
			case 'p':
				child_pid = atoi(optarg);
				break;
			case 'f':
				log_file = strdup(optarg);
				break;
			case 'h':
			default:
				print_usage(stdout, argv[0]);
				exit(1);
				break;
		}
	}

	if ((!log_file) || (child_pid <= 1)) {
		print_usage(stdout, argv[0]);
		exit(1);
	}

	dbg_opt("log_file:%s\n", log_file);

	if (!is_exist(child_pid)) {
		fprintf(stdout, "Please input a exist task\n");
		exit(1);
	}

	fp = fopen(log_file, "w+");
	if (NULL == fp) {
		fprintf(stdout, "Please input a right log file %d\n", __LINE__);
		exit(1);
	}

	ptrace(PTRACE_ATTACH, child_pid, NULL, NULL);

	wait(NULL);
	getnamebypid(child_pid, child_pid, task_name);
	ptrace(PTRACE_SETOPTIONS, child_pid, NULL, ptraceoption);
	ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	try_to_attach_child_pid();

	while(1) {
		child_waited = waitpid(-1, &status, __WALL);

		if (WIFEXITED(status)) {
			fprintf(fp, "thread %d exited with status %d\t\n",
					child_waited,
					WEXITSTATUS(status));
			if (child_waited == child_pid) {
				fprintf(fp, "The task %d exited,"
						" and now stop monitoring\n",
						child_pid);
				break;
			}
		}

		if (child_waited == -1) {
			fprintf(stderr, "Execption exit,Error:%s\n",
					strerror(errno));
			break;
		}

		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGUSR1) {
			ptrace(PTRACE_GETSIGINFO, child_waited, 0, &child_sig);
			if ((child_sig.si_code == -6) && (child_sig.si_errno == 0)) {
				get_addr(child_pid, &addr, &length);
				break;
			}
		}

		ptrace(PTRACE_CONT, child_waited, 1, NULL);
	}

	if (addr) {
		monitor_memory(child_pid, addr, length);
	}
	ptrace(PTRACE_CONT, child_waited, 1, NULL);

	while(1) {
		time_t timep;

		child_waited = waitpid(-1, &status, __WALL);

		time (&timep);
		if (WIFEXITED(status)) {
			fprintf(fp, "%s\t Thread %d exited with status %d\t\n",
					asctime(localtime(&timep)),
					child_waited,
					WEXITSTATUS(status));
			if (child_waited == child_pid) {
				fprintf(stdout, "The task %d exited,"
						" and now stop monitoring\n",
						child_pid);
				break;
			}
		}

		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
			ptrace(PTRACE_GETSIGINFO, child_waited, 0, &child_sig);
			/* It is monitoring signal, recording some useful information*/
			if ((child_sig.si_code == 4) && (child_sig.si_errno == 5)) {
				char thread_name[BUF_SIZE];
				struct pt_regs regs;
				unsigned long old_value;
				ptrace(PTRACE_GETREGS64, child_waited, 0, &regs);
				getnamebypid(child_pid, child_waited, thread_name);
				old_value = ptrace(PTRACE_PEEKDATA, child_waited,
						(unsigned long)child_sig.si_addr, 0);
				if (old_value == -1)
					fprintf(stderr, "read the old value error, errno:%d\n", errno);

				fprintf(fp, "%s\t The monitorted memory(0x%lx) is modifying by\n\t"
						" task(pid:%d, command:%s)\n\t"
						" thread(tid:%d, command:%s)\n\t"
						" the current instruction address:0x%lx\n\t"
						" the old value:0x%02x\n",
						asctime(localtime(&timep)),
						child_sig.si_addr, child_pid, task_name,
						child_waited, thread_name, regs.nip,
						(unsigned char)old_value);
				ptrace(PTRACE_SINGLESTEP, child_waited, 0, 0);
				continue;
			}

			/* It is SINGLESTEP signal, start monitoring child_waited thread*/
			if ((child_sig.si_code == 2) && (child_sig.si_errno == 0)) {
				monitor_memory(child_waited, addr, length);
			}

			/* New thread was cloned, and start monitoring the thread */
			if (((status >> 16) & 0xffff) == PTRACE_EVENT_CLONE) {
				pid_t new_pid;
				if (ptrace(PTRACE_GETEVENTMSG, child_waited, 0, &new_pid) != -1) {
					monitor_memory(child_waited, addr, length);
				}
			}
		}

		if (child_waited == -1) {
			fprintf(stderr, "Execption exit,Error:%s\n",
					strerror(errno));
			break;
		}

		ptrace(PTRACE_CONT, child_waited, 1, NULL);
	}

	fclose(fp);
	return 0;
}
