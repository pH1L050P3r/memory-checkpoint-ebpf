#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include "checkpoint.h"
#include <sys/mman.h>

#define ACTION_INIT	0
#define ACTION_VERIFY	1

int num_elements = (1UL << 10);
int timeout = 20;
int array[100000000];
int *continue_work;

void init_params(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "n:t:")) != -1) {
		switch(c) {
			case 'n':
				num_elements = (1UL << atoi(optarg));
				break;
			case 't':
				timeout = atoi(optarg);
				break;
			default:
				printf("Usage: %s [-n num_elements(power of 2)] [-t timeout]\n", argv[0]);
				exit(0);
		}
	}
}

void handle_timer(int signal)
{
	*continue_work = 0;
}


static void do_good(int *buff, int action, int case4)
{
        int i;
        int num=num_elements;
        if(case4){
            num=100000000;
        }
	if (action == ACTION_INIT)
		for (i = 0; i < num; i++)
			buff[i] = i;

	if (action == ACTION_VERIFY)
		for (i = 0; i < num; i++)
			assert(buff[i] == i);
}

static inline void do_evil(int *buff,int case4)
{
        int i, *ptr;
        int num=num_elements;
        if(case4){
            num=100000000;
        }
        for (i = 0; i < num; i++) {
                buff[i] = 0 - buff[i];
	}
}

float run_testcase1()
{
        int nr_calls = 0, run = 1, ret;
        int *buff;
        buff = malloc(sizeof(int) * num_elements);
        assert(buff != NULL);
        continue_work = &run;

        signal(SIGALRM, handle_timer);
        alarm(timeout);

        do_good(buff, ACTION_INIT, 0);

        while (*continue_work) {
                /***** cleanup temp files *****/
                cleanup();
                nr_calls++;
                /***** save context *****/
                ret = savecontext();
		assert(ret == 0);
                /***** recover context *****/
                ret = recovercontext();
		assert(ret == 0);
        }
        do_good(buff, ACTION_VERIFY, 0);
        free(buff);
    printf("testcase1 ran\n");
	return (float)nr_calls / timeout;
}

float run_testcase2()
{
        int nr_calls = 0, run = 1, ret;
        int *buff;

        buff = malloc(sizeof(int) * num_elements);
        assert(buff != NULL);
        continue_work = &run;

        signal(SIGALRM, handle_timer);
        alarm(timeout);

        do_good(buff, ACTION_INIT, 0);

        while (*continue_work) {
                 /***** cleanup temp files *****/
                cleanup();
                nr_calls++;
                /***** save context *****/
                ret = savecontext();
		assert(ret == 0);
                /* suspicious code */
                do_evil(buff, 0);
                /***** recover context *****/
                ret = recovercontext();
		assert(ret == 0);
        }
        do_good(buff, ACTION_VERIFY, 0);
        free(buff);
        printf("testcase2 ran\n");
	return (float)nr_calls / timeout;
}

int run_testcase3()
{
        int *buff,ret;

        buff =  mmap((void *)0x7ff7ca71e000, sizeof(int) * num_elements, PROT_READ | PROT_WRITE ,MAP_ANON| MAP_SHARED, -1, 0);
        if (buff == MAP_FAILED){
               printf("failed mmap\n");
               return 0;
        }
        assert(buff != NULL);

        do_good(buff, ACTION_INIT, 0);

        /***** cleanup temp files *****/
        cleanup();

        /***** save context *****/
        ret = savecontext();
	assert(ret == 0);

        /* suspicious code */
        do_evil(buff, 0);

        /***** recover context *****/
        ret = recovercontext();
	assert(ret == 0);

        do_good(buff, ACTION_VERIFY, 0);
        munmap(buff, sizeof(int) * num_elements);
        printf("testcase3 ran\n");
	return 0;
}

int run_testcase4()
{
        int *buff,ret;

        buff =  array;

        do_good(buff, ACTION_INIT, 1);

        /***** cleanup temp files *****/
        cleanup();

        /***** save context *****/
        ret = savecontext();
	assert(ret == 0);

        /* suspicious code */
        do_evil(buff, 1);

        /***** recover context *****/
        ret = recovercontext();
	assert(ret == 0);

        do_good(buff, ACTION_VERIFY, 1);
        printf("testcase4 ran\n");
	return 0;
}