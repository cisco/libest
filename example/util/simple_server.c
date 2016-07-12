/*------------------------------------------------------------------
 * simple_server.c - This is a very simple multi-threaded TCP
 *                   server used by the example EST server and EST
 *                   proxy applications. 
 *
 * August, 2013
 *
 * Copyright (c) 2013-2014, 2016 by cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
 */
#include <stdio.h>
#include <unistd.h>
#ifndef DISABLE_PTHREADS
#include <pthread.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <est.h>
#include <signal.h>



volatile int stop_flag = 0;
int sock;                 
static int tcp_port = 8085;
static int family = AF_INET;
volatile int num_threads; 
static EST_CTX *ctx;
#ifndef DISABLE_PTHREADS
pthread_mutex_t mutex;    
pthread_cond_t cond;      
int queue[20];
volatile int head;     
volatile int tail;     
pthread_cond_t full;   
pthread_cond_t empty;  

typedef void * (*thread_func_t)(void *);

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#define NUM_WORKER_THREADS 5


static int grab_work (int *sp)
{
    pthread_mutex_lock(&mutex);

    // Check for new work
    while (head == tail && stop_flag == 0) {
        pthread_cond_wait(&full, &mutex);
    }

    if (head > tail) {
        *sp = queue[tail % ARRAY_SIZE(queue)];
        tail++;

        // Keep our pointers aligned
        while (tail > (int)ARRAY_SIZE(queue)) {
            tail -= ARRAY_SIZE(queue);
            head -= ARRAY_SIZE(queue);
        }
    }

    pthread_cond_signal(&empty);
    pthread_mutex_unlock(&mutex);

    return !stop_flag;
}

static void * worker_thread (void* data)
{
    int sock = 0;

    while (grab_work(&sock)) {
	/*
	 * Both SERVER and PROXY modes use the
	 * same entry point to hand off the socket
	 * to libest
	 */
        est_server_handle_request(ctx, sock);
        close(sock);
    }

    // Tell the boss that we're finishing 
    pthread_mutex_lock(&mutex);
    num_threads--;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);
    return NULL;
}


static void process_socket (int fd)
{
    pthread_mutex_lock(&mutex);

    // Check if work queue is full and wait
    while (stop_flag == 0 && head - tail >= (int)ARRAY_SIZE(queue)) {
        pthread_cond_wait(&empty, &mutex);
    }

    if (head - tail < (int)ARRAY_SIZE(queue)) {
	// Put the accepted socket on to the work queue
        queue[head % ARRAY_SIZE(queue)] = fd;
        head++;
    }

    pthread_cond_signal(&full);
    pthread_mutex_unlock(&mutex);
}
#else
static void process_socket (int fd)
{
    est_server_handle_request(ctx, fd);
    close(fd);
}
#endif

static void * master_thread (void *data)
{
    struct sockaddr *addr;
    struct addrinfo hints, *ai, *aiptr;
    char portstr[12];
    int on = 1;
    int rc;
    int flags;
    int new;
    int unsigned len;

    /*
     * Lookup the local address we'll use to bind too
     */
    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; 
    snprintf(portstr, sizeof(portstr), "%u", tcp_port);
    rc = getaddrinfo(NULL, portstr, &hints, &aiptr);
    if (rc) {
        printf("\ngetaddrinfo call failed\n");
	printf("getaddrinfo(): %s\n", gai_strerror(rc));
        exit(1);
    }
    for (ai = aiptr; ai; ai = ai->ai_next) {
        sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
        if (sock == -1) {
	    /* If we can't create a socket using this address, then
	     * try the next address */
	    continue;
        }
	/*
	 * Set some socket options for our server
	 */
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on))) {
            printf("\nsetsockopt REUSEADDR call failed\n");
            exit(1);
        }
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on))) {
            printf("\nsetsockopt KEEPALIAVE call failed\n");
            exit(1);
        }
        flags = fcntl(sock, F_GETFL, 0);
        if (fcntl(sock, F_SETFL, flags | O_NONBLOCK)) {
            printf("\nfcntl SETFL call failed\n");
            exit(1);
        }
	/*
	 * Bind to the socket 
	 */
        rc = bind(sock, ai->ai_addr, ai->ai_addrlen);
        if (rc == -1) {
            printf("\nbind call failed\n");
            exit(1);
        }
	break;
    }
    if (ai) {
	addr = ai->ai_addr;
	listen(sock, SOMAXCONN);
    } else {
        printf("\nNo address info found\n");
        exit(1);
    }

    while (stop_flag == 0) {
        len = sizeof(struct sockaddr);
        new = accept(sock, (struct sockaddr*)addr, &len);
        if (new < 0) {
            if (stop_flag != 0) {
		break;
	    }
	    /*
	     * this is a bit cheesy, but much easier to implement than using select()
	     */
            usleep(100);
        } else {
            if (stop_flag == 0) {
                process_socket(new);
            }
        }
    }

    close(sock);
    freeaddrinfo(aiptr);

#ifndef DISABLE_PTHREADS
    // Notify all the workers that it's time to shutdown
    pthread_cond_broadcast(&full);

    // Wait for the workers to finish
    pthread_mutex_lock(&mutex);
    while (num_threads > 0) {
        pthread_cond_wait(&cond, &mutex);
    }
    pthread_mutex_unlock(&mutex);

    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);
    pthread_cond_destroy(&empty);
    pthread_cond_destroy(&full);
#endif

    stop_flag = 2;
    return NULL;
}

#ifndef DISABLE_PTHREADS
static int start_thread (thread_func_t func)
{
    pthread_t thread_id;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    return pthread_create(&thread_id, &attr, func, 0);
}
#endif

static void catch_int(int signo)
{
    stop_flag = 1;
}


/*
 * This is the entry point into the Simple TCP server.
 * This is designed to work with either the EST server
 * or EST proxy example applications.  This creates
 * a multi-threaded TCP server.  It opens a socket,
 * waits for incoming connections on the socket,
 * and dispatches work to a separate thread to process
 * the incoming EST request.
 *
 * Parameters:
 *     ectx	Pointer to the EST_CTX that was provided from
 *              calling est_server_init().
 *     port	The TCP port to listen too.
 *     delay	The number of seconds to wait before 
 *		automatically shutting down the server.
 *		Pass in 0 to run until keyboard input is 
 *		detected.
 *     v6       Set to non-zero value to enable IPv6
 */
void start_simple_server (EST_CTX *ectx, int port, int delay, int v6)
{
#ifndef DISABLE_PTHREADS
    int i;
#endif
    struct sigaction   sig_act;

    /*
     * Save a global reference to the context.
     * This code only supports running a single 
     * instance of the server.
     */
    ctx = ectx;
    tcp_port = port;
    if (v6) {
	family = AF_INET6;
    }

    /*
     * Install handler to catch ctrl-C to stop the process gracefully
     */
    memset(&sig_act, 0, sizeof(struct sigaction));
    sig_act.sa_handler = catch_int;
    sigemptyset(&sig_act.sa_mask);
    if (sigaction(SIGINT, &sig_act, NULL) == -1) {
        printf("\nCannot set handler for SIGINT\n");
    }

    /*
     * Indicate that the broken pipe signal during writes should be
     * ignored
     */
    memset(&sig_act, 0, sizeof(struct sigaction));
    sig_act.sa_handler = SIG_IGN;
    sigemptyset(&sig_act.sa_mask);
    if (sigaction(SIGPIPE, &sig_act, NULL) == -1) {
        printf("\nCannot set ignore action for SIGPIPE\n");
    }    
    
#ifndef DISABLE_PTHREADS
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond, NULL);
    pthread_cond_init(&empty, NULL);
    pthread_cond_init(&full, NULL);

    // Start master (listening) thread
    start_thread(master_thread);

    // Start worker threads
    for (i = 0; i < NUM_WORKER_THREADS; i++) {
        if (start_thread(worker_thread) != 0) {
            printf("\nCannot start worker thread: %d\n", errno);
        } else {
	    pthread_mutex_lock(&mutex);
            num_threads++;
	    pthread_mutex_unlock(&mutex);
        }
    }
#else
    /*
     * We're configured w/o support for pthreads.
     * Just run the server on the current thread.
     */
    master_thread(NULL);
#endif


    if (delay > 0) {
	/* We will automatically shut down the server
	 * after <delay> seconds */
	sleep(delay);
	stop_flag = 1;
    } 

    while (!stop_flag) {
        usleep(10000);	
    }
}

