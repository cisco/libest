/*------------------------------------------------------------------
 * simple_server.c - This is a very simple multi-threaded TCP
 *                   server used by the example EST server and EST
 *                   proxy applications. 
 *
 * August, 2013
 *
 * Copyright (c) 2013-2014 by cisco Systems, Inc.
 * Copyright (c) 2015 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 **------------------------------------------------------------------
 */

// 2015-08-14 made server code re-entrant, allowing for any number of instances
// 2015-08-14 sharing master_thread() with unit tests, more efficient synchronization
// 2015-08-14 added start_single_server() and stop_single_server() for unit tests
// 2014-06-25 extended logging of server main activity

#include <est.h>
#include <stdio.h>
#ifndef DISABLE_PTHREADS
#include <pthread.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netdb.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <est_locl.h>
#include <signal.h>

static volatile int stop_flag = 0; /* global effect, used for reacting to Ctrl-C */

struct server_data {
    int tcp_port;
    int family;
    volatile int running; // set to 0 in order to stop single-threaded server
    volatile int num_threads; // -1 for single_threaded server
    EST_CTX *ctx;
#ifndef DISABLE_PTHREADS
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int queue[20];
    volatile int head;
    volatile int tail;
    pthread_cond_t full;
    pthread_cond_t empty;
#endif
};

static void process_socket_request (EST_CTX *ctx, int sock)
{
    /*
     * Both SERVER and PROXY modes use the same entry point to hand off the socket to libest
     */
    EST_ERROR rv = est_server_handle_request(ctx, sock);
    const char *agent = ctx->est_mode == EST_SERVER ? "Server" : "Proxy";
    printf("%s finished processing request on socket %d, rv=%d (%s)\n\n", agent, sock, rv, EST_ERR_NUM_TO_STR(rv));
    close(sock);
}

#ifndef DISABLE_PTHREADS

typedef void * (*thread_func_t)(void *);

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#define NUM_WORKER_THREADS 5


static int grab_work (struct server_data *data, int *sp)
{
    pthread_mutex_lock(&data->mutex);

    // Check for new work
    while (data->head == data->tail && stop_flag == 0) {
        pthread_cond_wait(&data->full, &data->mutex);
    }

    if (data->head > data->tail) {
        *sp = data->queue[data->tail];
        data->tail++;

        // Handle pointer wrap-around
        if (data->tail >= (int)ARRAY_SIZE(data->queue)) {
            data->tail -= ARRAY_SIZE(data->queue);
            data->head -= ARRAY_SIZE(data->queue);
        }
    }

    pthread_cond_signal(&data->empty);
    pthread_mutex_unlock(&data->mutex);

    return (stop_flag == 0);
}

static void *worker_thread (struct server_data *data)
{
    int sock = 0;

    while (grab_work(data, &sock)) {
        process_socket_request(data->ctx, sock);
    }

    // Tell the boss that we're finishing 
    pthread_mutex_lock(&data->mutex);
    data->num_threads--;
    pthread_cond_signal(&data->cond);
    pthread_mutex_unlock(&data->mutex);
    return NULL;
}


static void process_socket (struct server_data *data, int fd)
{
    pthread_mutex_lock(&data->mutex);

    // Check if work queue is full and wait
    while (stop_flag == 0 && data->head - data->tail >= (int)ARRAY_SIZE(data->queue)) {
        pthread_cond_wait(&data->empty, &data->mutex);
    }

    if (stop_flag == 0) {
	// Put the accepted socket on to the work queue
        data->queue[data->head % ARRAY_SIZE(data->queue)] = fd;
        data->head++;
    }

    pthread_cond_signal(&data->full);
    pthread_mutex_unlock(&data->mutex);
}
#else
static void process_socket (struct server_data *data, int fd)
{
    process_socket_request(data->ctx, fd);
}
#endif

static void *master_thread (struct server_data *data)
{
    struct sockaddr *addr;
    struct addrinfo hints, *ai, *aiptr;
    char portstr[12];
    int on = 1;
    int rc;
    int sock, new_sock;
    socklen_t len;

    data->running = 1; // used as signal for start_single_server()
    est_set_log_source(data->ctx->est_mode);
    const char *agent = data->ctx->est_mode == EST_SERVER ? "Server" : "Proxy";
    printf("%s listens on port %d\n", agent, data->tcp_port);
     /*
     * Lookup the local address we'll use to bind to
     */
    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_family = data->family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; 
    snprintf(portstr, sizeof(portstr), "%u", data->tcp_port);
    rc = getaddrinfo(NULL, portstr, &hints, &aiptr);
    if (rc) {
        printf("getaddrinfo call failed\n");
	printf("getaddrinfo(): %s\n", gai_strerror(rc));
        exit(1);
    }
    for (ai = aiptr; ai; ai = ai->ai_next) {
        sock = socket(data->family, SOCK_STREAM, IPPROTO_TCP);
        if (sock == -1) {
	    /* If we can't create a socket using this address, then
	     * try the next address */
	    continue;
        }
	/*
	 * Set some socket options for our server
	 */
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on))) {
            printf("setsockopt REUSEADDR call failed\n");
            exit(1);
        }
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on))) {
            printf("setsockopt KEEPALIAVE call failed\n");
            exit(1);
        }
#ifndef _WIN32
        int flags = fcntl(sock, F_GETFL, 0);
        if (fcntl(sock, F_SETFL, flags | O_NONBLOCK)) {
            printf("fcntl SETFL call failed\n");
            exit(1);
        }
#else
        // http://stackoverflow.com/questions/9534088/using-winsock-for-socket-programming-in-c
        unsigned long on = 1;
        if (0 != ioctlsocket(sock, FIONBIO, &on)) {
            printf("ioctlsocket non-block call failed\n");
            exit(1);
        }
#endif
	/*
	 * Bind to the socket 
	 */
        rc = bind(sock, ai->ai_addr, ai->ai_addrlen);
        if (rc == -1) {
            printf("bind call failed, likely because port %d is already in use\n", data->tcp_port);
            exit(1);
        }
	break;
    }
    if (ai) {
	addr = ai->ai_addr;
	listen(sock, SOMAXCONN);
    } else {
        printf("No address info found\n");
        exit(1);
    }

    printf("%s awaiting first connection on socket %d...\n", agent, sock); fflush(stdout);

    while (stop_flag == 0 && data->running != 0 && data->num_threads != 0) {
        len = sizeof(struct sockaddr);
        new_sock = accept(sock, (struct sockaddr*)addr, &len);
        if (new_sock < 0) {
	    if (new_sock != -1) {
		printf("Error accepting new connection on socket %d: %d", sock, new_sock);
	    }
            if (stop_flag != 0) {
		break;
	    }
#if 1 // should be best to use select(), which is called by wait_for_read()
	    wait_for_read(sock, 300*1000);
#else
	    /*
	     * this is a bit cheesy, but much easier to implement than using select()
	     */
            usleep(100);
#endif
        } else {
            if (stop_flag == 0) {
		printf("%s accepted new TCP connection on socket %d\n", agent, new_sock);
		fflush(stdout);
		if (data->num_threads == -1) // single-threaded
		    process_socket_request(data->ctx, new_sock);
		else
		    process_socket(data, new_sock);
		printf("%s awaiting further connection on socket %d...\n", agent, sock); fflush(stdout);
            } else {
                close(new_sock);
            }
        }
    }

    close(sock);
    freeaddrinfo(aiptr);

    if (data->num_threads == -1){
	data->num_threads = 0; // used as signal for stop_single_server()
	return NULL;
    }

#ifndef DISABLE_PTHREADS
    // Notify all the workers that it's time to shutdown
    pthread_cond_broadcast(&data->full);

    // Wait for the workers to finish
    pthread_mutex_lock(&data->mutex);
    while (data->num_threads > 0) {
        pthread_cond_wait(&data->cond, &data->mutex);
    }
    pthread_mutex_unlock(&data->mutex);

    pthread_mutex_destroy(&data->mutex);
    pthread_cond_destroy(&data->cond);
    pthread_cond_destroy(&data->empty);
    pthread_cond_destroy(&data->full);
#endif

    return NULL;
}

#ifndef DISABLE_PTHREADS
static int start_thread (void *(*func)(struct server_data *data), struct server_data *data)
{
    pthread_t thread_id;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    return pthread_create(&thread_id, &attr, (thread_func_t)func, data);
}
#endif

static void catch_int(int signo)
{
    stop_flag = 1;
}


/*
 * This enters the main loop of a multi-threaded TCP server.
 * This is designed to work with either the EST server
 * or EST proxy example applications. It opens a socket,
 * waits for incoming connections on the socket,
 * and dispatches work to a separate thread to process
 * the incoming EST request.
 *
 * Parameters:
 *     ectx	Pointer to the EST_CTX that was provided from
 *              calling est_server_init().
 *     port	The TCP port to listen to.
 *     delay	The number of seconds to wait before 
 *		automatically shutting down the server.
 *		Pass in 0 to run until Ctrl-C is detected.
 *     v6       Set to non-zero value to enable IPv6
 */
void start_simple_server (EST_CTX *ectx, int port, int delay, int v6)
{
    struct server_data data;
    data.ctx = ectx;
    data.tcp_port = port;
    data.family = v6 ? AF_INET6 : AF_INET;

    /*
     * Install handler to catch ctrl-C to stop all threads gracefully
     */
    signal(SIGINT, catch_int);

#ifndef DISABLE_PTHREADS
    data.num_threads = 0;
    pthread_mutex_init(&data.mutex, NULL);
    pthread_cond_init(&data.cond, NULL);
    pthread_cond_init(&data.empty, NULL);
    pthread_cond_init(&data.full, NULL);
    data.head = data.tail = 0;

    // Start worker threads
    int i;
    for (i = 0; i < NUM_WORKER_THREADS; i++) {
        if (start_thread(worker_thread, &data) != 0) {
            printf("Cannot start worker thread: %d\n", errno);
        } else {
	    pthread_mutex_lock(&data.mutex);
            data.num_threads++;
	    pthread_mutex_unlock(&data.mutex);
        }
    }

    // Start master (listening) thread
    start_thread(master_thread, &data);

#else
    /*
     * We're configured w/o support for pthreads.
     * Just run the server on the current thread.
     */
    data.num_threads = -1;
    master_thread(&data);
#endif

    if (delay > 0) {
	/* We will automatically shut down the server after <delay> seconds */
	sleep(delay);
	stop_flag = 1;
    } 

    while (stop_flag == 0) {
        sleep(1); // some usleep() implementations appear to cause high CPU load
    }

 // must not auto-free the data struct before all threads have finished
    while (data.num_threads > 0) {
        sleep(1);
    }
}

/*
 * This launches a single-threaded TCP server.
 * Allows for any number of test EST servers or EST proxy servers.
 *
 * Parameters:
 *     ectx	Pointer to the EST_CTX that was provided from
 *              calling est_server_init().
 *     port	The TCP port to listen too.
 *     v6       Set to non-zero value to enable IPv6
 * Returns:
 *     Pointer to an internal structure to be used later to stop the server.
 */
void *start_single_server (EST_CTX *ectx, int port, int v6)
{
    struct server_data *data = (struct server_data *)malloc(sizeof (struct server_data));
    if (data == NULL) {
	return NULL;
    }
    data->ctx = ectx;
    data->tcp_port = port;
    data->family = v6 ? AF_INET6 : AF_INET;
    data->num_threads = -1;
#ifndef DISABLE_PTHREADS
    data->running = 0;
    pthread_t thread;
    pthread_create(&thread, NULL, (thread_func_t)master_thread, data);
    int timeout = 3000;
    while (data->running == 0 && --timeout > 0) {
        usleep(1000);
    }
#else
    master_thread(data);
#endif
    return (data);
}

/*
 * This stops a single-threaded TCP server started before.
 * This must eventually be called to free the data structure.
 *
 * Parameters:
 *     server	Pointer to data strucure obtained from start_single_server()
 */
void stop_single_server (void *server)
{
    struct server_data *data = (struct server_data *) server;
    if (data == NULL) {
	return;
    }
    data->running = 0;
    int timeout = 3000;
    while (data->num_threads != 0 && --timeout > 0) {
        usleep(1000);
    }
    if (data->num_threads == 0) {
	free(data);
    }
}
