/*------------------------------------------------------------------
 * simple_server_windows.c - 
 *                   This is a very simple Windows API 
 *                   multi-threaded  TCP server used by the 
 *                   example EST server and EST proxy 
 *                   applications when built on Windows. 
 *
 * April, 2016
 *
 * Copyright (c) 2016 by cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
 */
#include <stdio.h>
#include <WS2tcpip.h>
#include <fcntl.h>
#include <sys/types.h>
#include <est.h>
#include <signal.h>
#include <stdint.h>

#pragma comment(lib, "Ws2_32.lib")

#define NON_BLOCKING_SOCKET 1

volatile int stop_flag = 0;
int sock;
static int tcp_port = 8085;
static int family = AF_INET;
volatile int num_threads;
static EST_CTX *ctx;
CONDITION_VARIABLE cond;
CONDITION_VARIABLE BufferNotEmpty;
CONDITION_VARIABLE BufferNotFull;
CRITICAL_SECTION BufferLock;
int queue[20];
volatile int head;
volatile int tail;

#define SLEEP(x) Sleep(x*1000)

#define close(socket) closesocket(socket)
#define snprintf _snprintf

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#define NUM_WORKER_THREADS 5

static int grab_work (int *sp)
{
    EnterCriticalSection(&BufferLock);

    // Check for new work
    while (head == tail && stop_flag == 0) {
        SleepConditionVariableCS(&BufferNotEmpty, &BufferLock, INFINITE);
    }

    if (head > tail) {
        *sp = queue[tail % ARRAY_SIZE(queue)];
        tail++;

        // Keep our pointers aligned
        while (tail > (int) ARRAY_SIZE(queue)) {
            tail -= ARRAY_SIZE(queue);
            head -= ARRAY_SIZE(queue);
        }
    }

    WakeConditionVariable(&BufferNotFull);
    LeaveCriticalSection(&BufferLock);

    return !stop_flag;
}

DWORD WINAPI worker_thread (void* args)
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
    EnterCriticalSection(&BufferLock);
    num_threads--;
    WakeConditionVariable(&cond);
    LeaveCriticalSection(&BufferLock);
    return 0;
}

static void process_socket (int fd)
{
    EnterCriticalSection(&BufferLock);

    // Check if work queue is full and wait
    while (stop_flag == 0 && head - tail >= (int) ARRAY_SIZE(queue)) {
        SleepConditionVariableCS(&BufferNotFull, &BufferLock, INFINITE);
    }

    if (head - tail < (int) ARRAY_SIZE(queue)) {
        // Put the accepted socket on to the work queue
        queue[head % ARRAY_SIZE(queue)] = fd;
        head++;
    }

    WakeConditionVariable(&BufferNotEmpty);
    LeaveCriticalSection(&BufferLock);
}

static DWORD WINAPI master_thread_v4(LPVOID lpParam)
{
    int sock;
    struct sockaddr_in addr;
    int on = 1;
    int rc;
    int new;
    int unsigned len;

    u_long iMode = NON_BLOCKING_SOCKET;

    memset(&addr, 0x0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(tcp_port);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        fprintf(stderr, "\nsocket call failed\n");
        exit(1);
    }
    // Needs to be done to bind to both :: and 0.0.0.0 to the same port

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on));

    /*
	Replace POSIX code with Windows equivalent for setting non-blocking socket
     */
    ioctlsocket(sock, FIONBIO, &iMode);

    rc = bind(sock, (const struct sockaddr*)&addr, sizeof(addr));
    if (rc == -1) {
        fprintf(stderr, "\nbind call failed\n");
        exit(1);
    }
    listen(sock, SOMAXCONN);
    stop_flag = 0;

    while (stop_flag == 0) {
        len = sizeof(addr);
        new = accept(sock, (struct sockaddr*)&addr, &len);
        if (new < 0) {
            /*
             * this is a bit cheesy, but much easier to implement than using select()
             */

            SLEEP(1);
        }
        else {
            if (stop_flag == 0) {
                est_server_handle_request(ctx, new);
                close(new);
            }
        }
    }
    close(sock);
    return 0;
}

static DWORD WINAPI master_thread_v6 (LPVOID lpParam)
{
    int sock;
    struct sockaddr_in6 addr;
    int on = 1;
    int rc;
    int new;
    int unsigned len;

    u_long iMode = NON_BLOCKING_SOCKET;

    memset(&addr, 0x0, sizeof(struct sockaddr_in6));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons((uint16_t)tcp_port);

    sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        fprintf(stderr, "\nsocket call failed\n");
        exit(1);
    }
    // Needs to be done to bind to both :: and 0.0.0.0 to the same port
    int no = 0;
    setsockopt(sock, SOL_SOCKET, IPV6_V6ONLY, (void *)&no, sizeof(no));

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on));

    /*
	Replace POSIX code with Windows equivalent for setting non-blocking socket
     */
    ioctlsocket(sock, FIONBIO, &iMode);

    rc = bind(sock, (const struct sockaddr*)&addr, sizeof(addr));
    if (rc == -1) {
        fprintf(stderr, "\nbind call failed\n");
        exit(1);
    }
    listen(sock, SOMAXCONN);
    stop_flag = 0;

    while (stop_flag == 0) {
        len = sizeof(addr);
        new = accept(sock, (struct sockaddr*)&addr, &len);
        if (new < 0) {
            /*
             * this is a bit cheesy, but much easier to implement than using select()
             */

            SLEEP(1);
        }
        else {
            if (stop_flag == 0) {
                est_server_handle_request(ctx, new);
                close(new);
            }
        }
    }
    close(sock);
    return 0;
}

#if 0
DWORD WINAPI master_thread (void *arg)
{
    struct addrinfo hints, *ai, *aiptr;
    char portstr[12];
    int on = 1;
    int rc;
    int new;

    u_long iMode = NON_BLOCKING_SOCKET;

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
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*) &on,
            sizeof(on))) {
            printf("\nsetsockopt REUSEADDR call failed\n");
            exit(1);
        }
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*) &on,
            sizeof(on))) {
            printf("\nsetsockopt KEEPALIAVE call failed\n");
            exit(1);
        }

        ioctlsocket(sock, FIONBIO, &iMode);

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
        listen(sock, SOMAXCONN);
    } else {
        printf("\nNo address info found\n");
        exit(1);
    }

    while (stop_flag == 0) {
        new = accept(sock, NULL, NULL);
        if (new < 0) {
            if (stop_flag != 0) {
                break;
            }
            /*
             * this is a bit cheesy, but much easier to implement than using select()
             */
            SLEEP(1);
        } else {
            if (stop_flag == 0) {
                process_socket(new);
            }
        }
    }

    close(sock);
    freeaddrinfo(aiptr);

    // Notify all the workers that it's time to shutdown
    WakeAllConditionVariable(&BufferNotEmpty);

    // Wait for the workers to finish
    EnterCriticalSection(&BufferLock);
    while (num_threads > 0) {
        SleepConditionVariableCS(&cond, &BufferLock, INFINITE);
    }
    LeaveCriticalSection(&BufferLock);

    DeleteCriticalSection(&BufferLock);

    stop_flag = 2;
    return 0;
}
#endif

static HANDLE start_thread (LPTHREAD_START_ROUTINE func)
{
    DWORD mThreadID;

    return CreateThread(NULL, 0, func, NULL, 0, &mThreadID);
}

static void catch_int (int signo)
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
 *     ectx     Pointer to the EST_CTX that was provided from
 *              calling est_server_init().
 *     port     The TCP port to listen too.
 *     delay    The number of seconds to wait before 
 *              automatically shutting down the server.
 *              Pass in 0 to run until keyboard input is 
 *              detected.
 *     v6       Set to non-zero value to enable IPv6
 */
void start_simple_server (EST_CTX *ectx, int port, int delay, int v6)
{
    int i;

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
    signal(SIGINT, catch_int);

    InitializeCriticalSection(&BufferLock);
    InitializeConditionVariable(&cond);
    InitializeConditionVariable(&BufferNotEmpty);
    InitializeConditionVariable(&BufferNotFull);

    // Start master (listening) thread
    if (v6) {
        start_thread(master_thread_v6);
    } else {
        start_thread(master_thread_v4);
    }   

    // Start worker threads
    for (i = 0; i < NUM_WORKER_THREADS; i++) {
        if (start_thread(worker_thread) == NULL) {
            printf("\nCannot start worker thread\n");
        } else {
            EnterCriticalSection(&BufferLock);
            num_threads++;
            LeaveCriticalSection(&BufferLock);
        }
    }

    if (delay > 0) {
        /* We will automatically shut down the server
         * after <delay> seconds */
        SLEEP(delay);
        stop_flag = 1;
    }

    while (!stop_flag) {
        SLEEP(1);
    }
}

