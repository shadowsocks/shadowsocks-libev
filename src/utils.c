#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define INT_DIGITS 19		/* enough for 64 bit integer */

void ERROR(const char *s) {
    char *msg = strerror(errno);
    LOGE("%s: %s", s, msg);

}

char *itoa(int i) {
    /* Room for INT_DIGITS digits, - and '\0' */
    static char buf[INT_DIGITS + 2];
    char *p = buf + INT_DIGITS + 1;	/* points to terminating '\0' */
    if (i >= 0) {
        do {
            *--p = '0' + (i % 10);
            i /= 10;
        } while (i != 0);
        return p;
    }
    else {			/* i < 0 */
        do {
            *--p = '0' - (i % 10);
            i /= 10;
        } while (i != 0);
        *--p = '-';
    }
    return p;
}

char *ss_strndup(const char *s, size_t n) {
    size_t len = strlen(s);
    char *ret;

    if (len <= n) return strdup(s);

    ret = malloc(n + 1);
    strncpy(ret, s, n);
    ret[n] = '\0';
    return ret;
}

void FATAL(const char *msg) {
    LOGE("%s", msg);
    exit(-1);
}

void usage() {
    printf("\n");
    printf("shadowsocks-libev %s\n\n", VERSION);
    printf("  maintained by Max Lv <max.c.lv@gmail.com>\n\n");
    printf("  usage:\n\n");
    printf("    ss-[local|redir|server]\n");
    printf("          -s server_host -p server_port -l local_port -k password\n");
    printf("          [-m encrypt_method] [-f pid_file] [-t timeout] [-c config_file]\n");
    printf("\n");
    printf("  options:\n\n");
    printf("    encrypt_method:     table, rc4, aes-128-cfb, aes-192-cfb, aes-256-cfb,\n");
    printf("                        bf-cfb, cast5-cfb, des-cfb\n");
    printf("          pid_file:     valid path to the pid file\n");
    printf("           timeout:     socket timeout in senconds\n");
    printf("       config_file:     json format config file\n");
    printf("\n");
}

void demonize(const char* path) {

    /* Our process ID and Session ID */
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    /* If we got a good PID, then
       we can exit the parent process. */
    if (pid > 0) {
        FILE *file = fopen(path, "w");
        if (file == NULL) FATAL("Invalid pid file\n");

        fprintf(file, "%d", pid);
        fclose(file);
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Open any logs here */        

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

