/* Remote request listener
 * Copyright (C) 2015-2021, Wazuh Inc.
 * Mar 26, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "os_net/os_net.h"
#include "wazuh_modules/wmodules.h"
#include "maild.h"

size_t mailcom_dispatch(char * command, char ** output) {

    const char *rcv_comm = command;
    char *rcv_args = NULL;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "getconfig") == 0){
        // getconfig section
        if (!rcv_args){
            mdebug1("MAILCOM getconfig needs arguments.");
            os_strdup("err MAILCOM getconfig needs arguments", *output);
            return strlen(*output);
        }
        return mailcom_getconfig(rcv_args, output);

    } else {
        mdebug1("MAILCOM Unrecognized command '%s'.", rcv_comm);
        os_strdup("err Unrecognized command", *output);
        return strlen(*output);
    }
}

size_t mailcom_getconfig(const char * section, char ** output) {

    cJSON *cfg;
    char *json_str;

    if (strcmp(section, "global") == 0){
        if (cfg = getMailConfig(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "alerts") == 0){
        if (cfg = getMailAlertsConfig(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "internal") == 0){
        if (cfg = getMailInternalOptions(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    }
     else {
        goto error;
    }
error:
    mdebug1("At MAILCOM getconfig: Could not get '%s' section", section);
    os_strdup("err Could not get requested section", *output);
    return strlen(*output);
}


void * mailcom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;
    char socket_path[PATH_MAX + 1] = {0};

    snprintf(socket_path,PATH_MAX,"%s", MAIL_LOCAL_SOCK);

    mdebug1("Local requests thread ready");

    if (sock = OS_BindUnixDomain(socket_path, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s': (%d) %s.", MAIL_LOCAL_SOCK, errno, strerror(errno));
        return NULL;
    }

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("At mailcom_main(): select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror("At mailcom_main(): accept(): %s", strerror(errno));
            }

            continue;
        }

        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer,OS_MAXSTR), length) {
        case OS_SOCKTERR:
            merror("At mailcom_main(): OS_RecvSecureTCP(): response size is bigger than expected");
            break;

        case -1:
            merror("At mailcom_main(): OS_RecvSecureTCP(): %s", strerror(errno));
            break;

        case 0:
            mdebug1("Empty message from local client.");
            close(peer);
            break;

        case OS_MAXLEN:
            merror("Received message > %i", MAX_DYN_STR);
            close(peer);
            break;

        default:
            buffer[length] = '\0';
            length = mailcom_dispatch(buffer, &response);
            OS_SendSecureTCP(peer, length, response);
            free(response);
            close(peer);
        }
        free(buffer);
    }

    mdebug1("Local server thread finished.");

    close(sock);
    return NULL;
}
