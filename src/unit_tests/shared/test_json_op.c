/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "../../headers/json_op.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wazuh_modules/vulnerability_detector/mocks_wm_vuln_detector.h"

#define MAX_LENGHT_BUFFER_TEST 20

typedef struct
{
    char * path;
    char * buffer;
}test_json_op_t;

static int setup(void **state) {
    test_json_op_t * answer = (test_json_op_t *)malloc(sizeof(test_json_op_t));
    if (answer == NULL) {
        return -1;
    }
    answer->path = (char *)malloc(sizeof(char)*MAX_LENGHT_BUFFER_TEST);
    if (answer->path == NULL) {
        return -1;
    }
    answer->buffer = (char *)malloc(sizeof(char)*MAX_LENGHT_BUFFER_TEST);
    if (answer->buffer == NULL) {
        return -1;
    }
    answer->path = "/home/test";
    answer->buffer = "this is a test";
    *state = answer;
    return 0;
}

static int teardown(void **state) {
    free(*state);
    return 0;
}

static void test_json_fread(void **state) {
    test_json_op_t * answer = *state;

    will_return(__wrap_w_get_file_content, answer->buffer);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 8);

    cJSON * cjson = json_fread(answer->path, 0);

    printf("%s\n\r", answer->buffer);
    printf("%s\n\r", answer->path);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_json_fread, setup, teardown),
        };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
