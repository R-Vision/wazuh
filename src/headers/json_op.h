/*
 * JSON support library
 * Copyright (C) 2015, Wazuh Inc.
 * May 11, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef JSON_OP_H
#define JSON_OP_H

#define JSON_MAX_FSIZE 536870912
// Check if a JSON object is tagged
#define json_tagged_obj(x) (x && x->string)

#ifdef DEBUG
    #define WEAK_FOR_DEBUG __attr__((weak))
#else
    #define WEAK_FOR_DEBUG
#endif

#include <external/cJSON/cJSON.h>

/**
 * @brief It temporarily saves in memory the content of the file located in path.
 * It also allows requesting and verifying that the JSON has a null termination 
 * and recovers the pointer to the last parsed byte.
 * 
 * @param path  location of the file to be read.
 * @param retry allows to retry the operation if parsing to json fails.
 * @return cJSON* 
 */
cJSON * json_fread(const char * path, char retry);

/**
 * @brief Represent a cJSON entity in plain text for storage in the file located at path.
 * 
 * @param path location of the file to be write.
 * @param item json entity to be represented in text.
 * @return int stores the result of the write operation.
 */
int json_fwrite(const char * path, const cJSON * item);

/**
 * @brief Clear C/C++ style comments from a JSON string.
 * 
 * @param json json to which comment stripping is applied.
 */
void json_strip(char * json);

#endif
