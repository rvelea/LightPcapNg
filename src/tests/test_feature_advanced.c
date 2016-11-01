// test_feature_advanced.c
// Created on: Nov 1, 2016

// Copyright (c) 2016 Radu Velea

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "light_pcapng.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#define MAX_FEATURES 64

typedef double (*extractor_fn)(const light_pcapng);
static extractor_fn features[MAX_FEATURES] = {0,};
static int feature_count = 0;
static void *feature_lib_handle = NULL;

static int compile_features()
{
	int ret = system("make -C features");
	return ret;
}

static int extract_features()
{
	feature_lib_handle = dlopen("./features/libfeatures.so", RTLD_NOW);
	if (!feature_lib_handle) {
		dlerror();
		return -1;
	}

	FILE *feature_list = fopen("features/feature_list.txt", "r");
	if (!feature_list) {
		perror("Unable to open feature_list.txt");
		return -1;
	}

	char line[256] = {0,};
	while (fgets(line, sizeof(line), feature_list) != NULL) {
		if (line[strlen(line) - 1] == '\n') {
			line[strlen(line) - 1] = 0;
		}

		extractor_fn function = (extractor_fn)dlsym(feature_lib_handle, line);
		if (!function) {
			fprintf(stderr, "Unable to find symbol %s\n", line);
		}
		else {
			features[feature_count] = function;
			feature_count++;
		}
		memset(line, 0, sizeof(line));
	}

	fclose(feature_list);

	return 0;
}

int main(int argc, const char **args) {
	int i, j;

	if (compile_features() != 0) {
		fprintf(stderr, "Unable to compile features!\n");
		return EXIT_FAILURE;
	}

	if (extract_features() != 0) {
		fprintf(stderr, "Unable to extract function pointers!\n");
		return EXIT_FAILURE;
	}

	printf("Running feature extraction with %d functions and %d traces\n", feature_count, argc - 1);

	for (i = 1; i < argc; ++i) {
		const char *file = args[i];
		light_pcapng pcapng = light_read_from_path(file);
		if (pcapng != NULL) {
			double feature_values[MAX_FEATURES];
			light_option feature_option;

			printf("Extract features for %s\n", file);

			for (j = 0; j < feature_count; ++j) {
				feature_values[j] = features[j](pcapng);
			}

			feature_option = light_create_option(LIGHT_CUSTOM_OPTION_FEATURE_DOUBLE, feature_count * sizeof(double), feature_values);
			light_update_option(pcapng, pcapng, feature_option);
			light_pcapng_to_file(file, pcapng);

			light_free_option(feature_option);
			light_pcapng_release(pcapng);
		}
		else {
			fprintf(stderr, "Unable to read pcapng: %s\n", file);
		}
	}

	return EXIT_SUCCESS;
}
