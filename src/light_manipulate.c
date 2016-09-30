// light_manipulate.c
// Created on: Jul 23, 2016

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

#include "light_debug.h"
#include "light_internal.h"
#include "light_util.h"

#include <stdlib.h>
#include <string.h>

light_option light_create_option(const uint16_t option_code, uint16_t option_length, void *option_value)
{
	uint16_t size = 0;
	light_option option = calloc(1, sizeof(struct _light_option));

	PADD32(option_length, &size);
	option->custom_option_code = option_code;
	option->option_length = option_length;

	option->data = calloc(size, sizeof(uint8_t));
	memcpy(option->data, option_value, option_length);

	return option;
}

int light_add_option(light_pcapng section, light_pcapng pcapng, light_option option, light_boolean copy)
{
	size_t option_size = 0;
	light_option option_list = NULL;

	if (copy == LIGHT_TRUE) {
		option_list = __copy_option(option);
	}
	else {
		option_list = option;
	}

	if (pcapng->options == NULL) {
		pcapng->options = option_list;
	}
	else {
		light_option current = pcapng->options;
		while (current->next_option && current->next_option->custom_option_code != 0) {
			current = current->next_option;
		}

		light_option opt_endofopt = current->next_option;
		current->next_option = option_list;
		option_list->next_option = opt_endofopt;
	}

	uint32_t *tmp = __get_option_size(option, &option_size); // TODO: Make specialized functions.
	free(tmp);

	pcapng->block_total_lenght += option_size;

	if (__is_section_header(section) == 1) {
		struct _light_section_header *shb = (struct _light_section_header *)section->block_body;
		shb->section_length += option_size;
	}
	else {
		PCAPNG_WARNING("PCAPNG block is not section header!");
	}

	return LIGHT_SUCCESS;
}

int light_subcapture(const light_pcapng section, light_boolean (*predicate)(const light_pcapng), light_pcapng *subcapture)
{
	if (__is_section_header(section) == 0) {
		PCAPNG_ERROR("Invalid section header");
		return LIGHT_INVALID_SECTION;
	}

	// Root section header is automatically included into the subcapture.
	light_pcapng root = __copy_block(section, LIGHT_FALSE);
	light_pcapng iterator = root;
	light_pcapng next_block = section->next_block;

	while (next_block != NULL) {
		// Predicate functions applies to all block types, including section header blocks.
		if (!!predicate(next_block) == LIGHT_TRUE) {
			iterator->next_block = __copy_block(next_block, LIGHT_FALSE);
			iterator = iterator->next_block;
		}
		next_block = next_block->next_block;
	}

	*subcapture = root;
	return __validate_section(*subcapture);

}

