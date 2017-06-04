/*
 * feature_impl.c
 *
 *  Created on: Nov 1, 2016
 *      Author: rvelea
 */

#include "features.h"

#include <light_pcapng.h>

#include <stdio.h>

static uint64_t my_pow(uint32_t base, uint32_t exponent)
{
	uint64_t result = 1;

	while (exponent-- > 0) {
		result = result * base;
	}

	return result;
}

feature_type_t _f_data_transfered(const light_pcapng pcapng)
{
	feature_type_t bytes = 0;
	uint32_t block_type;
	light_pcapng iterator = pcapng;

	while (iterator != NULL) {
		light_get_block_info(iterator, LIGHT_INFO_TYPE, &block_type, NULL);
		if (block_type == LIGHT_ENHANCED_PACKET_BLOCK) {
			struct _light_enhanced_packet_block *epb;
			light_get_block_info(iterator, LIGHT_INFO_BODY, &epb, NULL);
			bytes += epb->original_capture_length;
		}
		else if (block_type == LIGHT_SIMPLE_PACKET_BLOCK) {
			struct _light_simple_packet_block *spb;
			light_get_block_info(iterator, LIGHT_INFO_BODY, &spb, NULL);
			bytes += spb->original_packet_length;
		}

		iterator = light_next_block(iterator);
	}

	return bytes;
}

feature_type_t _f_trace_duration(const light_pcapng pcapng)
{
	feature_type_t duration;
	uint64_t resolution = 1000; // Microsecond resolution.
	int first_block = 1;
	uint64_t first_timestamp = 0;
	uint64_t current_timestamp = 0;
	uint32_t block_type;
	light_pcapng iterator = pcapng;

	while (iterator != NULL) {
		light_get_block_info(iterator, LIGHT_INFO_TYPE, &block_type, NULL);
		if (block_type == LIGHT_INTERFACE_BLOCK) {
			light_option timestamp_resolution = light_get_option(iterator, LIGHT_OPTION_IF_TSRESOL);
			if (timestamp_resolution != NULL) {
				uint8_t *interface_resolution = (uint8_t *)light_get_option_data(timestamp_resolution);
				uint8_t value = *interface_resolution & 0x7F;

				if ((*interface_resolution & 0x80) == 0) { // Resolution is negative power of 10.
					resolution = 1000000000 / my_pow(10, value);
				}
				else { // Resolution is negative power of 2.
					resolution = 1000000000 / my_pow(2, value);
				}

				if (resolution == 0) {
					fprintf(stderr, "Invalid resolution: %u\n", value);
					resolution = 1000;
				}
			}
		}
		else if (block_type == LIGHT_ENHANCED_PACKET_BLOCK) {
			struct _light_enhanced_packet_block *epb;
			light_get_block_info(iterator, LIGHT_INFO_BODY, &epb, NULL);
			current_timestamp = ((uint64_t)epb->timestamp_high << 32) + epb->timestamp_low;
			if (first_block == 1) {
				first_timestamp = current_timestamp;
				first_block = 0;
			}
			else if (first_timestamp > current_timestamp) {
				fprintf(stderr, "We are going back in time!\n");
				first_timestamp = current_timestamp;
			}
		}
		/*
		else if (pcapng->block_type == LIGHT_SIMPLE_PACKET_BLOCK) {
			struct _light_simple_packet_block *spb = (struct _light_simple_packet_block *)pcapng->block_body;
		}
		*/

		iterator = light_next_block(iterator);
	}

	// Returning the duration in nanoseconds.
	duration = (current_timestamp - first_timestamp) * resolution;
	return duration;
}

feature_type_t _f_avg_packet_interval(const light_pcapng pcapng)
{
	feature_type_t duration;
	uint64_t resolution = 1000; // Microsecond resolution.
	int first_block = 1;
	uint64_t first_timestamp = 0;
	uint64_t current_timestamp = 0;
	uint32_t block_type;
	light_pcapng iterator = pcapng;
	uint32_t enhanced_block_count = 0;

	while (iterator != NULL) {
		light_get_block_info(iterator, LIGHT_INFO_TYPE, &block_type, NULL);
		if (block_type == LIGHT_INTERFACE_BLOCK) {
			light_option timestamp_resolution = light_get_option(iterator, LIGHT_OPTION_IF_TSRESOL);
			if (timestamp_resolution != NULL) {
				uint8_t *interface_resolution = (uint8_t *)light_get_option_data(timestamp_resolution);
				uint8_t value = *interface_resolution & 0x7F;

				if ((*interface_resolution & 0x80) == 0) { // Resolution is negative power of 10.
					resolution = 1000000000 / my_pow(10, value);
				}
				else { // Resolution is negative power of 2.
					resolution = 1000000000 / my_pow(2, value);
				}

				if (resolution == 0) {
					fprintf(stderr, "Invalid resolution: %u\n", value);
					resolution = 1000;
				}
			}
		}
		else if (block_type == LIGHT_ENHANCED_PACKET_BLOCK) {
			struct _light_enhanced_packet_block *epb;
			light_get_block_info(iterator, LIGHT_INFO_BODY, &epb, NULL);
			current_timestamp = ((uint64_t)epb->timestamp_high << 32) + epb->timestamp_low;
			if (first_block == 1) {
				first_timestamp = current_timestamp;
				first_block = 0;
			}
			else if (first_timestamp > current_timestamp) {
				fprintf(stderr, "We are going back in time!\n");
				first_timestamp = current_timestamp;
			}
			enhanced_block_count++;
		}
		/*
		else if (pcapng->block_type == LIGHT_SIMPLE_PACKET_BLOCK) {
			struct _light_simple_packet_block *spb = (struct _light_simple_packet_block *)pcapng->block_body;
		}
		*/

		iterator = light_next_block(iterator);
	}

	// Returning the duration in nanoseconds.
	if (enhanced_block_count) {
		duration = (current_timestamp - first_timestamp) * resolution / enhanced_block_count;
		return duration;
	}
	else {
		return -1;
	}
}

feature_type_t _f_address_relation(const light_pcapng pcapng)
{
	feature_type_t ret = -1;
	uint32_t block_type;
	light_pcapng iterator = pcapng;
	int i;

	light_option address_option = light_get_option(pcapng, LIGHT_CUSTOM_OPTION_ADDRESS_INFO);

	if (address_option != NULL) {
		uint8_t *label = (uint8_t *)light_get_option_data(address_option);
		if (*label == 4) {
			uint8_t source[4], destination[4];
			memcpy(source, label + 1, sizeof(uint32_t));
			memcpy(destination, label + 5, sizeof(uint32_t));

			ret = 0;
			for (i = 0; i < 4; ++i) {
				uint32_t match = !!(source[i] == destination[i]);

				if (match == 0) {
					break;
				}
				ret = (ret << 1) + match;
			}

			// source[0], source[1], source[2], source[3],
			// destination[0], destination[1], destination[2], destination[3];
		}
	}

	return ret;
}

