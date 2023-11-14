#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

size_t base64_encoded_size(size_t input_length) {
    const size_t lenMod3 = input_length%3;
    size_t pad = ((lenMod3&1)<<1) + ((lenMod3&2)>>1);
    return 4*(input_length + pad) / 3;
}

size_t base64_decoded_size(const char* input) {
    size_t input_length = strlen(input);
    size_t padding = 0;

    if (input_length > 1 && input[input_length - 1] == '=')
        padding++;

    if (input_length > 2 && input[input_length - 2] == '=')
        padding++;

    return (input_length / 4) * 3 - padding;
}

int base64_encode(const unsigned char* input, size_t input_length, char** output) {
    if (input == NULL || output == NULL) {
        return -1; // Invalid input or output pointers
    }

    size_t encoded_size = base64_encoded_size(input_length);
    *output = (char*)malloc(encoded_size + 1);

    if (*output == NULL) {
        return -2; // Memory allocation failed
    }

    size_t i, j = 0;
    for (i = 0; i < input_length; i += 3) {
        unsigned char byte1 = input[i];
        unsigned char byte2 = (i + 1 < input_length) ? input[i + 1] : 0;
        unsigned char byte3 = (i + 2 < input_length) ? input[i + 2] : 0;

        (*output)[j++] = base64_chars[byte1 >> 2];
        (*output)[j++] = base64_chars[((byte1 & 0x3) << 4) | (byte2 >> 4)];
        if (i + 1 < input_length) {
            (*output)[j++] = base64_chars[((byte2 & 0xF) << 2) | (byte3 >> 6)];
        }
        if (i + 2 < input_length) {
            (*output)[j++] = base64_chars[byte3 & 0x3F];
        }
    }
    assert(j<=encoded_size);

    // Add padding if necessary
    while(j < encoded_size) {
        (*output)[j++] = '=';
    }

    (*output)[encoded_size] = '\0';
    return 0; // Success
}

int base64_decode(const char* input, unsigned char** output, size_t* output_length) {
    if (input == NULL || output == NULL || output_length == NULL) {
        return -1; // Invalid input, output, or length pointers
    }

    size_t input_length = strlen(input);

    if (input_length % 4 != 0) {
        return -2; // Invalid Base64 input length
    }

    *output_length = base64_decoded_size(input);
    *output = (unsigned char*)malloc(*output_length);

    if (*output == NULL) {
        return -3; // Memory allocation failed
    }

    size_t i, j = 0;
    for (i = 0; i < input_length; i += 4) {
        unsigned char byte[4];
        for(size_t k = 0; k<4; k++)
        {
            char* p = strchr(base64_chars, input[i+k]);
            if (NULL == p)
            {
                free(*output);
                *output = NULL;
                return -4;
            }
            byte[k] = p - base64_chars;
        }

        (*output)[j++] = (byte[0] << 2) | (byte[1] >> 4);
        if (byte[2] != 64) {
            (*output)[j++] = ((byte[1] & 0xF) << 4) | (byte[2] >> 2);
        }
        if (byte[3] != 64) {
            (*output)[j++] = ((byte[2] & 0x3) << 6) | byte[3];
        }
        assert(j<=*output_length);
    }
    return 0; // Success
}

void free_base64_buffer(void* buffer) {
    free(buffer);
}