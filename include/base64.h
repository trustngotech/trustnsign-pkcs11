#ifndef __BASE64_H__
#define __BASE64_H__

size_t base64_encoded_size(size_t input_length);
size_t base64_decoded_size(const char* input);
int base64_encode(const unsigned char* input, size_t input_length, char** output);
int base64_decode(const char* input, unsigned char** output, size_t* output_length);

#endif /* ifndef __BASE64_H__ */