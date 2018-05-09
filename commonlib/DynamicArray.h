#ifndef _DYNAMICARRAY
#define _DYNAMICARRAY

class DynamicArray {
	unsigned char *arr;
	unsigned int len;
	unsigned int max;

	DynamicArray(const DynamicArray&);
public:
	DynamicArray();
	DynamicArray(unsigned int prealloc_size);

	void appendBytes(unsigned char *new_text, unsigned int new_len);
	unsigned int getLength();
	unsigned char* getArray();
	unsigned char* detachArray();
};

#endif