#include "DynamicArray.h"
#include <string.h>
#include <stdio.h>

DynamicArray::DynamicArray() : len(0), max(1) {
	arr = new unsigned char[max];
}

DynamicArray::DynamicArray(unsigned int prealloc_size) : len(0), max(prealloc_size) {
	arr = new unsigned char[max];
}

void DynamicArray::appendBytes(unsigned char *new_text, unsigned int new_len)
{
	unsigned char *current_text;
	if(this->len + new_len > this->max)
	{
		// we need to realloc
		current_text = new unsigned char[this->len + new_len];
		memcpy(current_text, this->arr, this->len);
		delete[] this->arr;
	}
	else
		current_text = this->arr;

	memcpy(current_text + this->len, new_text, new_len);

	this->max = this->len + new_len;
	this->len += new_len;
	this->arr = current_text;
	//printf("base_len = %u base_max = %u\n", this->len, this->max);
}

unsigned int DynamicArray::getLength() {
	return this->len;
}

unsigned char* DynamicArray::getArray() {
	return arr;
}

unsigned char* DynamicArray::detachArray() {
	unsigned char *res = this->arr;

	// regenerate array
	this->arr = new unsigned char[1];
	this->max = 1;
	this->len = 0;

	return res;
}