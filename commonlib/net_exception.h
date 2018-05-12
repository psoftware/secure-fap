#ifndef _NETEXCEPTION
#define _NETEXCEPTION

#include <iostream>
#include <string>

using namespace std;

class net_exception {
private:
	string msg_;

public:
	net_exception(const string& msg) : msg_(msg) {}
	~net_exception() {}

	string getMessage() const;
};

#endif