#include "cryptoneat/uuid.h"

#ifdef _WIN32
#include <rpc.h>
#else
#include <uuid/uuid.h>
#endif

namespace cryptoneat {


#ifndef _WIN32

std::string uuid::generate()
{
    uuid_t uuid;
    uuid_generate_random(uuid);

    char buf[40];
    uuid_unparse(uuid,buf);

    return buf;
}

#else



std::string uuid::generate()
{
	UUID id;
	::UuidCreate(&id);

	unsigned char* buf = 0;
	::UuidToStringA(&id, &buf);

	std::string ret((char*)buf);
	::RpcStringFreeA(&buf);
	return ret;
}



#endif




} // end namespaces