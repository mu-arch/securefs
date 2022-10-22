#include <boost/stacktrace/stacktrace.hpp>
#include <iostream>

extern "C" void __cxa_pure_virtual()
{
    std::cerr << "Pure virtual method called.\nStack trace:\n\n"
              << boost::stacktrace::stacktrace() << std::endl;
    std::abort();
}
