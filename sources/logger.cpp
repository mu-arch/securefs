#include "logger.h"
#include "myutils.h"
#include "platform.h"

#include <stdarg.h>
#include <stdio.h>

#ifdef WIN32
#include <Windows.h>
#include <time.h>

static void flockfile(FILE*) {}
static void funlockfile(FILE*) {}

static const void* current_thread_id(void)
{
    return reinterpret_cast<const void*>(GetCurrentThreadId());
}
#else
#include <pthread.h>
static const void* current_thread_id(void) { return (void*)(pthread_self()); }
#endif

namespace securefs
{
void Logger::vlog(LoggingLevel level, const char* format, va_list args) noexcept
{
    if (!m_fp || level < this->get_level())
        return;

    struct tm now;
    int now_ns = 0;
    OSService::get_current_time_in_tm(&now, &now_ns);

    flockfile(m_fp);

    if (m_fp == stderr)
    {
        switch (level)
        {
        case kLogWarning:
            OSService::set_color_on_stderr(Color::DarkGrey);
            break;
        case kLogError:
            OSService::set_color_on_stderr(Color::BrightRed);
            break;
        default:
            break;
        }
    }

    fprintf(m_fp,
            "[%s] [%p] [%d-%02d-%02d %02d:%02d:%02d.%09d UTC]    ",
            stringify(level),
            current_thread_id(),
            now.tm_year + 1900,
            now.tm_mon + 1,
            now.tm_mday,
            now.tm_hour,
            now.tm_min,
            now.tm_sec,
            now_ns);
    vfprintf(m_fp, format, args);

    if (m_fp == stderr && (level == kLogWarning || level == kLogError))
    {
        OSService::set_color_on_stderr(Color::Default);
    }

    putc('\n', m_fp);
    fflush(m_fp);
    funlockfile(m_fp);
}

void Logger::log(LoggingLevel level, const char* format, ...) noexcept
{
    if (!m_fp || level < this->get_level())
        return;
    va_list args;
    va_start(args, format);
    vlog(level, format, args);
    va_end(args);
}

Logger::Logger(FILE* fp, bool close_on_exit)
    : m_level(kLogInfo), m_fp(fp), m_close_on_exit(close_on_exit)
{
}

Logger::~Logger()
{
    if (m_close_on_exit)
        fclose(m_fp);
}

Logger* Logger::create_stderr_logger() { return new Logger(stderr, false); }

Logger* Logger::create_file_logger(const std::string& path)
{
#ifdef WIN32
    FILE* fp = _wfopen(widen_string(path).c_str(), L"a");
#else
    FILE* fp = fopen(path.c_str(), "a");
#endif
    if (!fp)
        THROW_POSIX_EXCEPTION(errno, path);
    return new Logger(fp, true);
}

std::unique_ptr<Logger> global_logger(Logger::create_stderr_logger());
}
