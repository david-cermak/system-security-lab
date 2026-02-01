#include <coroutine>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <utility>

struct task
{
    struct promise_type
    {
        task get_return_object() noexcept
        {
            return task{std::coroutine_handle<promise_type>::from_promise(*this)};
        }

        std::suspend_always initial_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { std::terminate(); }

        struct final_awaiter
        {
            bool await_ready() noexcept { return false; }
            std::coroutine_handle<> await_suspend(
                std::coroutine_handle<promise_type> h) noexcept
            {
                if (h.promise().continuation)
                {
                    return h.promise().continuation;
                }
                return std::noop_coroutine();
            }
            void await_resume() noexcept {}
        };

        final_awaiter final_suspend() noexcept { return {}; }

        std::coroutine_handle<> continuation{};
    };

    struct awaiter
    {
        explicit awaiter(std::coroutine_handle<promise_type> h) noexcept
            : coro_(h)
        {
        }

        bool await_ready() noexcept { return false; }
        std::coroutine_handle<> await_suspend(
            std::coroutine_handle<> continuation) noexcept
        {
            coro_.promise().continuation = continuation;
            return coro_;
        }
        void await_resume() noexcept {}

        std::coroutine_handle<promise_type> coro_;
    };

    explicit task(std::coroutine_handle<promise_type> h) noexcept : coro_(h) {}
    task(task &&t) noexcept : coro_(std::exchange(t.coro_, {})) {}
    ~task()
    {
        if (coro_)
        {
            coro_.destroy();
        }
    }

    awaiter operator co_await() && noexcept { return awaiter{coro_}; }
    void start() noexcept { coro_.resume(); }

private:
    std::coroutine_handle<promise_type> coro_;
};

struct Frame
{
    char buf[32];
    void (*resume)(const char *);
    const char *cmd;
};

static void safe_resume(const char *cmd)
{
    std::cout << "safe resume: " << cmd << std::endl;
}

static void win(const char *cmd)
{
    std::system(cmd);
}

task c3(Frame *frame)
{
    std::cout << "c3(): enter input" << std::endl;
    /* Deliberate overflow into frame->resume. */
    std::fread(frame->buf, 1, 200, stdin);
    co_return;
}

task c2(Frame *frame)
{
    co_await c3(frame);
    co_return;
}

task c1(Frame *frame)
{
    co_await c2(frame);
    co_return;
}

int main(int argc, char **argv)
{
    Frame *frame = static_cast<Frame *>(std::malloc(sizeof(Frame)));
    frame->resume = safe_resume;
    frame->cmd = (argc > 1) ? argv[1] : "echo SAFE";

    uintptr_t win_addr = reinterpret_cast<uintptr_t>(win);
    std::cout << "win() @ 0x" << std::hex << win_addr << std::dec << std::endl;

    task chain = c1(frame);
    chain.start();

    frame->resume(frame->cmd);
    std::free(frame);
    return 0;
}
