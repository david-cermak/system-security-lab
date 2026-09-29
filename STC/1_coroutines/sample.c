// Shows three core features:
//   1. A simple generator coroutine (cco_async / cco_yield).
//   2. A task that spawns concurrent worker fibers in a task-group.
//   3. Awaiting all spawned subtasks, with status + error handling.

#include <stdio.h>
#define STC_IMPLEMENT
#include <https://raw.githubusercontent.com/stclib/stcsingle/main/stc/coroutine.h>

// ---------------------------------------------------------------- 1. generator
struct Counter {
    cco_base base;
    int from, to, value;
};

int Counter(struct Counter* g) {
    cco_async (g) {
        for (g->value = g->from; g->value < g->to; ++g->value)
            cco_yield;
    }
    return 0;
}

// ---------------------------------------------------------------- 2. worker task
cco_task_struct (Worker) {
    Worker_base base;
    int id;
    cco_timer tm;
};

int worker(struct Worker* o) {
    cco_async (o) {
        printf("  worker %d: start\n", o->id);
        cco_await_timer(&o->tm, o->id * 0.1); // suspends, lets other workers run
        printf("  worker %d: done after %.1fs\n", o->id, cco_timer_elapsed(&o->tm));
    }
    return 0;
}

int generator(void)
{
    struct Counter gen = {.from = 0, .to = 5};
    cco_run_coroutine(Counter(&gen)) {
        printf("  %d\n", gen.value);
    }
}

// ------------------------------------------------------------ 3. boss task
cco_task_struct (Boss) {
    Boss_base base;
};

int boss(struct Boss* o) {
    cco_async (o) {
        cco_group_scope { // all spawned workers join this group
            for (c_range32(i, 4)) {
                struct Worker* w = c_new(struct Worker, {{worker}, .id = (int)i + 1});
                cco_spawn(w, cco_scope());
            }
            cco_suspend;             // yield so the workers start running
            cco_await_all(cco_scope()); // block until all workers finish
        }

        cco_finalize:
        puts("boss: all workers joined");
    }
    return 0;
}

int main(void) {
    puts("1. Generator coroutine:");
    generator();

    puts("2. Concurrent worker tasks:");
    cco_run_task(c_new(struct Boss, {{boss}}));
}


