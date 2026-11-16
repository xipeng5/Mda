// 自建 hold 测试靶子：每 200ms 调一次 work()，打印计数。
// 用途：验证 hold 断点是否真的停住线程（计数停止增长）与放行后恢复。
#include <stdio.h>
#include <unistd.h>
#include <time.h>

__attribute__((noinline)) volatile int work(int i) {
    // 一点可观测副作用，避免被优化掉
    volatile int x = i * 3 + 1;
    return x;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int i = 1; i <= 3000; i++) {
        int r = work(i);
        printf("tick %d r=%d\n", i, r);
        usleep(200 * 1000);
    }
    return 0;
}
