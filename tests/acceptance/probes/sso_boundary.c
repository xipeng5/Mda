// SSO 边界探针：libc++ ABI v1 的 SSO 容量是 22 字符，第 23 个字符必须转堆。
// 只在真机跑，输出首字节（含 long flag）与 data 指针是否落在对象内部。
#include <stdio.h>
#include <string>
#include <cstdint>

int main(void) {
    printf("sizeof(std::string)=%zu\n", sizeof(std::string));
    for (int n = 0; n <= 32; n++) {
        std::string s(n, 'A');
        const unsigned char* raw = (const unsigned char*)&s;
        const unsigned char* data = (const unsigned char*)s.data();
        int inside = (data >= raw && data < raw + sizeof(s)) ? 1 : 0;
        printf("n=%2d first_byte=0x%02x data_inside_obj=%d size=%zu cap=%zu\n",
               n, raw[0], inside, s.size(), s.capacity());
    }
    return 0;
}
