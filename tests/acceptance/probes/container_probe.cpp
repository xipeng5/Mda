// 只为拿到 libc++ std::string/vector/map 的真实内存布局（真机 ground truth）
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <cstdint>

static void dump(const char* tag, const void* p, size_t n) {
    const unsigned char* b = (const unsigned char*)p;
    printf("%s (%zu bytes): ", tag, n);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main() {
    printf("sizeof(std::string)=%zu\n", sizeof(std::string));
    // SSO：短串（15 字符以内）
    std::string sso = "hello";
    dump("sso.bytes", &sso, sizeof(sso));
    printf("sso.data=%p sso.c_str=%s size=%zu\n", (void*)sso.data(), sso.c_str(), sso.size());
    // 长串
    std::string lng(64, 'A');
    dump("long.bytes", &lng, sizeof(lng));
    printf("long.data=%p size=%zu cap=%zu\n", (void*)lng.data(), lng.size(), lng.capacity());
    // 边界：14 / 15 / 16 字符
    for (int n = 14; n <= 17; n++) {
        std::string s(n, 'x');
        unsigned char first = ((const unsigned char*)&s)[0];
        unsigned char last = ((const unsigned char*)&s)[sizeof(s)-1];
        printf("n=%d first_byte=0x%02x last_byte=0x%02x data=%p\n", n, first, last, (void*)s.data());
    }
    std::vector<int> v = {1,2,3};
    dump("vector.bytes", &v, sizeof(v));
    printf("vector.size=%zu cap=%zu data=%p begin_off0=%d\n", v.size(), v.capacity(), (void*)v.data(), *(int*)((char*)&v));
    std::map<int,int> m; m[1]=10; m[2]=20; m[3]=30;
    dump("map.bytes", &m, sizeof(m));
    printf("map.size=%zu\n", m.size());
    return 0;
}
