#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define MSB_ON 0x8000000000000000;
#define PP 8589942785; // Primitive Polynomial
#define NUM_ROUND 6;

// 먼저 GF(2^33)에서 X^3 연산부터 구현해보기

typedef struct {
    uint32_t high; // only LSB is used
    uint64_t low;
} uint65_t;

typedef struct {
    uint8_t data[4];
} key_t;

uint64_t p = PP;

uint64_t add_GF(uint64_t op1, uint64_t op2);
uint65_t add_GF_65(uint65_t op1, uint65_t op2);
// 피연산자 2개 받고, 마지막으로 irreducible polynomial을 받는다.
uint64_t mul_GF(uint64_t op1, uint64_t op2, uint64_t pp);
uint64_t mul_GF_65(uint64_t op1, uint64_t op2, uint64_t pp);
uint65_t shift_uint65(uint65_t op, int count);
uint64_t cubing_func(uint64_t op);

int bit_length(uint64_t num);
int bit_length_uint65(uint65_t num);

void encrypt(uint8_t* pt, uint8_t* ct, key_t* k);
void dump_mem(uint8_t* mem, int count);

int main(int argc, char* argv[])
{
    // uint64_t a = 0b100000000000000000000000000000000;
    // uint64_t res = cubing_func(a);
    // printf("%llu\n", res);
    int rounds = NUM_ROUND;
    key_t sub_keys[6];
    for (int i = 0; i < rounds; i++) {
        memset(&sub_keys[i], 41 + i, sizeof(key_t));
    }
    uint8_t plaintext[8];
    uint8_t ciphertext[8];
    memset(plaintext, 90, sizeof(plaintext));
    memset(ciphertext, 0, sizeof(ciphertext));
    encrypt(plaintext, ciphertext, sub_keys);
    dump_mem(ciphertext, 8);
    return 0;
}

void encrypt(uint8_t* pt, uint8_t* ct, key_t* k)
{
    uint32_t left;
    uint32_t right;
    uint32_t tmp;
    uint64_t subkey;
    uint64_t extended_right;
    // copy plaintext and ready to start feistal struct
    memcpy(&left, &pt[0], sizeof(left));
    memcpy(&right, &pt[4], sizeof(right));
    for (int i = 0; i < 6; i++)
    {   
        tmp = right;
        // extension MSB -> cubing function -> discard MSB
        extended_right = 0;
        extended_right = right;
        subkey = 0;
        memcpy(&subkey, &k[i], sizeof(key_t));
        subkey |= 0x100000000;
        extended_right = cubing_func(add_GF(subkey, extended_right));
        extended_right &= 0xffffffff;
        
        right = (uint32_t)add_GF((uint64_t)left, extended_right);
        left = tmp;
    }

    memcpy(&ct[0], &right, sizeof(right));
    memcpy(&ct[4], &left, sizeof(left));
}

uint64_t cubing_func(uint64_t op)
{
    assert(bit_length(op) <= 32);
    
    uint64_t res = mul_GF_65(op, op, p);
    // printf("%llu\n", res);

    assert(bit_length(res) <= 32);
    res = mul_GF_65(res, op, p);

    return res;
}

uint64_t add_GF(uint64_t op1, uint64_t op2)
{
    return op1 ^ op2;
}

uint65_t add_GF_65(uint65_t op1, uint65_t op2)
{
    uint65_t res;
    memset(&res, 0, sizeof(res));
    res.high = op1.high ^ op2.high;
    res.low = op1.low ^ op2.low;
    return res;
}

uint65_t shift_uint65(uint65_t op, int count)
{
    uint65_t res;
    memset(&res, 0, sizeof(res));
    if (!count) {
        return op;
    }
    res.high = (op.low >> (64 - count)) & 1;
    res.low = op.low << count;
    return res;
}

uint64_t mul_GF(uint64_t op1, uint64_t op2, uint64_t pp)
{
    uint8_t bit = op2 & 1;
    uint64_t sum = 0;
    uint64_t adder = op1;
    // 먼저 그냥 해서 더한다
    for (uint32_t i = 0; i <= bit_length(op2); i++)
    {
        if ((op2 >> i) & 1) {
            sum = add_GF(sum, (adder << i));
        }
    }

    // 그 다음에 pp 보다 degree 같거나 높으면 그러지 않을 떄까지, pp로 계속 나눈 나머지를 sum으로 한다.
    int flag = bit_length(sum) - bit_length(pp);
    while (flag >= 0) {
        sum = add_GF(sum, pp << flag);
        flag = bit_length(sum) - bit_length(pp);
    }
    return sum;
}

uint64_t mul_GF_65(uint64_t op1, uint64_t op2, uint64_t pp)
{
    uint8_t bit = op2 & 1;
    uint65_t sum;
    memset(&sum, 0, sizeof(sum));
    uint65_t adder;
    adder.high = 0;
    adder.low = op1;
    // 먼저 그냥 해서 더한다
    for (uint32_t i = 0; i <= bit_length(op2); i++)
    {
        if ((op2 >> i) & 1) {
            sum = add_GF_65(sum, shift_uint65(adder, i));
        }
    }
    // 그 다음에 pp 보다 degree 같거나 높으면 그러지 않을 떄까지, pp로 계속 나눈 나머지를 sum으로 한다.
    int flag = bit_length_uint65(sum) - bit_length(pp);
    uint65_t pp_;
    memset(&pp_, 0, sizeof(pp_));
    pp_.low = pp;
    while (flag >= 0) {
        sum = add_GF_65(sum, shift_uint65(pp_, flag));
        flag = bit_length_uint65(sum) - bit_length(pp);
    }
    return sum.low;
}


// 가장 왼쪽에 있는 1 bit 위치 나타내기
int bit_length(uint64_t num)
{
    uint64_t number = num;
    uint64_t flag = number & MSB_ON;
    int ret = 63;
    while (ret) {
        if (flag) {
            return ret;
        } else {
            ret -= 1;
            number <<= 1;
            flag = number & MSB_ON;
        }
    }
    return ret;
}

int bit_length_uint65(uint65_t num)
{
    if (num.high & 1) {
        return 64;
    } else {
        return bit_length(num.low);
    }
}

void dump_mem(uint8_t* mem, int count)
{
    for (int i = 0; i < count; i++) {
        if (count % 16 == 15) {
            printf("%02X\n", mem[i]);
        } else {
            printf("%02X ", mem[i]);
        }
    }
    puts("");
}