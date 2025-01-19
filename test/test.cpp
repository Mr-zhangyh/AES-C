
#include "cAes.h"
#include <time.h>
#include <stdlib.h>


void test_expendKey() {

	AesKeyBox key;
	unsigned char ky16[16] = {
	0x2b,0x7e,0x15,0x16,
	0x28,0xae,0xd2,0xa6,
	0xab,0xf7,0x15,0x88,
	0x09,0xcf,0x4f,0x3c
	};
	unsigned char ky24[24] = {
	0x8e,0x73,0xb0,0xf7,
	0xda,0x0e,0x64,0x52,
	0xc8,0x10,0xf3,0x2b,
	0x80,0x90,0x79,0xe5,
	0x62,0xf8,0xea,0xd2,
	0x52,0x2c,0x6b,0x7b
	};
	unsigned char ky32[32] = {
	0x60,0x3d,0xeb,0x10,
	0x15,0xca,0x71,0xbe,
	0x2b,0x73,0xae,0xf0,
	0x85,0x7d,0x77,0x81,
	0x1f,0x35,0x2c,0x07,
	0x3b,0x61,0x08,0xd7,
	0x2d,0x98,0x10,0xa3,
	0x09,0x14,0xdf,0xf4
	};
	typedef  struct {
		uchar c0;
		uchar c1;
		uchar c2;
		uchar c3;
	}uw, * puw;
	AesInit(&key, ky16, AES128);
	puw w = (puw)key.expandKey;

	for (uchar i = 0; i < (key.Nr + 1) * 4; i++) {
		printf("\nw[%hhd]=\t%02x%02x%02x%02x ", i, w[i].c0, w[i].c1, w[i].c2, w[i].c3);
		if (!((i + 1) % 4)) {
			printf("\n");
		}

	}

	AesInit(&key, ky24, AES192);
	w = (puw)key.expandKey;

	for (uchar i = 0; i < (key.Nr + 1) * 4; i++) {
		printf("\nw[%d]=\t%02x%02x%02x%02x ", i, w[i].c0, w[i].c1, w[i].c2, w[i].c3);
		if (!((i + 1) % 4)) {
			printf("\n");
		}
	}
	AesInit(&key, ky32, AES256);
	printf("\nAES%d_expendKey：\n", AES256*8);
	w = (puw)key.expandKey;
	for (uchar i = 0; i < (key.Nr + 1) * 4; i++) {
		printf("\nw[%d]=\t%02x%02x%02x%02x ", i, w[i].c0, w[i].c1, w[i].c2, w[i].c3);
		if (!((i + 1) % 4)) {
			printf("\n");
		}
	}

}

void  test() {
	int zp[3][5][7] = {
	111,112,113,114,115,116,117,
	121,122,123,124,125,126,127,
	131,132,133,134,135,136,137,
	141,142,143,144,145,146,147,
	151,152,153,154,155,156,157,
	211,212,213,214,215,216,217,
	221,222,223,224,225,226,227,
	231,232,233,234,235,236,237,
	241,242,243,244,245,246,247,
	251,252,253,254,255,256,257,
	311,312,313,314,315,316,317,
	321,322,323,324,325,326,327,
	331,332,333,334,335,336,337,
	341,342,343,344,345,346,347,
	351,352,353,354,355,356,357 };

	for (size_t i = 1; i <= 3; i++) {
		for (size_t j = 1; j <= 5; j++) {
			for (size_t k = 1; k <= 7; k++) {
				printf("zp[%d][%d][%d]=\t%p\n", i, j, k, &zp[i - 1][j - 1][k - 1]);
			}
		}
	}

	typedef  int(*pz)[5][7];
	int(*ip)[5][7] = zp;
	pz p = zp;

	int* rp = (int*)zp;
	printf("zp[2][2][2]=%d\n", *(rp + (5 * 7 * 1 + 1 * 7 + 1)));
	printf("zp[2][2][2]=%d\n", p[1][1][1]);
	printf("数组指针zp:\n");
	printf("zp=\t%d\n", *(int*)ip);
	printf("zp+1=\t%d\n", *(int*)(ip + 1));
	printf("ip[1][2][1]=%d\n", ip[0][1][0]);
	printf("ip[1][2][1]=%d\n", *(*(*(ip + 0) + 1) + 0));



}

void test_01() {
	//声明 keybox
	AesKeyBox keybox;
	//密钥数组
	unsigned char key[16] = {
	0x2b,0x7e,0x15,0x16,
	0x28,0xae,0xd2,0xa6,
	0xab,0xf7,0x15,0x88,
	0x09,0xcf,0x4f,0x3c
	};
	//初始化keybox
	AesInit(&keybox, key, AES128);
	//明文
	unsigned char data[16] = {
	0x32,0x43,0xf6,0xa8,
	0x88,0x5a,0x30,0x8d,
	0x31,0x31,0x98,0xa2,
	0xe0,0x37,0x07,0x34
	};

	printf("明文:\t");
	for (unsigned char i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n密钥:\t");
	for (unsigned char i = 0; i < 16; i++) {
		printf("%02x ", key[i]);
	}
	AesBlockCipher(&keybox, data);

	printf("\n\n密文为:\t");
	for (unsigned char i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	
	AesInvBlockCipher(&keybox, data);
	printf("\n明文为:\t");
	for (unsigned char i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n\n");
}


void test_02Aes128() {

	printf("\n\n\n/************Aes128加密模式——开始****************/\n");
	AesKeyBox keybox;
	unsigned char data[16] = {
	0x00,0x11,0x22,0x33,
	0x44,0x55,0x66,0x77,
	0x88,0x99,0xaa,0xbb,
	0xcc,0xdd,0xee,0xff
	};
	unsigned char key[] = { 00,01,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };

	AesInit(&keybox, key, AES128);
	
	printf("\n明文为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n密钥为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", key[i]);
	}

	AesBlockCipher(&keybox, data);
	printf("\n\n密文为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	AesInvBlockCipher(&keybox, data);
	printf("\n解密后：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n\n/************Aes128加密模式——结束****************/\n");
}
void test_02Aes128_by_molloc() {

	printf("\n\n\n/************Aes128加密模式——开始****************/\n");
	AesKeyBox *keybox=(AesKeyBox*)malloc(sizeof(AesKeyBox));
	unsigned char data[16] = {
	0x00,0x11,0x22,0x33,
	0x44,0x55,0x66,0x77,
	0x88,0x99,0xaa,0xbb,
	0xcc,0xdd,0xee,0xff
	};
	unsigned char key[] = { 00,01,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };

	AesInit(keybox, key, AES128);

	printf("\n明文为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n密钥为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", key[i]);
	}

	AesBlockCipher(keybox, data);
	printf("\n\n密文为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}

	AesBlockCipher(keybox, data);
	printf("\n\n2*密文为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}

	AesInvBlockCipher(keybox, data);
	printf("\n1*解密后：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}

	AesInvBlockCipher(keybox, data);
	printf("\n2*解密后：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n\n/************Aes128加密模式——结束****************/\n");
}

void test_02Aes192() {
	printf("\n\n\n/************Aes192加密模式——开始****************/\n");
	AesKeyBox keybox;
	unsigned char data[16] = {
	0x00,0x11,0x22,0x33,
	0x44,0x55,0x66,0x77,
	0x88,0x99,0xaa,0xbb,
	0xcc,0xdd,0xee,0xff
	};
	unsigned char key[] = { 00,01,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 };

	AesInit(&keybox, key, AES192);

	printf("\n明文为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n密钥为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", key[i]);
	}

	AesBlockCipher(&keybox, data);
	printf("\n\n密文为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}

	AesInvBlockCipher(&keybox, data);
	printf("\n解密后：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n\n/************Aes192加密模式——结束****************/\n");
}
void test_02Aes256() {

	printf("\n\n\n/************Aes256加密模式——开始****************/\n");
	AesKeyBox keybox;

	unsigned char data[16] = {
	0x00,0x11,0x22,0x33,
	0x44,0x55,0x66,0x77,
	0x88,0x99,0xaa,0xbb,
	0xcc,0xdd,0xee,0xff
	};
	unsigned char key[] = { 00,01,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 };

	AesInit(&keybox, key, AES256);

	printf("\n明文为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n密钥为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", key[i]);
	}

	AesBlockCipher(&keybox, data);
	printf("\n\n密文为：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	AesInvBlockCipher(&keybox, data);

	printf("\n解密后：\t");
	for (size_t i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n\n/************Aes256加密模式——结束****************/\n");
}



int  main() {
	uchar data[16] = { 0xd4,0xbf,0x5d,0x30,0xe0,0xb4,0x52,0xae,0xb8,0x41,0x11,0xf1,0x1e,0x27,0x98,0xe5 };
	//MixColumns(data);
	//MixColumns_byTable(data);
	//for (uchar i = 0; i < Nb * 4; i++) {
	//	printf("%02x ", data[i]);
	//}



	//clock_t t0 = clock();
	//for (int i = 0; i < 100000000; i++) {
	//	MixColumns_byTable(data);
	//}
	//clock_t t1 = clock();
	//printf("time0=%d\n", t1 - t0);

	//t0 = clock();
	//for (int i = 0; i < 100000000; i++) {
	//	MixColumns(data);
	//}
	//t1 = clock();
	//printf("time1=%d\n", t1 - t0);

	printf("AesBox结构体大小：%d\n", sizeof(AesKeyBox));
	//test_expendKey();
	//test_01();
	//test_02Aes128();
	//test_02Aes192();
	//test_02Aes256();
	test_02Aes128_by_molloc();

	return 0;
}