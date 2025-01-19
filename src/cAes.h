#ifndef HEAD_cAes_H
#define HEAD_cAes_H
#include <stdio.h>
typedef unsigned char uchar;//为了简便敲代码，将unsigned char改名为uchar
/// @brief 加密类型，AesInit()函数所需的枚举参数。
typedef enum {

	AES128 = 16,/*AES128加密模式；128bit=16Byte*/
	AES192 = 24,/*AES192加密模式；192bit=24Byte*/
	AES256 = 32,/*AES256加密模式；256bit=32Byte*/
} AESType_t;

/**
 * @brief 此结构体为加密解密时所必需的参数，只需声明，通过cAesLib_setKey()函数完成初始化。
*/
typedef struct {
	uchar Nk;/*密钥行数，Nk=4、6、8,分别对应AES128、AES192、AES256*/
	uchar Nr;/*加密轮数，Nr=10、12、14,分别对应AES128、AES192、AES256*/
	uchar aesType;/*加密类型，aesType=128、192、256,分别对应AES128、AES192、AES256*/
	//AES拓展密匙, 空间大小 AES128:4*Nb*(10+1):4*Nb*(12+1)、AES256:4*Nb*(14+1)=240
	uchar expandKey[240];//用户不需要填充，[4*Nb*(Nr+1)]、这里按最大的AES256进行初始化,240个字节
}AesKeyBox;

#if __cplusplus
extern "C" {
#endif // __cplusplus


	/**
	 * @brief GF(2^8)上的乘2操作
	 * @param val 被乘数
	 * @return 积
	*/
	unsigned  char Xtime_2(uchar val);

	/**
	 * @brief 将一个4字节的字节数组循环左移一个字节。
	 * 例如：unsigned char w[4]={1，2，3，4};
	 *		RotWord(w);
	 *		函数执行后: w={2,3,4,1}
	 * @param pword 4字节变量的地址。
	*/
	void RotWord(uchar* pword);
	void SubWord(uchar* pword);
	void XorWord(int* data, int* rcon);
	void AddRoundKey(uchar* state, const uchar* expendkey);
	/**
	 * @brief S盒字节替换。
	 * @param state 输入输出参数，16个字节的字节数组，必须保证该数组有16字节的可操作内存。
	 * @return state 将原state数组修改后返回。
	*/
	void SubBytes(uchar* state);

	/**
	 * @brief 行位移，对state矩阵进行行位移操作。
	 * @param state 输入输出参数，16个字节的字节数组，必须保证该数组有16字节的可操作内存。
	 * @return state 将原state数组修改后返回。
	*/
	void ShiftRows(uchar* state);

	/**
	 * @brief 通过计算的方法进行列混合,比查表的方法效率低。
	 * @param state 输入输出参数，16个字节的字节数组，必须保证该数组有16字节的可操作内存。
	 * @return state 将原state数组修改后返回。
	*/
	void MixColumns(uchar* state);

	/**
	 * @brief 通过查表的方法进行列混合，比MixColumns函数效率高，时间复杂度约为MixColumns函数的1/5。
	 * @param state 输入输出参数，16个字节的字节数组，必须保证该数组有16字节的可操作内存。
	 * @return state 将原state数组修改后返回。
	*/
	void MixColumns_byTable(uchar* state);

	/**
	 * @brief 解密字节替换，直接操作state指针下的内存。
	 * @param state 数据地址，必须保证该地址下的数据可操作，即不能被const修饰。
	*/
	void InvSubBytes(uchar* state);

	/**
	 * @brief 解密行位移，对state矩阵进行行位移操作。
	 * @param state 输入输出参数，16个字节的字节数组，必须保证该数组有16字节的可操作内存。
	 * @return state 将原state数组修改后返回。
	*/
	void InvShiftRows(uchar* state);

	/**
	 * @brief 通过计算的方法进行解密列混合,比查表的方法效率低。
	 * @param state 输入输出参数，16个字节的字节数组，必须保证该数组有16字节的可操作内存。
	 * @return state 将原state数组修改后返回。
	*/
	void InvMixColumns(uchar* state);
	/**
 * @brief 通过查表的方法进行解密列混合，比InvMixColumns函数效率高，时间复杂度约为InvMixColumns函数的1/5。
 * @param state 输入输出参数，16个字节的字节数组，必须保证该数组有16字节的可操作内存。
 * @return state 将原state数组修改后返回。
*/
	void InvMixColumns_byTable(uchar* state);


	/**
	 * @brief AesKeyBox 的构造函数，加密解密之前，必须调用该函数进行初始化AesKeyBox对象。
	 * @param KeyBox AesKeyBox的对象。
	 * @param CipherKey 密钥字节数组。依据
	 * @param aestype 加密类型,值为：AES128、	AES192、AES256中的一个。
	*/
	void AesInit(AesKeyBox* KeyBox, const uchar* CipherKey, AESType_t aestype);

	/**
	 * @brief Aes加密，将data指针下的前16个字节数据加密为密文。
	 * @param KeyBox 密钥盒对象，用于存储加密解密所需的参数，使用前必须使用构造函数AesInit()函数进行初始化。
	 * @param data 输入输出参数，为要加密数据的地址。该地址下必须含有16个字节可操作的内存空间。
	*/
	void AesBlockCipher(AesKeyBox* KeyBox, uchar* data);

	/**
	 * @brief Aes加密低效版本：通过计算进行列混合的方式
	*/
	void AesBlockCipher_s(AesKeyBox* KeyBox, uchar* data);

	/**
	 * @brief Aes解密，将data指针下的前16个字节数据加密为密文。
	 * @param KeyBox 密钥盒对象，用于存储加密解密所需的参数，使用前必须使用构造函数AesInit()函数进行初始化。
	 * @param data 输入输出参数，为要解密数据的地址。该地址下必须含有16个字节可操作的内存空间。
	*/
	void AesInvBlockCipher(AesKeyBox* KeyBox, uchar* data);

	/**
 * @brief Aes解密低效版本：通过计算进行列混合的方式
*/
	void AesInvBlockCipher_s(AesKeyBox* KeyBox, uchar* data);



#if __cplusplus
}
#endif // __cplusplus
#endif // !HEAD_cAes_H

