#ifndef HEAD_cAes_H
#define HEAD_cAes_H
#include <stdio.h>
typedef unsigned char uchar;//Ϊ�˼���ô��룬��unsigned char����Ϊuchar
/// @brief �������ͣ�AesInit()���������ö�ٲ�����
typedef enum {

	AES128 = 16,/*AES128����ģʽ��128bit=16Byte*/
	AES192 = 24,/*AES192����ģʽ��192bit=24Byte*/
	AES256 = 32,/*AES256����ģʽ��256bit=32Byte*/
} AESType_t;

/**
 * @brief �˽ṹ��Ϊ���ܽ���ʱ������Ĳ�����ֻ��������ͨ��cAesLib_setKey()������ɳ�ʼ����
*/
typedef struct {
	uchar Nk;/*��Կ������Nk=4��6��8,�ֱ��ӦAES128��AES192��AES256*/
	uchar Nr;/*����������Nr=10��12��14,�ֱ��ӦAES128��AES192��AES256*/
	uchar aesType;/*�������ͣ�aesType=128��192��256,�ֱ��ӦAES128��AES192��AES256*/
	//AES��չ�ܳ�, �ռ��С AES128:4*Nb*(10+1):4*Nb*(12+1)��AES256:4*Nb*(14+1)=240
	uchar expandKey[240];//�û�����Ҫ��䣬[4*Nb*(Nr+1)]�����ﰴ����AES256���г�ʼ��,240���ֽ�
}AesKeyBox;

#if __cplusplus
extern "C" {
#endif // __cplusplus


	/**
	 * @brief GF(2^8)�ϵĳ�2����
	 * @param val ������
	 * @return ��
	*/
	unsigned  char Xtime_2(uchar val);

	/**
	 * @brief ��һ��4�ֽڵ��ֽ�����ѭ������һ���ֽڡ�
	 * ���磺unsigned char w[4]={1��2��3��4};
	 *		RotWord(w);
	 *		����ִ�к�: w={2,3,4,1}
	 * @param pword 4�ֽڱ����ĵ�ַ��
	*/
	void RotWord(uchar* pword);
	void SubWord(uchar* pword);
	void XorWord(int* data, int* rcon);
	void AddRoundKey(uchar* state, const uchar* expendkey);
	/**
	 * @brief S���ֽ��滻��
	 * @param state �������������16���ֽڵ��ֽ����飬���뱣֤��������16�ֽڵĿɲ����ڴ档
	 * @return state ��ԭstate�����޸ĺ󷵻ء�
	*/
	void SubBytes(uchar* state);

	/**
	 * @brief ��λ�ƣ���state���������λ�Ʋ�����
	 * @param state �������������16���ֽڵ��ֽ����飬���뱣֤��������16�ֽڵĿɲ����ڴ档
	 * @return state ��ԭstate�����޸ĺ󷵻ء�
	*/
	void ShiftRows(uchar* state);

	/**
	 * @brief ͨ������ķ��������л��,�Ȳ��ķ���Ч�ʵ͡�
	 * @param state �������������16���ֽڵ��ֽ����飬���뱣֤��������16�ֽڵĿɲ����ڴ档
	 * @return state ��ԭstate�����޸ĺ󷵻ء�
	*/
	void MixColumns(uchar* state);

	/**
	 * @brief ͨ�����ķ��������л�ϣ���MixColumns����Ч�ʸߣ�ʱ�临�Ӷ�ԼΪMixColumns������1/5��
	 * @param state �������������16���ֽڵ��ֽ����飬���뱣֤��������16�ֽڵĿɲ����ڴ档
	 * @return state ��ԭstate�����޸ĺ󷵻ء�
	*/
	void MixColumns_byTable(uchar* state);

	/**
	 * @brief �����ֽ��滻��ֱ�Ӳ���stateָ���µ��ڴ档
	 * @param state ���ݵ�ַ�����뱣֤�õ�ַ�µ����ݿɲ����������ܱ�const���Ρ�
	*/
	void InvSubBytes(uchar* state);

	/**
	 * @brief ������λ�ƣ���state���������λ�Ʋ�����
	 * @param state �������������16���ֽڵ��ֽ����飬���뱣֤��������16�ֽڵĿɲ����ڴ档
	 * @return state ��ԭstate�����޸ĺ󷵻ء�
	*/
	void InvShiftRows(uchar* state);

	/**
	 * @brief ͨ������ķ������н����л��,�Ȳ��ķ���Ч�ʵ͡�
	 * @param state �������������16���ֽڵ��ֽ����飬���뱣֤��������16�ֽڵĿɲ����ڴ档
	 * @return state ��ԭstate�����޸ĺ󷵻ء�
	*/
	void InvMixColumns(uchar* state);
	/**
 * @brief ͨ�����ķ������н����л�ϣ���InvMixColumns����Ч�ʸߣ�ʱ�临�Ӷ�ԼΪInvMixColumns������1/5��
 * @param state �������������16���ֽڵ��ֽ����飬���뱣֤��������16�ֽڵĿɲ����ڴ档
 * @return state ��ԭstate�����޸ĺ󷵻ء�
*/
	void InvMixColumns_byTable(uchar* state);


	/**
	 * @brief AesKeyBox �Ĺ��캯�������ܽ���֮ǰ��������øú������г�ʼ��AesKeyBox����
	 * @param KeyBox AesKeyBox�Ķ���
	 * @param CipherKey ��Կ�ֽ����顣����
	 * @param aestype ��������,ֵΪ��AES128��	AES192��AES256�е�һ����
	*/
	void AesInit(AesKeyBox* KeyBox, const uchar* CipherKey, AESType_t aestype);

	/**
	 * @brief Aes���ܣ���dataָ���µ�ǰ16���ֽ����ݼ���Ϊ���ġ�
	 * @param KeyBox ��Կ�ж������ڴ洢���ܽ�������Ĳ�����ʹ��ǰ����ʹ�ù��캯��AesInit()�������г�ʼ����
	 * @param data �������������ΪҪ�������ݵĵ�ַ���õ�ַ�±��뺬��16���ֽڿɲ������ڴ�ռ䡣
	*/
	void AesBlockCipher(AesKeyBox* KeyBox, uchar* data);

	/**
	 * @brief Aes���ܵ�Ч�汾��ͨ����������л�ϵķ�ʽ
	*/
	void AesBlockCipher_s(AesKeyBox* KeyBox, uchar* data);

	/**
	 * @brief Aes���ܣ���dataָ���µ�ǰ16���ֽ����ݼ���Ϊ���ġ�
	 * @param KeyBox ��Կ�ж������ڴ洢���ܽ�������Ĳ�����ʹ��ǰ����ʹ�ù��캯��AesInit()�������г�ʼ����
	 * @param data �������������ΪҪ�������ݵĵ�ַ���õ�ַ�±��뺬��16���ֽڿɲ������ڴ�ռ䡣
	*/
	void AesInvBlockCipher(AesKeyBox* KeyBox, uchar* data);

	/**
 * @brief Aes���ܵ�Ч�汾��ͨ����������л�ϵķ�ʽ
*/
	void AesInvBlockCipher_s(AesKeyBox* KeyBox, uchar* data);



#if __cplusplus
}
#endif // __cplusplus
#endif // !HEAD_cAes_H

