#ifndef HEAD_cAesInterFace_H
#define HEAD_cAesInterFace_H
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
#endif // !HEAD_cAesInterFace_H
