//
//  NSString+Encrypt.m
//  EncryptionDemo
//
//  Created by 李晓飞 on 2018/3/29.
//  Copyright © 2018年 xiaofei. All rights reserved.
//

#import "NSString+Encrypt.h"
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonDigest.h>


@implementation NSString (Encrypt)

#pragma mark - 对称加密算法 -- AES
/**
 #import <CommonCrypto/CommonCrypto.h>
 AES主要应用在关键数据和文件的的保密同时又需要解密的情形，其加密密钥和解密密钥相同，根据密钥长度分为128、192和256三种级别，密钥长度越大安全性也就越大，但性能也就越低，根据实际业务的安全要求来决定就好。通常情况，对一些关键数据进行加密的对象都是字符串，加密结果也以字符串进行保存，所以在设计接口的时候参数和返回值均为字符串。（关于关键参数的意义放在代码后讲解。）
 kCCKeySizeAES256           密钥长度，枚举类型，还有128，192 两种
 kCCBlockSizeAES128         块长度，固定值16(字节，128位)，由AES算法内部加密细节决定，不过哪种方式、模式，均为此
 kCCAlgorithmAES            算法名称，不区分128，192还是256。
 kCCOptionPKCS7Padding      填充模式，AES算法内部加密细节决定AES的明文必须为64位的整数倍，如果位数不足，则需要补齐。kCCOptionPKCS7Padding表示，缺几位就补几个几。比如缺少3位，则在明文后补3个3。iOS种只有这一种补齐方式，其它平台方式更多，如kCCOptionPKCS5Padding，kCCOptionZeroPadding。如果要实现一致性，则此处其它平台也要使用kCCOptionPKCS7Padding。
 kCCOptionECBMode           工作模式，电子密码本模式。此模式不需要初始化向量。iOS种只有两种方式，默认是CBC模式，即块加密模式。标准的AES除此外还有其它如CTR,CFB等方式。kCCOptionECBMode模式下多平台的要求不高，推荐使用。CBC模式，要求提供相同的初始化向量，多个平台都要保持一致，工作量加大，安全性更高，适合更高要求的场景使用。
 base64                     一种unicode到asci码的映射，由于明文和密文标准加密前后都可能是汉字或者特殊字符，故为了直观的显示，通常会对明文和密文进行base64编码。
 */
// 加密
- (NSString *)aes256_encrypt:(NSString *)key {
    const char *cstr = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:self.length];
    
    // 对数据进行加密
    char keyPtr[kCCKeySizeAES256 + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding | kCCOptionECBMode, keyPtr, kCCKeySizeAES256, NULL, [data bytes], dataLength, buffer, bufferSize, &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *result = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        // base256
        return [result base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    }else {
        return nil;
    }
}
// 解密
- (NSString *)aes256_decrypt:(NSString *)key {
    NSData *data = [[NSData alloc] initWithBase64EncodedData:[self dataUsingEncoding:NSASCIIStringEncoding] options:NSDataBase64DecodingIgnoreUnknownCharacters];
    // 对数据进行解密
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding | kCCOptionECBMode, keyPtr, kCCKeySizeAES256, NULL, [data bytes], dataLength, buffer, bufferSize, &numBytesDecrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *result = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    }else {
        return nil;
    }
}

#pragma mark - 摘要算法 -- MD5 SHA
// 消息摘要算法MD5 将任意明文（不为空）映射为32位字符串。数字签名和复杂的加密系统中都有使用，单独使用由于撞库原因安全性较低
/**
 * MD5 特点
 * 压缩性：任意长度的数据，算出的MD5值 长度 都是固定的
 * 容易计算：从原数据计算出MD5值很容易
 * 抗修改性：对原数据进行任何改动，哪怕只修改一个字节，所得到的MD5值都有很大的区别
 * 弱抗碰撞：已知原数据和其MD5值，想找到一个具有相同MD5值的数据（即伪造数据）是非常困难的
 * 强抗碰撞：想找到两个不同数据，使他们具有相同的MD5值，是非常困难的
 */
- (NSString *)md5HexDigest {
    const char *cstr = [self cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cstr, (unsigned int)strlen(cstr), result);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    
    for (int i=0; i<CC_MD5_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", result[i]];
    }
    return output;
}


// 安全散列算法SHA 按结果的位数分为256、484、512三种基本方式，根据对结果的要求而选择即可。通过CC_SHA256_DIGEST_LENGTH等枚举类型进行设置
// 每一个公司都有自己的“盐值”，盐值越复杂，越安全
- (NSString *)sha256HexDigest_32BitIsAdd:(BOOL)isAdd {
    NSString *codeStr = self;
    
    if (isAdd) {
        codeStr = [self stringByAppendingString:@"ef9f26f67af16c595a9ac5901107451b3703ce1f677f2568951b393372ed02be"];
    }
    const char *cstr = [codeStr cStringUsingEncoding:NSUTF8StringEncoding];
    
    NSData *data = [NSData dataWithBytes:cstr length:codeStr.length];
    
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    
    CC_SHA256(data.bytes, (unsigned int)data.length, digest);
    
    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    
    return output;
}


@end
