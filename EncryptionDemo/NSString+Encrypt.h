//
//  NSString+Encrypt.h
//  EncryptionDemo
//
//  Created by 李晓飞 on 2018/3/29.
//  Copyright © 2018年 xiaofei. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (Encrypt)
#pragma mark - 对称加密算法
// 加密
- (NSString *)aes256_encrypt:(NSString *)key;
// 解密
- (NSString *)aes256_decrypt:(NSString *)key;
#pragma mark - MD5
- (NSString *)md5HexDigest;
/**
 * SHA加密
 * @param isAdd  是否加盐
 */
- (NSString *)sha256HexDigest_32BitIsAdd:(BOOL)isAdd;

@end
