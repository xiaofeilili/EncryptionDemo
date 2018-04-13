//
//  ViewController.m
//  EncryptionDemo
//
//  Created by 李晓飞 on 2018/3/29.
//  Copyright © 2018年 xiaofei. All rights reserved.
//

#import "ViewController.h"
#import "NSString+Encrypt.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSString *str = @"987654321";
    NSString *key = @"12345678901234561234567890123456";
    NSString *enStr = [str aes256_encrypt:key];
    NSString *deStr = [enStr aes256_decrypt:key];
    
    
//    NSString *plainText = @"O57W05XN-EQ2HCD3V-LPJJ4H0N-ZFO2WHRR-9HAVXR2J-YTYXDQPK-SJXZXALI-FAIHJV";
//    NSString *key = @"12345678901234561234567890123456";
//    NSString *enStr = [plainText aes256_encrypt:key];
    
    NSLog(@"%@,\n %@", enStr, deStr);
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
