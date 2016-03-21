//
//  ViewController.m
//  encryptDemo
//
//  Created by 潘 思浩 on 13-7-22.
//  Copyright (c) 2013年 com.miaomiaobase. All rights reserved.
//

#import "ViewController.h"
#import <CommonCrypto/CommonDigest.h> 

#define kYan @"!*h^Tuyb123%^^#*&^^%%^^&&&s)%$hd"


@interface ViewController (){
    NSString *resultString;
}

- (NSString *)getMd5_32Bit_String:(NSString *)srcString;
- (NSString *)getMd5_16Bit_String:(NSString *)srcString;
@end

@implementation ViewController
@synthesize entryptTypeLabel;

@synthesize introLabel1;
@synthesize introLabel2;
@synthesize introLabel3;
@synthesize introLabel4;
@synthesize resultLabel1;
@synthesize resultLabel2;
@synthesize resultLabel3;
@synthesize resultLabel4;

@synthesize srcStringTextField;

- (void)viewDidLoad
{
    [super viewDidLoad];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}



- (IBAction)commonMd5BtnPressed:(id)sender {
    [entryptTypeLabel setText:@"常规md5加密"];
    
    [introLabel1 setText:@"32位小写"];
    [resultLabel1 setText:[self getMd5_32Bit_String:srcStringTextField.text]];
   
    
    //只需将得到的加密字串转化成大写即可
    [introLabel2 setText:@"32位大写"];
    [resultLabel2 setText:[[self getMd5_32Bit_String:srcStringTextField.text] uppercaseString]];
    
    [introLabel3 setText:@"16位小写"];
    [resultLabel3 setText:[self getMd5_16Bit_String:srcStringTextField.text]];
    
    [introLabel4 setText:@"16位大写"];
    [resultLabel4 setText:[[self getMd5_16Bit_String:srcStringTextField.text] uppercaseString]];
    
}





- (IBAction)secondaryMd5BtnPressed:(id)sender {
    //实际上就是做两次常规转化
    [entryptTypeLabel setText:@"二次md5加密"];
    
    [introLabel1 setText:@"32位小写"];
    NSString *s =[self getMd5_32Bit_String:[self getMd5_32Bit_String:srcStringTextField.text]];
        NSLog(@"%@ ",s);
    [resultLabel1 setText:s];
    
    
    //只需将得到的加密字串转化成大写即可
    [introLabel2 setText:@"32位大写"];
    [resultLabel2 setText:[[self getMd5_32Bit_String:[[self getMd5_32Bit_String:srcStringTextField.text] uppercaseString]]uppercaseString]];
    
    [introLabel3 setText:@"16位小写"];
    [resultLabel3 setText:[self getMd5_16Bit_String:[self getMd5_16Bit_String:srcStringTextField.text]]];
    
    [introLabel4 setText:@"16位大写"];
    [resultLabel4 setText:[[self getMd5_16Bit_String:[[self getMd5_16Bit_String:srcStringTextField.text] uppercaseString]] uppercaseString]];
}

//sha加密
- (IBAction)shaBtnPressed:(id)sender{
    [entryptTypeLabel setText:@"sha安全哈希加密"];
    
    [introLabel1 setText:@"sha1加密"];
    [resultLabel1 setText:[self getSha1String:srcStringTextField.text]];
    
    [introLabel2 setText:@"sha256加密"];
    [resultLabel2 setText:[self getSha256String:srcStringTextField.text]];
    
    [introLabel3 setText:@"sha384加密"];
    [resultLabel3 setText:[self getSha384String:srcStringTextField.text]];
    
    [introLabel4 setText:@"sha512加密"];
    [resultLabel4 setText:[self getSha512String:srcStringTextField.text]];
    
}

- (IBAction)bgTap:(id)sender {
    [self.srcStringTextField resignFirstResponder];
}

//16位MD5加密方式
- (NSString *)getMd5_16Bit_String:(NSString *)srcString{
    //提取32位MD5散列的中间16位
    NSString *md5_32Bit_String=[self getMd5_32Bit_String:srcString];
    NSString *result = [[md5_32Bit_String substringToIndex:24] substringFromIndex:8];//即9～25位
 
    return result;
}


/*1.简单说明
 
 MD5:全称是Message Digest Algorithm 5，译为“消息摘要算法第5版”
 
 效果：对输入信息生成唯一的128位散列值（32个字符）
 
 2.MD5的特点
 
 （1）输入两个不同的明文不会得到相同的输出值
 
 （2）根据输出值，不能得到原始的明文，即其过程不可逆
 
 3.MD5的应用
 
 由于MD5加密算法具有较好的安全性，而且免费，因此该加密算法被广泛使用
 
 主要运用在数字签名、文件完整性验证以及口令加密等方面
 
 4.MD5破解
 
 MD5解密网站：http://www.cmd5.com
 
 20151219100434754.png (820×377)
 
 5.MD5改进
 
 现在的MD5已不再是绝对安全，对此，可以对MD5稍作改进，以增加解密的难度
 
 加盐（Salt）：在明文的固定位置插入随机串，然后再进行MD5
 
 先加密，后乱序：先对明文进行MD5，然后对加密得到的MD5串的字符进行乱序
 
 总之宗旨就是：黑客就算攻破了数据库，也无法解密出正确的明文*/


//32位MD5加密方式
- (NSString *)getMd5_32Bit_String:(NSString *)srcString{
    
    NSLog(@"加密前 %@ ", srcString);
    srcString = [NSString stringWithFormat:@"%@%@",srcString,kYan ];//加盐
    
    const char *cStr = [srcString UTF8String];//转换成utf-8
    
    //开辟一个16字节（128位：md5加密出来就是128位/bit
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    /*
     extern unsigned char *CC_MD5(const void *data, CC_LONG len, unsigned char *md)
     官方封装好的加密方法
     把cStr字符串转换成了32位的16进制数列（这个过程不可逆转） 存储到了result这个空间中*/

    CC_MD5( cStr, strlen(cStr), digest );

    NSMutableString *result = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];//32
    
    /*
     x表示十六进制，%02X  意思是不足两位将用0补齐，如果多余两位则不影响
     NSLog("%02X", 0x888);  //888
     NSLog("%02X", 0x4); //04*/
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [result appendFormat:@"%02x", digest[i]];
    
    NSLog(@" 常规加密 %@ ", result);
    
    return result;
}




//sha1加密方式
- (NSString *)getSha1String:(NSString *)srcString{
    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, data.length, digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    
    return result;
}

//sha256加密方式
- (NSString *)getSha256String:(NSString *)srcString {
    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, data.length, digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    
    return result;
}

//sha384加密方式
- (NSString *)getSha384String:(NSString *)srcString {
    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    
    uint8_t digest[CC_SHA384_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, data.length, digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA384_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA384_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    
    return result;
}

//sha512加密方式
- (NSString*) getSha512String:(NSString*)srcString {
    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    uint8_t digest[CC_SHA512_DIGEST_LENGTH];
    
    CC_SHA512(data.bytes, data.length, digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++)
        [result appendFormat:@"%02x", digest[i]];
    return result;
}




@end