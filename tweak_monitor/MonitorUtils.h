#import "Symbol/RestoreSymbol.h"
#import <Foundation/Foundation.h>

@interface MonitorUtils : NSObject
// 函数声明
+ (void)reportLogWithCategory:(NSString *)category 
                         func:(NSString *)func 
                      content:(id)content 
                   methodDesc:(NSString *)methodDesc;

+ (void)reportFileLog:(NSString *)funcName 
               opType:(NSString *)opType 
             pathInfo:(NSString *)pathInfo;
                        
+ (void)sendLog:(NSDictionary *)data;
@end