#import "MonitorUtils.h"

static NSString *SERVER_URL = @"http://192.168.31.158:8080/api/report_log";

@implementation MonitorUtils


+ (NSString *)getCallStack
{
    RestoreSymbol *symbol = [[RestoreSymbol alloc] init];
    NSArray *symbolInfo = [symbol outputCallStackSymbol];
    // 获取失败直接返回默认值
    if (!symbolInfo || ![symbolInfo isKindOfClass:[NSArray class]]) {
        return @"Unknown Stack";
    }
    NSMutableArray *filteredStack = [NSMutableArray array];
    // 过滤干扰数据关键字
    NSArray *blackList = @[
        @"MonitorTweak.dylib",
        @"libdispatch.dylib",
        @"TweakEx.dylib"
    ];
    for (id item in symbolInfo) 
    {
        // 排除Null 对象或 nil
        if (item == nil || [item isKindOfClass:[NSNull class]]) {
            continue;
        }
        // 确保是字符串类型
        if (![item isKindOfClass:[NSString class]]) {
            continue;
        }
        NSString *line = (NSString *)item;
        // 排除内容为 "null" 的字符串或长度为 0 的行
        if ([line.lowercaseString isEqualToString:@"null"] || line.length == 0) {
            continue;
        }
        // 关键字过滤
        BOOL isBlacklisted = NO;
        for (NSString *keyword in blackList) {
            if ([line rangeOfString:keyword options:NSCaseInsensitiveSearch].location != NSNotFound) {
                isBlacklisted = YES;
                break;
            }
        }
        // 清洗存入数组
        if (!isBlacklisted) {
            NSString *cleanLine = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (cleanLine.length > 0) {
                [filteredStack addObject:cleanLine];
            }
        }
    } 
    // 将结果并返回
    if (filteredStack.count > 0) {
        return [filteredStack componentsJoinedByString:@"\n"];
    }
    return @"Unknown Stack"; // 默认字符串
}

+ (void)loadConfig {
    NSString *configPath = @"/var/mobile/monitor_config.json";
    if ([[NSFileManager defaultManager] fileExistsAtPath:configPath]) {
        NSData *data = [NSData dataWithContentsOfFile:configPath];
        if (data) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (json && json[@"server_url"]) {
                SERVER_URL = json[@"server_url"];
                NSLog(@"[MonitorTweak] Updated server url: %@", SERVER_URL);
            }
        }
    }
}

+ (void)sendLog:(NSDictionary *)data {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ [self loadConfig]; });

    NSURL *url = [NSURL URLWithString:SERVER_URL];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [req setHTTPMethod:@"POST"];
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    
    NSError *error;
    NSData *body = [NSJSONSerialization dataWithJSONObject:data options:0 error:&error];
    if (!body) return;
    [req setHTTPBody:body];
    
    NSURLSessionConfiguration *conf = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:conf];
    [[session dataTaskWithRequest:req] resume];
}

+ (void)reportLogWithCategory:(NSString *)category func:(NSString *)func content:(id)content methodDesc:(NSString *)methodDesc {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"type"] = @"info";
    dict[@"category"] = category;
    
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy/MM/dd, HH:mm:ss"; 
    dict[@"timestamp"] = [formatter stringFromDate:[NSDate date]];
    
    dict[@"func"] = func;
    dict[@"method"] = methodDesc;
    dict[@"content"] = [NSString stringWithFormat:@"%@", content ?: @"nil"];
    
    // 获取函数调用堆栈
    dict[@"stack"] = [self getCallStack] ?: @""; 
    
    [self sendLog:dict];
}

+ (void)reportFileLog:(NSString *)funcName opType:(NSString *)opType pathInfo:(NSString *)pathInfo {

    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"type"] = @"file";
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy/MM/dd, HH:mm:ss"; 
    dict[@"timestamp"] = [formatter stringFromDate:[NSDate date]];
    dict[@"func"] = funcName;
    dict[@"op"] = opType;
    dict[@"method"] = pathInfo;
    dict[@"stack"] = [self getCallStack] ?: @""; 

    [self sendLog:dict];

}

@end
