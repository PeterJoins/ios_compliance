#import "MonitorUtils.h"
#import <Foundation/Foundation.h>

// =======================================================
// 监控 NSFileHandle
// =======================================================
%hook NSFileHandle

+ (id)fileHandleForReadingAtPath:(NSString *)path {
    if (path) { 
        [MonitorUtils reportFileLog:@"[NSFileHandle fileHandleForReadingAtPath]" 
                             opType:@"读取" 
                           pathInfo:path];
    }
    return %orig; 
}

%end

// =======================================================
// 监控 NSFileManager
// =======================================================
%hook NSFileManager

- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr {
    if (path) { 
        [MonitorUtils reportFileLog:@"[NSFileManager createFileAtPath]" 
                             opType:@"创建" 
                           pathInfo:path];
    }
    return %orig;
}

- (BOOL)copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError **)error {
    if (srcPath && dstPath) { 
        NSString *displayPath = [NSString stringWithFormat:@"%@ \n➡️ %@", srcPath, dstPath];
        [MonitorUtils reportFileLog:@"[NSFileManager copyItemAtPath]"
                             opType:@"复制"
                           pathInfo:displayPath]; // 修正：变量名大小写
    }
    return %orig;
}

- (BOOL)removeItemAtPath:(NSString *)path error:(NSError **)error {
    if (path) { 
        [MonitorUtils reportFileLog:@"[NSFileManager removeItemAtPath]"
                             opType:@"删除" 
                           pathInfo:path];
    }
    return %orig;
}

%end

// =======================================================
// 监控 Plist 写入
// =======================================================
%hook NSDictionary

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if (path) { 
        [MonitorUtils reportFileLog:@"[NSDictionary writeToFile]" 
                             opType:@"写入Plist" 
                           pathInfo:path];
    }
    return %orig;
}

%end