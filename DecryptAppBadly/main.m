//
//  main.m
//  DecryptAppBadly
//
//  Created by Zhuowei Zhang on 2021-02-06.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
@import Darwin;
@import MachO;

extern int mremap_encrypted(void* start, size_t len, uint32_t cryptid, uint32_t cputype, uint32_t cpusubtype);

bool DecryptFile(NSString* inputPath, NSString* outputPath) {
    NSFileManager* fileManager = [NSFileManager defaultManager];
    NSError* error;
    NSDictionary<NSFileAttributeKey, id>* srcInfo = [fileManager attributesOfItemAtPath:inputPath error:&error];
    if (error) {
        NSLog(@"%@", error);
        return false;
    }
    size_t fileSize = srcInfo.fileSize;
    int fd = open(inputPath.UTF8String, O_RDONLY);
    if (fd == -1) {
        NSLog(@"open: %s", strerror(errno));
        return false;
    }
    void* ptr = mmap(nil, fileSize, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED) {
        NSLog(@"mmap: %s", strerror(errno));
        return 1;
    }
    // loop through all the mach headers
    struct mach_header_64* mh = (struct mach_header_64*)ptr;
    struct load_command* cmd = (struct load_command*)((uint8_t*)mh + sizeof(struct mach_header_64));
    struct encryption_info_command_64* encryption_info = nil;
    for (unsigned int index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
            case LC_ENCRYPTION_INFO_64:
                encryption_info = (struct encryption_info_command_64*)cmd;
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    if (!encryption_info) {
        NSLog(@"Not encrypted??");
        return false;
    }
    NSLog(@"about to remap");
    int result = mremap_encrypted(ptr + encryption_info->cryptoff, encryption_info->cryptsize, encryption_info->cryptid, mh->cputype, mh->cpusubtype);
    if (result) {
        NSLog(@"mremap_encrypted: %s", strerror(errno));
        return false;
    }
    NSLog(@"remapped");
    NSMutableData* patchedData = [NSMutableData dataWithContentsOfFile:inputPath];
    memcpy(patchedData.mutableBytes + encryption_info->cryptoff, ptr + encryption_info->cryptoff, encryption_info->cryptsize);
    struct encryption_info_command_64* new_encryption_info = (struct encryption_info_command_64*)(patchedData.mutableBytes + (((char*)encryption_info) - (char*)ptr));
    NSLog(@"ptr to new info = %p (off from %p)", new_encryption_info, patchedData.mutableBytes);
    new_encryption_info->cryptid = 0;
    NSLog(@"written!");
    [patchedData writeToFile:outputPath options:0 error:&error];
    if (error) {
        NSLog(@"write data: %@", error);
        return false;
    }
    munmap(ptr, fileSize);
    close(fd);
    return true;
}

bool IsExecutable(NSString* path) {
    FILE* f = fopen(path.UTF8String, "r");
    if (!f) {
        return false;
    }
    uint32_t magic = 0;
    if (fread(&magic, 1, sizeof(magic), f) != sizeof(magic)) {
        fclose(f);
        return false;
    }
    fclose(f);
    if (magic == MH_MAGIC_64) {
        return true;
    }
    return false;
}

bool DecryptApp(NSString* inputPath, NSString* outputPath) {
    NSFileManager* fileManager = [NSFileManager defaultManager];
    NSArray<NSString*>* subpaths = [fileManager subpathsAtPath:inputPath];
    //NSLog(@"subpaths = %@", subpaths);
    for (NSString* path in subpaths) {
        NSString* fullPath = [inputPath stringByAppendingPathComponent:path];
        if (!IsExecutable(fullPath)) {
            continue;
        }
        NSString* fullOutputPath = [outputPath stringByAppendingPathComponent:path];
        NSLog(@"%@ %@", fullPath, fullOutputPath);
        NSString* outputDir = [fullOutputPath stringByDeletingLastPathComponent];
        NSError* error;
        [fileManager createDirectoryAtPath:outputDir withIntermediateDirectories:true attributes:nil error:&error];
        if (error) {
            NSLog(@"Creating dir: %@", error);
            return false;
        }
        if (!DecryptFile(fullPath, fullOutputPath)) {
            return false;
        }
    }
    return true;
}

int main(int argc, char * argv[]) {
    if (argc != 3) {
        NSLog(@"Usage: %s <input> <output>", argv[0]);
        return 1;
    }
    bool success = DecryptApp([NSString stringWithUTF8String:argv[1]],
                               [NSString stringWithUTF8String:argv[2]]);
    return success? 0: 1;
#if 0
    NSString * appDelegateClassName;
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
#endif
}
