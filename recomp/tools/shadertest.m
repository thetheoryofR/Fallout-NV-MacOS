// Offline shader-translator test: every shader in every FNV shader package is translated to MSL and
// compiled by the Metal compiler (fast math off). Reports pass/fail counts and the first errors.
//   shadertest <Data/Shaders dir> [dump_dir]
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include "../host/sm2msl.h"

int main(int argc, char **argv) {
    @autoreleasepool {
        id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
        MTLCompileOptions *opt = [MTLCompileOptions new];
        opt.mathMode = MTLMathModeSafe;
        NSString *dir = [NSString stringWithUTF8String:argv[1]];
        const char *dump = argc > 2 ? argv[2] : NULL;
        NSMutableSet *seen = [NSMutableSet set];
        int total = 0, unique = 0, tfail = 0, cfail = 0, shown = 0;
        NSMutableDictionary *reasons = [NSMutableDictionary dictionary];
        for (NSString *f in [[[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil] sortedArrayUsingSelector:@selector(compare:)]) {
            if (![f hasPrefix:@"shaderpackage"] || ![f hasSuffix:@".sdp"]) continue;
            NSData *d = [NSData dataWithContentsOfFile:[dir stringByAppendingPathComponent:f]];
            const uint8_t *b = d.bytes; uint32_t n; memcpy(&n, b + 4, 4); size_t o = 12;
            for (uint32_t i = 0; i < n; i++) {
                char name[257] = {0}; memcpy(name, b + o, 256); for (int k = 0; k < 256; k++) if ((uint8_t)name[k] == 0xfd) name[k] = 0;
                uint32_t len; memcpy(&len, b + o + 256, 4);
                NSData *code = [NSData dataWithBytes:b + o + 260 length:len];
                o += 260 + len; total++;
                if ([seen containsObject:code]) continue;
                [seen addObject:code]; unique++;
                char err[512] = ""; SMInfo info; memset(&info, 0, sizeof info);
                char *msl = sm_translate(code.bytes, len / 4, &info, NULL, 0, err, sizeof err);
                if (!msl) {
                    tfail++;
                    NSString *k = [NSString stringWithFormat:@"translate: %s", err];
                    reasons[k] = @([reasons[k] intValue] + 1);
                    continue;
                }
                NSError *e = nil;
                id<MTLLibrary> lib = [dev newLibraryWithSource:[NSString stringWithUTF8String:msl] options:opt error:&e];
                if (!lib) {
                    cfail++;
                    NSString *msg = e.localizedDescription;
                    NSRange r = [msg rangeOfString:@"error: "];
                    NSString *k = r.location != NSNotFound ? [msg substringFromIndex:r.location] : msg;
                    k = [[k componentsSeparatedByString:@"\n"] firstObject];
                    if (k.length > 110) k = [k substringToIndex:110];
                    reasons[k] = @([reasons[k] intValue] + 1);
                    if (dump && shown < 8) {
                        char path[1024]; snprintf(path, sizeof path, "%s/fail_%03d_%s.metal", dump, shown, name);
                        FILE *fp = fopen(path, "w"); if (fp) { fputs(msl, fp); fclose(fp); }
                        shown++;
                    }
                }
                free(msl);
            }
        }
        printf("shaders %d, unique %d, translate-fail %d, metal-compile-fail %d, OK %d\n", total, unique, tfail, cfail, unique - tfail - cfail);
        NSArray *keys = [reasons keysSortedByValueUsingComparator:^NSComparisonResult(id a, id b2) { return [b2 compare:a]; }];
        for (NSUInteger i = 0; i < keys.count && i < 12; i++) printf("  %5d  %s\n", [reasons[keys[i]] intValue], [keys[i] UTF8String]);
    }
    return 0;
}
