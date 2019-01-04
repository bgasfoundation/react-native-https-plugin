//
//  RNNativeFetch.m
//  medipass
//
//  Created by Paul Wong on 13/10/16.
//  Copyright © 2016 Localz. All rights reserved.
//

#import "RNHttpsPlugin.h"

@interface RNHttpsPluginException : NSException
@end
@implementation RNHttpsPluginException
@end

// private delegate for verifying certs
@interface NSURLSessionSSLPinningDelegate:NSObject <NSURLSessionDelegate>

- (id)initWithTrustCertNames:(NSArray<NSString *> *)trustCertNames;

@property (nonatomic, strong) NSArray<NSString *> *trustCertNames;

@end

@implementation NSURLSessionSSLPinningDelegate

- (id)initWithTrustCertNames:(NSArray<NSString *> *)trustCertNames {
    if (self = [super init]) {
        _trustCertNames = trustCertNames;
    }
    return self;
}

- (NSArray *)pinnedTrustCertificateData {
    NSMutableArray *localTrustCertData = [NSMutableArray array];
    for (NSString* trustCertName in self.trustCertNames) {
        NSString *trustCertPath = [[NSBundle mainBundle] pathForResource:trustCertName ofType:nil];
        if (trustCertPath == nil) {
            @throw [[RNHttpsPluginException alloc]
                initWithName:@"CertificateError"
                reason:@"Can not load certicate given, check it's in the app resources."
                userInfo:nil];
        }
        [localTrustCertData addObject:[NSData dataWithContentsOfFile:trustCertPath]];
    }

    NSMutableArray *pinnedTrustCertificates = [NSMutableArray array];
    for (NSData *trustCertData in localTrustCertData) {
        [pinnedTrustCertificates addObject:(__bridge_transfer id)SecCertificateCreateWithData(NULL, (__bridge CFDataRef)trustCertData)];
    }
  return pinnedTrustCertificates;
}

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler {

    if ([[[challenge protectionSpace] authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];

        // ignore verifying domain name so that the certifcate can authenticate multiple IPs
        NSArray *policies = @[(__bridge_transfer id)SecPolicyCreateSSL(true, nil)];

        SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)policies);
        // setup
        SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)self.pinnedTrustCertificateData);
        SecTrustResultType result;

        // evaluate
        OSStatus errorCode = SecTrustEvaluate(serverTrust, &result);

        BOOL evaluatesAsTrusted = (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed);
        if (errorCode == errSecSuccess && evaluatesAsTrusted) {
            NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        } else {
            completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, NULL);
        }
    } else {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
    }
}

@end

@interface RNHttpsPlugin()

@property (nonatomic, strong) NSURLSessionConfiguration *sessionConfig;

@end

@implementation RNHttpsPlugin
RCT_EXPORT_MODULE();

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        self.sessionConfig.HTTPCookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    }
    return self;
}

+ (BOOL)requiresMainQueueSetup
{
  return true;
}

RCT_EXPORT_METHOD(fetch:(NSString *)url obj:(NSDictionary *)obj callback:(RCTResponseSenderBlock)callback) {
    NSURL *u = [NSURL URLWithString:url];
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:u];

    NSURLSession *session;
    if (obj) {
        if (obj[@"method"]) {
            [request setHTTPMethod:obj[@"method"]];
        }
        if (obj[@"timeout"]) {
          [request setTimeoutInterval:[obj[@"timeout"] intValue] / 1000];
        }
        if (obj[@"headers"] && [obj[@"headers"] isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary *m = [obj[@"headers"] mutableCopy];
            for (NSString *key in [m allKeys]) {
                if (![m[key] isKindOfClass:[NSString class]]) {
                    m[key] = [m[key] stringValue];
                }
            }
            [request setAllHTTPHeaderFields:m];
        }
        if (obj[@"body"]) {
            NSData *data = [obj[@"body"] dataUsingEncoding:NSUTF8StringEncoding];
            [request setHTTPBody:data];
        }
    }
    if (obj && obj[@"sslconfig"] && obj[@"sslconfig"][@"truststore"]) {
        // load truststore
        NSURLSessionSSLPinningDelegate *delegate = [[NSURLSessionSSLPinningDelegate alloc] initWithTrustCertNames:@[obj[@"sslconfig"][@"truststore"]]];
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig delegate:delegate delegateQueue:[NSOperationQueue mainQueue]];
    } else if (obj && obj[@"sslconfig"] && obj[@"sslconfig"][@"certs"]) {
        // load all certs
        NSURLSessionSSLPinningDelegate *delegate = [[NSURLSessionSSLPinningDelegate alloc] initWithTrustCertNames:obj[@"sslconfig"][@"certs"]];
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig delegate:delegate delegateQueue:[NSOperationQueue mainQueue]];
    } else {
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig];
    }

    //implement load keystore.
    //keystore: '*********',
    //storeType: 'PKCS12',
    //storePassword: '*******'

    __block NSURLSessionDataTask *dataTask = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (!error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                NSHTTPURLResponse *httpResp = (NSHTTPURLResponse*) response;
                NSInteger statusCode = httpResp.statusCode;
                NSString *bodyString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                NSString *statusText = [NSHTTPURLResponse localizedStringForStatusCode:httpResp.statusCode];

                NSDictionary *res = @{
                                      @"status": @(statusCode),
                                      @"headers": httpResp.allHeaderFields,
                                      @"bodyString": bodyString,
                                      @"statusText": statusText
                                      };
                callback(@[[NSNull null], res]);
            });
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                callback(@[@{@"message":error.localizedDescription}, [NSNull null]]);
            });
        }
    }];

    [dataTask resume];
}

@end
