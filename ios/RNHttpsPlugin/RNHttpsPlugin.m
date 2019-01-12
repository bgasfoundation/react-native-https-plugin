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

- (id)initWithCertInfo:(NSString*)trustCertName credCertName:(NSString*)credCertName credCertPassword:(NSString*)credCertPassword;

@property (nonatomic, strong) NSString *trustCertName;
@property (nonatomic, strong) NSString *credCertName;
@property (nonatomic, strong) NSString *credCertPassword;

@end

@implementation NSURLSessionSSLPinningDelegate

- (id)initWithCertInfo:(NSString*)trustCertName credCertName:(NSString*)credCertName credCertPassword:(NSString*)credCertPassword {
    if (self = [super init]) {
      _trustCertName = trustCertName;
      _credCertName = credCertName;
      _credCertPassword = credCertPassword;
    }
    return self;
}

- (NSArray *)pinnedTrustCertificateData {
    NSMutableArray *localCertData = [NSMutableArray array];

    NSString *certPath = [[NSBundle mainBundle] pathForResource:self.trustCertName ofType:nil];
    if (certPath == nil) {
        @throw [[RNHttpsPluginException alloc]
            initWithName:@"CertificateError"
            reason:@"Can not load certicate given, check it's in the app resources."
            userInfo:nil];
    }
    [localCertData addObject:[NSData dataWithContentsOfFile:certPath]];

    NSMutableArray *pinnedCertificates = [NSMutableArray array];
    for (NSData *certData in localCertData) {
        [pinnedCertificates addObject:(__bridge_transfer id)SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData)];
    }
    return pinnedCertificates;
}

- (SecIdentityRef)pinnedCredCertificateData {
  SecIdentityRef clientCertificate = NULL;

    NSString *certPath = [[NSBundle mainBundle] pathForResource:self.credCertName ofType:nil];
    if (certPath == nil) {
      @throw [[RNHttpsPluginException alloc]
              initWithName:@"CertificateError"
              reason:@"Can not load certicate given, check it's in the app resources."
              userInfo:nil];
    }

    NSData *pkcs12Data = [[NSData alloc] initWithContentsOfFile:certPath];
    CFDataRef inPKCS12Data = (__bridge CFDataRef)pkcs12Data;
    CFStringRef password = (__bridge CFStringRef)(self.credCertPassword);
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };
    CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = NULL;

    OSStatus err = SecPKCS12Import(inPKCS12Data, optionsDictionary, &items);

    CFRelease(optionsDictionary);

    if (err == errSecSuccess && CFArrayGetCount(items) > 0) {
      CFDictionaryRef pkcsDict = CFArrayGetValueAtIndex(items, 0);

      SecTrustRef trust = (SecTrustRef)CFDictionaryGetValue(pkcsDict, kSecImportItemTrust);

      if (trust != NULL) {
        clientCertificate = (SecIdentityRef)CFDictionaryGetValue(pkcsDict, kSecImportItemIdentity);
        CFRetain(clientCertificate);
      }
    }

    if (items) {
      CFRelease(items);
    }
    return clientCertificate;
}

- (NSURLCredential *)provideClientCertificate {
  SecIdentityRef identity = [self pinnedCredCertificateData];

  if (!identity) {
    return nil;
  }

  SecCertificateRef certificate = NULL;
  SecIdentityCopyCertificate (identity, &certificate);
  const void *certs[] = {certificate};
  CFArrayRef certArray = CFArrayCreate(kCFAllocatorDefault, certs, 1, NULL);
  NSURLCredential *credential = [NSURLCredential credentialWithIdentity:identity certificates:(__bridge NSArray *)certArray persistence:NSURLCredentialPersistencePermanent];
  CFRelease(certArray);

  return credential;
}

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler {

    if ([[[challenge protectionSpace] authenticationMethod] isEqualToString:NSURLAuthenticationMethodClientCertificate]) {
      NSURLCredential *credential = [self provideClientCertificate];
      completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    } else if ([[[challenge protectionSpace] authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust]) {
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
    if (obj && obj[@"sslconfig"]) {
      if (!obj[@"sslconfig"][@"truststore"] || !obj[@"sslconfig"][@"keystore"]) {
         session = [NSURLSession sessionWithConfiguration:self.sessionConfig];
      } else {
        // load trust and/or credential certificate
        NSURLSessionSSLPinningDelegate *delegate = [[NSURLSessionSSLPinningDelegate alloc] initWithCertInfo:obj[@"sslconfig"][@"truststore"]
                           credCertName:obj[@"sslconfig"][@"keystore"]
                           credCertPassword:obj[@"sslconfig"][@"storePassword"]];

        session = [NSURLSession sessionWithConfiguration:self.sessionConfig delegate:delegate delegateQueue:[NSOperationQueue mainQueue]];
      }
    } else {
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig];
    }

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
