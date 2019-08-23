require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "RNHttpsPlugin"
  s.version      = package["version"]
  s.summary      = "Callback and promise based HTTP client that supports SSL pinning for React Native"
  s.homepage     = "https://github.com/wallchainfoundation/react-native-https-plugin"
  s.license      = "MIT"
  s.author       = "oncecrossover@gmail.com"
  s.platform     = :ios, "8.0"
  s.source       = { :git => "https://github.com/wallchainfoundation/react-native-https-plugin.git", :tag => "#{s.version}" }

  s.source_files  = "ios/**/*.{h,m}"

  s.dependency "React"
end
