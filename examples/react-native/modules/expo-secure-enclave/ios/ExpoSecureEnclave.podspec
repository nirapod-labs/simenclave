# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 SimEnclave Contributors

Pod::Spec.new do |s|
  s.name           = 'ExpoSecureEnclave'
  s.version        = '1.0.0'
  s.summary        = 'Raw Secure Enclave SecKey adapter for the SimEnclave React Native demo'
  s.description    = 'Issues the raw Security-framework calls (SecKeyCreateRandomKey with the ' \
                     'Secure Enclave token, SecKeyCreateSignature, SecItem*) a device app makes, ' \
                     'so SimEnclave hooks them in the Simulator.'
  s.author         = 'SimEnclave Contributors'
  s.homepage       = 'https://github.com/0xnirapod/simenclave'
  s.license        = { :type => 'Apache-2.0' }
  s.platforms      = { :ios => '15.1', :tvos => '15.1' }
  s.source         = { :git => '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule'
  }

  s.source_files = "**/*.{h,m,mm,swift,hpp,cpp}"
end
