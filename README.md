# Biometry Service

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->

[![All Contributors](https://img.shields.io/badge/all_contributors-5-orange.svg?style=flat-square)](#contributors-)

<!-- ALL-CONTRIBUTORS-BADGE:END -->

This library offers a simple contract to use the biometry across Android, IOS and UWP.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Getting Started

Install the latest version of BiometryService Nuger "Add Nuget Reference"
A small sample is available as a playground.

## Features

The biometryService Interface 'IBiometryService' Implement the following method :

- GetGapabilites
- ValidateIdentity
- Encryt
- Decrypt

As of now, this is the list of features available per platform.


| Feature          | IOS | Android | UWP  |
| ------------------ | ----- | --------- | ------ |
| GetCapability    | x   | x       | x    |
| ValidateIdentity | x   | x       | Mock |
| Encrypt          | x   | x       | Mock |
| Decrypt          | x   | x       | Mock |

### instantiation

- IOS

An example of instantiation as follow with the fallback to the pin code with some text descriptions to display for the user.

```
            var options = new BiometryOptions();
            options.LocalizedReasonBodyText = "REASON THAT APP WANTS TO USE BIOMETRY :)";
            options.LocalizedFallbackButtonText = "FALLBACK";
            options.LocalizedCancelButtonText = "CANCEL";

            // use LAPolicy.DeviceOwnerAuthenticationWithBiometrics for biometrics only with no fallback to passcode/password
            // use LAPolicy.DeviceOwnerAuthentication for biometrics+watch with fallback to passcode/password
            _biometryService = new BiometryService(options, async ct => "Biometrics_Confirm", LAPolicy.DeviceOwnerAuthentication);
```

- Android

Face ID is only available with the followwing configuration `.SetAllowedAuthenticators(BiometricManager.Authenticators.BiometricWeak` during instantiation of the service.

Encrypt/Decrypt method are only available with the following configuration `.SetAllowedAuthenticators(BiometricManager.Authenticators.BiometricStrong` during instantiation of the service.

An example of instantiation is as follow, with the fallback to the pin code with some text descriptions to display for the user.

```
			    _biometryService = new BiometryService(MainActivity.Instance,
												   CoreDispatcher.Main,
                                                   ct => Task.FromResult(new BiometricPrompt.PromptInfo.Builder()
												    .SetTitle("Biometrics SignIn")
												    .SetSubtitle("Biometrics Confirm")
												    .SetAllowedAuthenticators(BiometricManager.Authenticators.BiometricStrong | BiometricManager.Authenticators.DeviceCredential) // Fallback on secure pin
                                                    .SetNegativeButtonText("Cancel")
                                                    .Build()));
```

### GetGapabilites

This method helps to check the hardware status on the device.
`_biometryService.GetCapabilities();`

It will return a struct `BiometryCapabilities` with the detailled device configuration.

- IOS

| Capability   | ValidateIdentity | Decrypt | Encrypt |
| -------------- | ------------------ | --------- | --------- |
| Face ID      | x                | x       | x       |
| Touch ID     | x                | x       | x       |
| Fallback PIN | x                | x       | x       |

- Android


| Capability   | ValidateIdentity | Decrypt | Encrypt |
| -------------- | ------------------ | --------- | --------- |
| Face ID      | x                | None    | None    |
| Touch ID     | x                | x       | x       |
| Fallback PIN | x                | x       | x       |

On Android depending on how the service is instantiated, some features might not be available and will throw errors.

### ValidateIdentity

This method helps to authenticate the user by returning an Enum `BiometryResult`.
`_biometryService.ValidateIdentity(ct);`

### Encrypt

The follow method do specific actions according to the platorm targeted.
`await _biometryService.Encrypt(ct, "Key", "StringToEnrypt");`

- IOS

The `SecKeyChain` will be used to store a string linked to a key. IOS is in charge of securing the data with biometric Authentication during the process.
In case of error, `SecurityException` is thrown.

- Android

A new `CryptoObject` from `AndroidX.Biometric` is created with a key as a parameter. Then the data will be encrypted and presented to the `biometricPrompt` manager.
The final step will encode the data in base64 and store it in App with the shared preferences.


### Decrypt

The following method does specific actions according to the platform targeted.
`await _biometryService.Decrypt(ct, "Secret");`

- IOS

Retrieve the encrypted data from the `SecKeyChain` with the secret as a parameter. IOS is in charge of decrypting the data with biometric Authentication during the process. 

- Android

Retrieve the shared preference encrypted data, then decrypt it with the secret as a parameter by presenting it to the `biometricPrompt` manager.

## Changelog

Please consult the [CHANGELOG](CHANGELOG.md) for more information about version
history.

## License

This project is licensed under the Apache 2.0 license - see the
[LICENSE](LICENSE) file for details.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on the process for
contributing to this project.

Be mindful of our [Code of Conduct](CODE_OF_CONDUCT.md).

## Contributors

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->

<!-- ALL-CONTRIBUTORS-LIST:END -->
