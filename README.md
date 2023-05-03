# Biometry Service

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->

[![All Contributors](https://img.shields.io/badge/all_contributors-5-orange.svg?style=flat-square)](#contributors-)

<!-- ALL-CONTRIBUTORS-BADGE:END -->

This library offers a simple contract to use the biometry across Android, iOS and Windows (UWP & WinUI).

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Features

The Biometry Service Interface `IBiometryService` is made of the following methods:

- GetGapabilites
- ScanBiometry
- Encryt
- Decrypt
- Remove

As of now, this is the list of features available per platform.

| Feature          | iOS     | Android | UWP     | WinUI   |
| ---------------- | ------- | ------- | ------- | ------- |
| GetCapability    | &check; | &check; | &check; | &check; |
| ValidateIdentity | &check; | &check; | &cross; | &cross; |
| Encrypt          | &check; | &check; | &cross; | &cross; |
| Decrypt          | &check; | &check; | &cross; | &cross; |

## Getting Started

Install the latest stable version of `BiometryService` in your platform heads and `BiometryService.Abstractions` in your presentation layer if you are using MVVM pattern, and if not just install both in your platform heads.

A small sample Uno application is available as a playground with some basic command to test the service methods.
They also provide some basic initialization but no dependency injection and more complex code.

### Instantiation

#### Android

Face authentication is only available when using `.SetAllowedAuthenticators(AndroidX.Biometric.BiometricManager.Authenticators.BiometricWeak)` in the `BiometricPrompt.PromptInfo.Builder` instantiation that is required for the service. Please note that if you are using `.SetAllowedAuthenticators(AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong)` in the `BiometricPrompt.PromptInfo.Builder` Face authentication is only available on a Google Pixel 4 as of now.

Please note that Encrypt/Decrypt methods are only available when using `.SetAllowedAuthenticators(AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong)` in the `BiometricPrompt.PromptInfo.Builder` instantiation that is required for the service.

Please also note that the title and subtitle are used for `Fingerprint` and `Face` biometry.

Here is an example of instantiation of the service for Android.

``` cs
var promptBuilder = () => new BiometricPrompt.PromptInfo.Builder()
	.SetTitle("Title")
	.SetSubtitle("Subtitle")
	.SetNegativeButtonText("Cancel")
	.SetAllowedAuthenticators(AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong)
	.Build();

var biometryService = new BiometryService(
	fragmentActivity: MainActivity.Instance,
	promptInfoBuilder: promptBuilder,
	loggerFactory: null
);
```

#### iOS

Please note that you must set `NSFaceIDUsageDescription` (key/value) in the `Info.plist` file otherwise the service will throw an exception.

Please also note that the prompt builder subtitle is used for `Fingerprint` biometry only.

Here is an example of instantiation of the service for iOS.

``` cs
_biometryService = new BiometryService(
	useOperationPrompt: "Subtitle",
	laContext: null,
	localAuthenticationPolicy: LAPolicy.DeviceOwnerAuthenticationWithBiometrics,
	loggerFactory: null
);
```

## Methods

Please note that in case of error, `BiometryException` is thrown. 

Biometry Exception Types:
- `Failed`: Any other failures while trying to use the device biometrics.
- `Unavailable`: The device biometrics is not available.
- `NotEnrolled`: The device has not been enrolled to use biometrics.
- `PasscodeNeeded`: The passcode needs to be set on the device.
- `Locked`:
  - The device has been locked from using his biometrics.
  - Due mostly to too many attempts.
  - User have to try again later or unlock his device again.
- `KeyInvalidated`:
  - Biometric information has changed (E.g. Touch ID or Face ID has changed).
  - User have to set up biometric authentication again.

If it's a cancellation error, `OperationCanceledException` is thrown.

### GetGapabilites

Gets the device's current biometric capabilities.

It will return a struct `BiometryCapabilities` with the detailled device configuration.

### ScanBiometry

Attemps to scan the user's biometry.

``` cs
await biometryService.ScanBiometry(cancellationToken);
```

### Encrypt

Encrypts the value and stores it into the platform secure storage with the given key name.

``` cs
await biometryService.Encrypt(cancellationToken, "KeyName", "KeyValue");
```

#### Android

A new `CryptoObject` from `AndroidX.Biometric` is created with a key as a parameter. Then the data will be encrypted and presented to the `BiometricPrompt` manager.
The final step will encode the data in base64 and store it in App with the shared preferences.

#### iOS

The `SecKeyChain` will be used to store a string linked to a key. The OS is in charge of securing the data with biometric authentication during the process.

### Decrypt

Decrypts and gets the data associated to the given key name.

``` cs
await biometryService.Decrypt(cancellationToken, "KeyName");
```

#### Android

Retrieve the shared preference encrypted data, then decrypt it with the secret as a parameter by presenting it to the `BiometricPrompt` manager.

#### iOS

Retrieve the encrypted data from the `SecKeyChain` with the secret as a parameter. iOS is in charge of decrypting the data with biometric Authentication during the process. 

### Remove

Removes the ecrypted value in the platform secure storage.

``` cs
biometryService.Remove("KeyName");
```

#### Android

Remove the encrypted data from the shared preferences.

#### iOS

Remove the encrypted data from the `SecKeyChain`.

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
