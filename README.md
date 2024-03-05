# Biometry Service

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE) ![Version](https://img.shields.io/nuget/v/BiometryService?style=flat-square) ![Downloads](https://img.shields.io/nuget/dt/BiometryService?style=flat-square)

This library offers a simple contract to use the biometry across Android, iOS and Windows (UWP & WinUI).

## Getting Started

1. Install `BiometryService` nuget package.
   
1. Get an `IBiometryService` instance.

   `IBiometryService` is implemented by `BiometryService`.
   The constructor of `BiometryService` is different on each platform.

   ### Windows

   On Windows there are no parameters. 

   ``` cs
    _biometryService = new BiometryService();
   ```

   ### Android

   On Android, you need to provide a `fragmentActivity` and a `promptInfoBuilder`.

   ``` cs
   var promptBuilder = () => new BiometricPrompt.PromptInfo.Builder()
	   .SetTitle("TODO: Title")
	   .SetSubtitle("TODO: Subtitle")
	   .SetNegativeButtonText("Cancel")
	   .SetAllowedAuthenticators(AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong)
	   .Build();

   var biometryService = new BiometryService(
   	   fragmentActivity: MainActivity.Instance,
   	   promptInfoBuilder: promptBuilder,
   	   loggerFactory: null
   );
   ```
   ### iOS

   On iOS, you first need to set `NSFaceIDUsageDescription` (key/value) in the `Info.plist` file.

   ``` xml
     <!-- info.plist -->
	 <key>NSFaceIDUsageDescription</key>
	 <string>TODO: Biometry would like to use Face Id</string>
   ```

   Then, instantiate of the service for iOS.

   ``` cs
   _biometryService = new BiometryService(
   	   useOperationPrompt: "TODO: Subtitle",
   	   laContext: null,
   	   localAuthenticationPolicy: LAPolicy.DeviceOwnerAuthenticationWithBiometrics,
   	   loggerFactory: null
   );
   ```

1. Use `ScanBiometry` to prompt the native experience. 
   This will use automaticaly use the native biometric service of that device (FaceID, TouchID, Android Fingerprint, ect.). 

   ``` csharp
   try
   {
      await _biometryService.ScanBiometry(CancellationToken.None);
      // TODO: Handle the case when biometry is recognized.
   }
   catch (BiometryException biometryException)
   {
      // TODO: Handle the case when biometry is not recognized.
      Console.WriteLine($"{biometryException.Reason} : {biometryException.Message}");
   }
   ```

## Notes on Instantiation

### Android
- Face authentication is only available when using `.SetAllowedAuthenticators(AndroidX.Biometric.BiometricManager.Authenticators.BiometricWeak)` in the `BiometricPrompt.PromptInfo.Builder` instantiation that is required for the service. Please note that if you are using `.SetAllowedAuthenticators(AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong)` in the `BiometricPrompt.PromptInfo.Builder` Facial authentification is exclusively accessible on phones equipped with Class 3 Biometric capabilities. (Pixel 4 and 8 for now).

- Please note that `Encrypt` and `Decrypt` methods are only available when using `.SetAllowedAuthenticators(AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong)` in the `BiometricPrompt.PromptInfo.Builder` instantiation that is required for the service.

- Please also note that the prompt builder `SetTitle` and `SetSubtitle` are used for both `Fingerprint` and `Face` biometry. We suggest that you use something generic enough for both cases.

### iOS

- The `laContext` parameter (local authentication context) can be set by creating a new [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext#2930204).
   ``` csharp
   var laContext = new LAContext
   {
   	LocalizedReason = "This app wants to use biometry for ...",
   	LocalizedFallbackTitle = "Fallback Title",
   	LocalizedCancelTitle = "Cancel Title"
   };
   ```
- Please note that the subtitle passed via `useOperationPrompt` is only displayed on devices using TouchID.

## Features

### Platform Compatibilities

The `IBiometryService` has severals methods.

As of now, this is the list of features available per platform.

| Methods          | iOS     | Android | WinUI   | UWP     |
| ---------------- | :-----: | :-----: | :-----: | :-----: |
| `GetCapability`  | ✔ | ✔ | ✔ | ✔ |
| `ScanBiometry`	 | ✔ | ✔ | ✔ | ✔ |
| `Encrypt`        | ✔ | ✔ | ✔ | ✔ |
| `Decrypt`        | ✔ | ✔ | ❌ | ❌ |
| `Remove`         | ✔ | ✔ | ✔ | ✔ |

### Tests

It's also possible to use a fake implementation of `IBiometryService` named `FakeBiometryService` for testing purposes only.

This fake implementation doesn't actually encrypt anything, the key and value pairs are stored in memory.

The fake implementation behavior can be customized by using constructor parameters.

``` csharp
var fakeBiometryService = new FakeBiometryService
{
   biometryType: BiometryType.None,
   isBiometryEnabled: false,
   isPasscodeSet: false
};
```

### Error Handling

Please note that in case of error, a `BiometryException` is thrown. 

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

This method gets the device's current biometric capabilities.

It returns a struct `BiometryCapabilities` with the detailed device configuration.

### ScanBiometry

This method attemps to scan the user's biometry.

``` cs
await biometryService.ScanBiometry(CancellationToken.None);
```

### Encrypt

This method encrypts a value and stores it into the platform secure storage with the given key name.

``` cs
await biometryService.Encrypt(CancellationToken.None, "Key", "Value");
```

On Android, a new `CryptoObject` from `AndroidX.Biometric` is created with a key as a parameter. Then the data is encrypted and presented to the `BiometricPrompt` manager.
The final step encodes the data in base64 and stores it in the shared preferences.

On iOS, the `SecKeyChain` is used to store a string linked to a key. The OS is in charge of securing the data with biometric authentication during the process.

### Decrypt

This method decrypts and gets the data associated to the given key.

``` cs
await biometryService.Decrypt(CancellationToken.None, "Key");
```

On Android, the method retrieves the shared preference encrypted data, then decrypts it with the secret as a parameter by presenting it to the `BiometricPrompt` manager.

On iOS, the method retrieves the encrypted data from the `SecKeyChain` with the secret as a parameter. iOS is in charge of decrypting the data with biometric authentication during the process. 

### Remove

This method removes the ecrypted value from the platform secure storage.

``` cs
biometryService.Remove("Key");
```

On Android, the method removes the encrypted data from the shared preferences.

On iOS, the method removes the encrypted data from the `SecKeyChain`.

## Breaking Changes

Please consult the [BREAKING CHANGES](BREAKING_CHANGES.md) for more information about breaking changes history.

## License

This project is licensed under the Apache 2.0 license - see the
[LICENSE](LICENSE) file for details.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on the process for
contributing to this project.

Be mindful of our [Code of Conduct](CODE_OF_CONDUCT.md).
