#if __IOS__
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Foundation;
using LocalAuthentication;
using Microsoft.Extensions.Logging;
using Security;
using Uno;
using Uno.Extensions;
using Uno.Logging;

namespace BiometryService
{
	/// <summary>
	///     Implementation of the <see cref="IBiometryService" /> for iOS.
	/// </summary>
	public class BiometryService : IBiometryService
	{
		private FuncAsync<string> _description;
		private readonly LAPolicy _localAuthenticationPolicy;
		private readonly BiometryOptions _options;
		private readonly bool _fallbackOnPasscodeAuthentication;


		/// <summary>
		///     Initializes a new instance of the <see cref="BiometryService" /> class.
		/// </summary>
		/// <param name="options">The <see cref="BiometryOptions" /> instance to use.</param>
		/// <param name="description">An enum of LAPolicy.</param>
		/// <param name="localAuthenticationPolicy">The <see cref="LAPolicy" /> to use.</param>
		public BiometryService(BiometryOptions options, FuncAsync<string> description, LAPolicy localAuthenticationPolicy = LAPolicy.DeviceOwnerAuthentication)
		{
			_options = options ?? new BiometryOptions();

			_description = description;

			_localAuthenticationPolicy = localAuthenticationPolicy;
		}

		/// <summary>
		///     Gets the device's current biometric capabilities.
		/// </summary>
		/// <returns>A <see cref="BiometryCapabilities" /> struct instance.</returns>
		public BiometryCapabilities GetCapabilities()
		{
			var context = new LAContext();
			context.CanEvaluatePolicy(_localAuthenticationPolicy, out var laError);

			var biometryType = GetBiometryTypeFrom(context.BiometryType);
			var passcodeIsSet = true;
			var biometryIsEnabled = true;

			if (laError != null)
			{
				// Online docs, but no error code values: https://developer.apple.com/documentation/localauthentication/laerror?language=objc
				// Source code docs found locally starting in dir:
				// /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/LocalAuthentication.framework/Headers/LAError.h
				// /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/LocalAuthentication.framework/Headers/LAPublicDefines.h
				// Double check for your platform just to be sure! /Applications/Xcode.app/Contents/Developer/Platforms/{X}.platform/...

				if (laError.Code == -5)
				{
					// passcode/password not set on the device by the user
					passcodeIsSet = false;
					biometryIsEnabled = false;
				}

				if (laError.Code == -6)
				{
					// biometrics not available (no hardware support OR user has disabled FaceID/TouchID for the app)
					biometryIsEnabled = false;
				}

				if (laError.Code == -7)
				{
					// biometrics not enrolled (no finger xor face was added by the user)
					biometryIsEnabled = false;
				}
			}

			var capabilities = new BiometryCapabilities(biometryType, biometryIsEnabled, passcodeIsSet);
			return capabilities;
		}

		/// <summary>
		///     Authenticate the user using biometrics.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <returns>A <see cref="BiometryResult" /> enum value.</returns>
		public async Task<BiometryResult> ValidateIdentity(CancellationToken ct)
		{
			var context = new LAContext();
			context.LocalizedReason = _options.LocalizedReasonBodyText;
			context.LocalizedFallbackTitle = _options.LocalizedFallbackButtonText;
			context.LocalizedCancelTitle = _options.LocalizedCancelButtonText;

			var capabilities = GetCapabilities();
			if (!capabilities.PasscodeIsSet)
			{
				throw new BiometryException(
					"No passcode/password is set on the device. To avoid catching this exception: call GetCapabilities() and inspect if the passcode/password is set or not before calling this method.");
			}

			if (!capabilities.IsSupported)
			{
				throw new BiometryException(
					"Biometrics not available (no hardware support OR user has disabled FaceID/TouchID for the app). To avoid catching this exception: call GetCapabilities() and inspect if the biometrics is supported before calling this method.");
			}

			if (!capabilities.IsEnabled)
			{
				throw new BiometryException(
					"Biometrics not enrolled (no finger xor face was added by the user). To avoid catching this exception: call GetCapabilities() and inspect if biometrics is enabled before calling this method.");
			}

			if (context.BiometryType == LABiometryType.FaceId)
			{
				// Verify that info.plist contains NSFaceIDUsageDescription key/value otherwise the app will crash
				var faceIDUsageDescription = ((NSString)NSBundle.MainBundle.InfoDictionary["NSFaceIDUsageDescription"])?.ToString();
				if (string.IsNullOrEmpty(faceIDUsageDescription))
				{
					throw new BiometryException("Please add a NSFaceIDUsageDescription key in the `Info.plist` file.");
				}
			}

			var (_, laError) = await context.EvaluatePolicyAsync(_localAuthenticationPolicy, context.LocalizedReason);
			var evaluatePolicyResult = GetAuthenticationResultFrom(laError);

			return new BiometryResult();
		}

		/// <summary>
		///     Encrypt the string value into the keychain
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="key">The key for the value.</param>
		/// <param name="value">A string value to encrypt.</param>
		/// <returns>A string</returns>
		public async Task Encrypt(CancellationToken ct, string key, string value)
		{
			var capabilities = GetCapabilities();
			if (capabilities.IsEnabled)
			{
				if (this.Log().IsEnabled(LogLevel.Debug))
				{
					this.Log().Debug($"Encrypting the fingerprint for the key '{key}'.");
				}

				try
				{
					SaveKey(key, value);

					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info($"The fingerprint is successfully encrypted for the key '{key}'.");
					}

				}
				catch (SecurityException ex)
				{
					throw new BiometryException(string.Format("Encryption was cancelled. {0}", ex));
				}
			}
			else
            {
				if (this.Log().IsEnabled(LogLevel.Debug))
				{
					this.Log().Debug($"Can not encrypt '{key}'.");
				}
			}						
		}

		/// <summary>
		///     Decodes the array of string data to a string value
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="key">The key for the value.</param>
		/// <returns>A string</returns>
		public async Task<string> Decrypt(CancellationToken ct, string key)
		{
			var capabilities = GetCapabilities();
			if (capabilities.IsEnabled)
			{
				if (this.Log().IsEnabled(LogLevel.Debug))
				{
					this.Log().Debug($"Decrypting the fingerprint for the key '{key}'.");
				}

				try
				{
				   return RetrieveKey(key, await _description(ct));
				}
				catch (SecurityException ex)
				{
					throw new BiometryException(string.Format("Decryption was cancelled. {0}", ex));
				}				
			} else
            {
				if (this.Log().IsEnabled(LogLevel.Debug))
				{
					this.Log().Debug($"Can not decrypt '{key}'.");
				}
				return null;
			}
		}

		private static BiometryAuthenticationResult GetAuthenticationResultFrom(NSError laError)
		{
			// Online docs, but no error code values: https://developer.apple.com/documentation/localauthentication/laerror?language=objc
			// Source code docs found locally starting in dir:
			// /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/LocalAuthentication.framework/Headers/LAError.h
			// /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/LocalAuthentication.framework/Headers/LAPublicDefines.h
			// Double check for your platform just to be sure! /Applications/Xcode.app/Contents/Developer/Platforms/{X}.platform/...

			if (laError == null)
			{
				return BiometryAuthenticationResult.Granted;
			}

			switch (laError.Code)
			{
				case 0:
					return BiometryAuthenticationResult.Granted;
				case -1:
					// user failed auth; this case happens after they failed multiple attempts and also failed fallback if that's an option
					return BiometryAuthenticationResult.Denied;
				case -2:
					// user cancelled
					return BiometryAuthenticationResult.Cancelled;
				case -3:
					// user attempted to fallback to passcode/password, but that's not an option
					// only applies to LAPolicy.DeviceOwnerAuthenticationWithBiometrics
					return BiometryAuthenticationResult.Denied;
				case -4:
					// system cancelled
					return BiometryAuthenticationResult.Cancelled;
				case -5:
					// passcode/password not set
					// this case should not happen because callers of this private method should pre-check for this
					return BiometryAuthenticationResult.Denied;
				case -6:
					// biometrics not available
					// this case should not happen because callers of this private method should pre-check for this
					return BiometryAuthenticationResult.Denied;
				case -7:
					// biometrics not enrolled
					// this case should not happen because callers of this private method should pre-check for this
					return BiometryAuthenticationResult.Denied;
				case -8:
					// user failed too many attempts for biometry and is now locked out from using biometry in the future until passcode/password is provided
					// only applies to LAPolicy.DeviceOwnerAuthenticationWithBiometrics
					return BiometryAuthenticationResult.Denied;
				case -9:
					// app cancelled
					return BiometryAuthenticationResult.Cancelled;
				case -10:
					// invalidated LAContext; this case can happen when LAContext.Invalidate() was called
					return BiometryAuthenticationResult.Denied;
				case -11:
					// no paired Apple watch is available
					// only applies when using LAPolicy.DeviceOwnerAuthenticationWithWatch
					return BiometryAuthenticationResult.Denied;
				case -1004:
					// no native dialog was shown because LAContext.InteractionNotAllowed is `true`
					return BiometryAuthenticationResult.Denied;
				default:
					// unknown case not documented by Apple, just return denied instead of throwing an exception to prevent breaking the future
					return BiometryAuthenticationResult.Denied;
			}
		}

		private static BiometryType GetBiometryTypeFrom(LABiometryType biometryType)
		{
			switch (biometryType)
			{
				case LABiometryType.None:
					return BiometryType.None;
				case LABiometryType.TouchId:
					return BiometryType.Fingerprint;
				case LABiometryType.FaceId:
					return BiometryType.Face;
				default:
					// unknown case, just return none to prevent breaking the future
					return BiometryType.None;
			}
		}

		private void SaveKey(string keyName, string value)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Saving the key (key name: '{keyName}').");
			}

			var record = new SecRecord(SecKind.GenericPassword)
			{
				Service = keyName.ToLowerInvariant(),
			};

			var status = SecKeyChain.Remove(record);

			if (status == SecStatusCode.Success || status == SecStatusCode.ItemNotFound)
			{
				record.AccessControl = new SecAccessControl(
					SecAccessible.WhenPasscodeSetThisDeviceOnly,
					_fallbackOnPasscodeAuthentication ? SecAccessControlCreateFlags.UserPresence : SecAccessControlCreateFlags.TouchIDCurrentSet
				);

				record.Generic = NSData.FromString(value);

				var result = SecKeyChain.Add(record);

				if (result != SecStatusCode.Success)
				{
					throw new SecurityException(result);
				}

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Successfully saved the key (key name: '{keyName}').");
				}
			}
			else
			{
				throw new SecurityException(status);
			}
		}

		private string RetrieveKey(string keyName, string prompt)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Retrieving the key pair (key name: '{keyName}', prompt: '{prompt}').");
			}

			var record = new SecRecord(SecKind.GenericPassword)
			{
				Service = keyName.ToLowerInvariant(),
				UseOperationPrompt = prompt
			};

			var key = SecKeyChain.QueryAsRecord(record, out var result);

			switch (result)
			{
				case SecStatusCode.Success:

					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info($"Successfully retrieved the key pair (key name: '{keyName}', prompt: '{prompt}').");
					}

					return key.Generic.ToString();
				case SecStatusCode.AuthFailed:

					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info($"Could not retrieve the key due to a failed authentication (key name: '{keyName}', prompt: '{prompt}').");
					}

					return null;
				case SecStatusCode.ItemNotFound:
					throw new BiometryException("Key not found.");
				default:
					throw new SecurityException(result);
			}
		}
	}
}

#endif
