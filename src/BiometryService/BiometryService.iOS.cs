#if __IOS__
using System;
using System.Threading;
using System.Threading.Tasks;
using Foundation;
using LocalAuthentication;

namespace BiometryService
{
	/// <summary>
	///     Implementation of the <see cref="IBiometryService" /> for iOS.
	/// </summary>
	public class BiometryService : IBiometryService
	{
		private readonly LAPolicy _localAuthenticationPolicy;
		private readonly BiometryOptions _options;

		/// <summary>
		///     Initializes a new instance of the <see cref="BiometryService" /> class.
		/// </summary>
		/// <param name="options">The <see cref="BiometryOptions" /> instance to use.</param>
		/// <param name="localAuthenticationPolicy">The <see cref="LAPolicy" /> to use.</param>
		public BiometryService(BiometryOptions options, LAPolicy localAuthenticationPolicy = LAPolicy.DeviceOwnerAuthentication)
		{
			_options = options ?? new BiometryOptions();

			_localAuthenticationPolicy = localAuthenticationPolicy;
		}

		/// <inheritdoc />
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

		/// <inheritdoc />
		public async Task<BiometryAuthenticationResult> Authenticate(CancellationToken ct)
		{
			var context = new LAContext();
			context.LocalizedReason = _options.LocalizedReasonBodyText;
			context.LocalizedFallbackTitle = _options.LocalizedFallbackButtonText;
			context.LocalizedCancelTitle = _options.LocalizedCancelButtonText;

			var capabilities = GetCapabilities();
			if (!capabilities.PasscodeIsSet)
			{
				throw new Exception(
					"No passcode/password is set on the device. To avoid catching this exception: call GetCapabilities() and inspect if the passcode/password is set or not before calling this method.");
			}

			if (!capabilities.IsSupported)
			{
				throw new Exception(
					"Biometrics not available (no hardware support OR user has disabled FaceID/TouchID for the app). To avoid catching this exception: call GetCapabilities() and inspect if the biometrics is supported before calling this method.");
			}

			if (!capabilities.IsEnabled)
			{
				throw new Exception(
					"Biometrics not enrolled (no finger xor face was added by the user). To avoid catching this exception: call GetCapabilities() and inspect if biometrics is enabled before calling this method.");
			}

			if (context.BiometryType == LABiometryType.FaceId)
			{
				// Verify that info.plist contains NSFaceIDUsageDescription key/value otherwise the app will crash
				var faceIDUsageDescription = ((NSString)NSBundle.MainBundle.InfoDictionary["NSFaceIDUsageDescription"])?.ToString();
				if (string.IsNullOrEmpty(faceIDUsageDescription))
				{
					throw new MissingFieldException("Please add a NSFaceIDUsageDescription key in the `Info.plist` file.");
				}
			}

			var (_, laError) = await context.EvaluatePolicyAsync(_localAuthenticationPolicy, context.LocalizedReason);
			var evaluatePolicyResult = GetAuthenticationResultFrom(laError);

			return evaluatePolicyResult;
		}

		/// <inheritdoc />
		public Task<BiometryAuthenticationResult> Encrypt<T>(CancellationToken ct, string key, string value)
		{
			throw new NotImplementedException();
		}

		/// <inheritdoc />
		public Task<BiometryAuthenticationResult> Decrypt(CancellationToken ct, string key, out string value)
		{
			throw new NotImplementedException();
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
	}
}

#endif
