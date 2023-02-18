#if __IOS__
using System;
using System.Threading;
using System.Threading.Tasks;
using Foundation;
using LocalAuthentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Security;

namespace BiometryService;

/// <summary>
/// Implementation of the <see cref="IBiometryService" /> for iOS.
/// </summary>
public sealed class BiometryService : IBiometryService
{
	private readonly LAContext _laContext;

	/// <summary>
	/// User facing description of the kind of authentication that the application is trying to perform.
	/// </summary>
	/// <remarks>
	/// Set this value to a string that will be displayed to the user when the authentication takes place for the item to give the user some context for the request.
	/// </remarks>
	private readonly string _useOperationPrompt;

	/// <summary>
	/// Authentication policies.
	/// </summary>
	private readonly LAPolicy _localAuthenticationPolicy;
	
	private readonly ILogger _logger;

	private readonly bool _fallbackOnPasscodeAuthentication = false;

	/// <summary>
	/// Initializes a new instance of the <see cref="BiometryService" /> class.
	/// </summary>
	/// <param name="laContext"><see cref="LAContext" />.</param>
	/// <param name="useOperationPrompt">Biometry user facing description.</param>
	/// <param name="localAuthenticationPolicy"><see cref="LAPolicy"/>.</param>
	/// <param name="loggerFactory"><see cref="ILoggerFactory"/>.</param>
	public BiometryService(
		LAContext laContext,
		string useOperationPrompt,
		LAPolicy localAuthenticationPolicy = LAPolicy.DeviceOwnerAuthentication,
		ILoggerFactory loggerFactory = null
	)
	{
		_laContext = laContext;
		_useOperationPrompt = useOperationPrompt;
		_localAuthenticationPolicy = localAuthenticationPolicy;
		_logger = loggerFactory?.CreateLogger<IBiometryService>() ?? NullLogger<IBiometryService>.Instance;
	}

	/// <inheritdoc/>
	public Task<BiometryCapabilities> GetCapabilities(CancellationToken ct)
	{
		_laContext.CanEvaluatePolicy(_localAuthenticationPolicy, out var laError);

		var biometryType = GetBiometryTypeFrom(_laContext.BiometryType);
		var passcodeIsSet = true;
		var biometryIsEnabled = true;

		if (laError is not null)
		{
			/* Documentation (https://developer.apple.com/documentation/localauthentication/laerror/code) without error code values.
			 * See error code values locations bellow.
			 * /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/LocalAuthentication.framework/Headers/LAError.h
			 * /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/LocalAuthentication.framework/Headers/LAPublicDefines.h */
			switch (laError.Code)
			{
				case -5: // Passcode is not set on the device.
					passcodeIsSet = false;
					biometryIsEnabled = false;
					break;
				case -6: // Biometrics is not available (No hardware support or TouchId/FaceId has been disabled for the application).
				case -7: // Biometrics is not enrolled (TouchId/FaceId was not added).
					biometryIsEnabled = false;
					break;
			}
		}
		return Task.FromResult(new BiometryCapabilities(biometryType, biometryIsEnabled, passcodeIsSet));
	}

	/// <inheritdoc/>
	public async Task ScanBiometry(CancellationToken ct)
	{
		if (_laContext.BiometryType is LABiometryType.FaceId)
		{
			// Verify that Info.plist file contains NSFaceIDUsageDescription (key/value) otherwise the application will crash.
			var faceIDUsageDescription = ((NSString)NSBundle.MainBundle.InfoDictionary["NSFaceIDUsageDescription"])?.ToString();
			if (string.IsNullOrEmpty(faceIDUsageDescription))
			{
				throw new BiometryException(BiometryExceptionReason.Failed, "Please add NSFaceIDUsageDescription key in the `Info.plist` file.");
			}
		}

		/* Documentation (https://developer.apple.com/documentation/localauthentication/laerror/code) without error code values.
		 * See error code values locations bellow.
		 * /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/LocalAuthentication.framework/Headers/LAError.h
		 * /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/LocalAuthentication.framework/Headers/LAPublicDefines.h */
		var (_, laError) = await _laContext.EvaluatePolicyAsync(_localAuthenticationPolicy, _laContext.LocalizedReason);
		if (laError is not null)
		{
			switch (laError.Code)
			{
				case 0:
					break;
				case -1:
					// user failed auth; this case happens after they failed multiple attempts and also failed fallback if that's an option
					throw new BiometryException(BiometryExceptionReason.Failed, "");
				case -2:
					// user cancelled
					throw new OperationCanceledException();
				case -3:
					// user attempted to fallback to passcode/password, but that's not an option
					// only applies to LAPolicy.DeviceOwnerAuthenticationWithBiometrics
					throw new BiometryException(BiometryExceptionReason.Failed, "");
				case -4:
					// system cancelled
					throw new OperationCanceledException();
				case -5:
					// passcode/password not set
					// this case should not happen because callers of this private method should pre-check for this
					throw new BiometryException(BiometryExceptionReason.PasscodeNeeded, "Passcode is not set on the device.");
				case -6:
					// biometrics not available
					// this case should not happen because callers of this private method should pre-check for this
					throw new BiometryException(BiometryExceptionReason.Unavailable, "Biometrics is not available (No hardware support or TouchId/FaceId has been disabled for the application).");
				case -7:
					// biometrics not enrolled
					// this case should not happen because callers of this private method should pre-check for this
					throw new BiometryException(BiometryExceptionReason.NotEnrolled, "Biometrics is not enrolled (TouchId/FaceId was not added).");
				case -8:
					// user failed too many attempts for biometry and is now locked out from using biometry in the future until passcode/password is provided
					// Only applies to LAPolicy.DeviceOwnerAuthenticationWithBiometrics
					throw new BiometryException(BiometryExceptionReason.Locked, "");
				case -9:
					// app cancelled
					throw new OperationCanceledException();
				case -10:
					// invalidated LAContext; this case can happen when LAContext.Invalidate() was called
					throw new BiometryException(BiometryExceptionReason.Failed, "");
				case -11: // No paired Apple Watch is available. Only applies when using LAPolicy.DeviceOwnerAuthenticationWithWatch.
					throw new BiometryException(BiometryExceptionReason.Failed, "No paired Apple Watch is available.");
				case -1004:
					// no native dialog was shown because LAContext.InteractionNotAllowed is `true`
					throw new BiometryException(BiometryExceptionReason.Failed, "");
				default:
					// unknown case not documented by Apple, just return denied instead of throwing an exception to prevent breaking the future
					throw new BiometryException(BiometryExceptionReason.Failed, "");
			}
		}
	}

	/// <inheritdoc/>
	public async Task Encrypt(CancellationToken ct, string keyName, string keyValue)
	{
		try
		{
			if (_logger.IsEnabled(LogLevel.Debug))
			{
				_logger.LogDebug($"Encrypting the key '{keyName}'.");
			}

			var biometryCapabilities = await GetCapabilities(ct);
			if (biometryCapabilities.IsSupported & biometryCapabilities.IsEnabled)
			{
				SetValueForKey(keyName, keyValue);

				if (_logger.IsEnabled(LogLevel.Debug))
				{
					_logger.LogDebug($"The key '{keyName}' has been successfully encrypted.");
				}
			}
			else
			{
				var reason = biometryCapabilities.IsSupported ? BiometryExceptionReason.NotEnrolled : BiometryExceptionReason.Unavailable;
				var message = biometryCapabilities.IsSupported ? "Biometrics are not enrolled on this device" : "Biometry is not available on this device";

				throw new BiometryException(reason, message);
			}
		}
		catch
		{
			if (_logger.IsEnabled(LogLevel.Debug))
			{
				_logger.LogDebug($"The key '{keyName}' has not been successfully encrypted.");
			}
			throw;
		}
	}

	/// <inheritdoc/>
	public async Task<string> Decrypt(CancellationToken ct, string keyName)
	{
		try
		{
			if (_logger.IsEnabled(LogLevel.Debug))
			{
				_logger.LogDebug($"Decrypting the key '{keyName}'.");
			}

			var biometryCapabilities = await GetCapabilities(ct);
			if (biometryCapabilities.IsEnabled)
			{
				var keyValue = GetValueForKey(keyName, _useOperationPrompt);

				if (_logger.IsEnabled(LogLevel.Debug))
				{
					_logger.LogDebug($"The key '{keyName}' has been successfully decrypted.");
				}

				return keyValue;
			}
			else
			{
				var reason = biometryCapabilities.IsSupported ? BiometryExceptionReason.NotEnrolled : BiometryExceptionReason.Unavailable;
				var message = biometryCapabilities.IsSupported ? "Biometrics are not enrolled on this device" : "Biometry is not available on this device";

				throw new BiometryException(reason, message);
			}
		}
		catch
		{
			if (_logger.IsEnabled(LogLevel.Debug))
			{
				_logger.LogDebug($"The key '{keyName}' has not been successfully decrypted.");
			}
			throw;
		}
	}

	/// <inheritdoc/>
	public void Remove(string keyName)
	{
		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug($"Removing the key '{keyName}'.");
		}

		var record = new SecRecord(SecKind.GenericPassword)
		{
			Service = keyName.ToLowerInvariant(),
			UseOperationPrompt = _useOperationPrompt
		};

		var status = SecKeyChain.Remove(record);
		if (status is not SecStatusCode.Success)
		{
			if (_logger.IsEnabled(LogLevel.Debug))
			{
				_logger.LogDebug($"The key '{keyName}' has not been successfully removed.");
			}
			throw new BiometryException(BiometryExceptionReason.Failed, $"Something went wrong while removing the key '{keyName}'. Status = {status}");
		}

		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug($"The key '{keyName}' has been successfully removed.");
		}
	}

	/// <summary>
	/// 
	/// </summary>
	/// <param name="biometryType"></param>
	/// <returns></returns>
	private static BiometryType GetBiometryTypeFrom(LABiometryType biometryType)
	{
		return biometryType switch
		{
			LABiometryType.None => BiometryType.None,
			LABiometryType.TouchId => BiometryType.Fingerprint,
			LABiometryType.FaceId => BiometryType.Face,
			_ => BiometryType.None,
		};
	}

	/// <summary>
	/// 
	/// </summary>
	/// <param name="keyName"></param>
	/// <param name="keyValue"></param>
	/// <exception cref="BiometryException"></exception>
	private void SetValueForKey(string keyName, string keyValue)
	{
		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug($"Saving the key '{keyName}'.");
		}

		var record = new SecRecord(SecKind.GenericPassword)
		{
			Service = keyName.ToLowerInvariant(),
		};

		// Check for duplicate key.
		var status = SecKeyChain.Remove(record);
		if (status is not SecStatusCode.Success | status is not SecStatusCode.ItemNotFound)
		{
			throw new BiometryException(BiometryExceptionReason.Failed, $"Something went wrong while checking for duplicate key '{keyName}'. Status = {status}");
		}

		// Use biometry to encrypt the key.
		record.AccessControl = new SecAccessControl(
			SecAccessible.WhenPasscodeSetThisDeviceOnly,
			_fallbackOnPasscodeAuthentication ? SecAccessControlCreateFlags.UserPresence : SecAccessControlCreateFlags.BiometryCurrentSet
		);

		record.Generic = NSData.FromString(keyValue);

		var result = SecKeyChain.Add(record);
		if (result is not SecStatusCode.Success)
		{
			throw new BiometryException(BiometryExceptionReason.Failed, $"Something went wrong while saving the key '{keyName}'. Status = {status}");
		}

		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug($"Successfully saved the key '{keyName}'.");
		}
	}

	/// <summary>
	/// 
	/// </summary>
	/// <param name="keyName"></param>
	/// <param name="useOperationPrompt"></param>
	/// <returns></returns>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="SecurityException"></exception>
	private string GetValueForKey(string keyName, string useOperationPrompt)
	{
		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug($"Retrieving the key '{keyName}'.");
		}

		var record = new SecRecord(SecKind.GenericPassword)
		{
			Service = keyName.ToLowerInvariant(),
			UseOperationPrompt = useOperationPrompt
		};

		var key = SecKeyChain.QueryAsRecord(record, out var result);

		if (result is SecStatusCode.Success)
		{
			if (_logger.IsEnabled(LogLevel.Debug))
			{
				_logger.LogDebug($"Successfully retrieved value of the key '{keyName}'.");
			}
			return key.Generic.ToString();
		}

		var reason = BiometryExceptionReason.Failed;
		var message = $"Something went wrong while retrieving value of the key '{keyName}'.";

		switch (result)
		{
			case SecStatusCode.AuthFailed:
				reason = BiometryExceptionReason.Failed;
				message = $"Authentication failed. Could not retrieve value of the key '{keyName}'.";
				break;
			case SecStatusCode.ItemNotFound:
				message = $"Key '{keyName}' not found.";
				reason = BiometryExceptionReason.KeyNotFound;
				break;
		}

		if (_logger.IsEnabled(LogLevel.Error))
		{
			_logger.LogError(message);
		}
		throw new BiometryException(reason, message);
	}
}
#endif
