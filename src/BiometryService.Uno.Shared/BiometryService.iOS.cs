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
public sealed partial class BiometryService : IBiometryService
{
	/// <summary>
	/// User facing description of the kind of authentication that the application is trying to perform.
	/// </summary>
	/// <remarks>
	/// Set this value to a string that will be displayed to the user when the authentication takes place for the item to give the user some context for the request.
	/// </remarks>
	private readonly string _useOperationPrompt;

	private readonly LAContext _laContext;

	/// <summary>
	/// Authentication policies.
	/// </summary>
	private readonly LAPolicy _localAuthenticationPolicy;
	
	private readonly ILogger _logger;

	private readonly bool _fallbackOnPasscodeAuthentication = false;

	/// <summary>
	/// Initializes a new instance of the <see cref="BiometryService" /> class.
	/// </summary>
	/// <param name="useOperationPrompt">Biometry user facing description.</param>
	/// <param name="laContext"><see cref="LAContext" />.</param>
	/// <param name="localAuthenticationPolicy"><see cref="LAPolicy"/>.</param>
	/// <param name="loggerFactory"><see cref="ILoggerFactory"/>.</param>
	public BiometryService(
		string useOperationPrompt,
		LAContext laContext = null,
		LAPolicy localAuthenticationPolicy = LAPolicy.DeviceOwnerAuthentication,
		ILoggerFactory loggerFactory = null
	)
	{
		_useOperationPrompt = useOperationPrompt;
		_laContext = laContext ?? new LAContext();
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
		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug("Scanning biometry.");
		}

		if (_laContext.BiometryType is LABiometryType.FaceId)
		{
			if (_logger.IsEnabled(LogLevel.Trace))
			{
				_logger.LogTrace("Checks that `Info.plist` file contains NSFaceIDUsageDescription.");
			}

			// Checks that Info.plist file contains NSFaceIDUsageDescription (key/value) otherwise the application will crash.
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
			var reason = BiometryExceptionReason.Failed;
			var message = string.Empty;

			switch (laError.Code)
			{
				case -2: // User cancelled.
				case -4: // System cancelled.
				case -9: // Application cancelled.
					throw new OperationCanceledException();

				// The user failed to provide valid credentials.
				case -1:
					message = "The user failed to provide valid credentials.";
					break;

				// The user tapped the fallback button in the authentication dialog, but no fallback is available for the authentication policy.
				// Only applies to LAPolicy.DeviceOwnerAuthenticationWithBiometrics.
				case -3:
					message = "No fallback is available for the authentication policy";
					break;

				// A passcode isn’t set on the device.
				// This case should not happen because callers of this method should pre-check for this.
				case -5:
					reason = BiometryExceptionReason.PasscodeNeeded;
					message = "A passcode isn’t set on the device.";
					break;

				// Biometry is not available on the device.
				// This case should not happen because callers of this method should pre-check for this.
				case -6:
					reason = BiometryExceptionReason.Unavailable;
					message = "Biometrics is not available (No hardware support or TouchId/FaceId has been disabled for the application).";
					break;

				// The user has no enrolled biometric identities.
				// This case should not happen because callers of this method should pre-check for this.
				case -7:
					reason = BiometryExceptionReason.NotEnrolled;
					message = "Biometrics is not enrolled (TouchId/FaceId was not added).";
					break;

				// Biometry is locked because there were too many failed attempts.
				// A passcode is now required to unlock biometry.
				// Try the LAPolicy.DeviceOwnerAuthentication instead to allow use of a passcode.
				// Only applies to LAPolicy.DeviceOwnerAuthenticationWithBiometrics.
				case -8:
					reason = BiometryExceptionReason.Locked;
					message = "Biometry is locked because there were too many failed attempts.";
					break;

				// The context was previously invalidated.
				// You can invalidate a context by calling its Invalidate method.
				case -10: 
					message = "The context was invalidated";
					break;

				// An attempt to authenticate with Apple Watch failed.
				// Only applies when using LAPolicy.DeviceOwnerAuthenticationWithWatch.
				case -11:
					message = "No paired Apple Watch is available.";
					break;

				// Displaying the required authentication user interface is forbidden.
				// Only applies when LAContext.InteractionNotAllowed is set to true.
				case -1004: 
					message = "Displaying the required authentication user interface is forbidden.";
					break;

				// Unknown or unmanaged case.
				default:
					message = string.Concat(
						$"Unknown or unmanaged case. Error code {laError.Code}.",
						$"Description: '{laError.LocalizedDescription}'.{Environment.NewLine}",
						"See https://developer.apple.com/documentation/localauthentication/laerror/code for more informations."
					);
					break;
			}

			throw new BiometryException(reason, message);
		}
		else
		{
			if (_logger.IsEnabled(LogLevel.Information))
			{
				_logger.LogDebug("Biometry has been successfully scanned.");
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
				_logger.LogDebug("Encrypting the key '{keyName}'.", keyName);
			}

			await ValidateBiometryCapabilities(ct);

			SetValueForKey(keyName, keyValue);

			if (_logger.IsEnabled(LogLevel.Debug))
			{
				_logger.LogDebug("The key '{keyName}' has been successfully encrypted.", keyName);
			}
		}
		catch
		{
			if (_logger.IsEnabled(LogLevel.Debug))
			{
				_logger.LogDebug("The key '{keyName}' has not been successfully encrypted.", keyName);
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
				_logger.LogDebug("Decrypting the key '{keyName}'.", keyName);
			}

			await ValidateBiometryCapabilities(ct);

			var keyValue = GetValueForKey(keyName, _useOperationPrompt);

			if (_logger.IsEnabled(LogLevel.Debug))
			{
				_logger.LogDebug("The key '{keyName}' has been successfully decrypted.", keyName);
			}

			return keyValue;
		}
		catch
		{
			if (_logger.IsEnabled(LogLevel.Debug))
			{
				_logger.LogDebug("The key '{keyName}' has not been successfully decrypted.", keyName);
			}
			throw;
		}
	}

	/// <inheritdoc/>
	public void Remove(string keyName)
	{
		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug("Removing the key '{keyName}'.", keyName);
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
				_logger.LogDebug("The key '{keyName}' has not been successfully removed.", keyName);
			}
			throw new BiometryException(BiometryExceptionReason.Failed, $"Something went wrong while removing the key '{keyName}'. Status = {status}");
		}

		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug("The key '{keyName}' has been successfully removed.", keyName);
		}
	}

	/// <summary>
	/// Gets <see cref="BiometryType"/> from <see cref="LABiometryType"/>.
	/// </summary>
	/// <param name="biometryType"><see cref="LABiometryType"/>.</param>
	/// <returns><see cref="BiometryType"/>.</returns>
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
	/// Encrypt a key using biometry.
	/// </summary>
	/// <remarks>
	/// If the key already exists, it will be replaced.
	/// </remarks>
	/// <param name="keyName">The key name.</param>
	/// <param name="keyValue">The key value.</param>
	/// <exception cref="BiometryException">.</exception>
	private void SetValueForKey(string keyName, string keyValue)
	{
		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug("Saving the key '{keyName}'.", keyName);
		}

		var record = new SecRecord(SecKind.GenericPassword)
		{
			Service = keyName.ToLowerInvariant(),
		};

		// Check for duplicate key.
		var status = SecKeyChain.Remove(record);
		if (status is SecStatusCode.Success || status is SecStatusCode.ItemNotFound)
		{
			// Use biometry to encrypt the key.
			record.AccessControl = new SecAccessControl(
				SecAccessible.WhenPasscodeSetThisDeviceOnly,
				_fallbackOnPasscodeAuthentication ? SecAccessControlCreateFlags.UserPresence : SecAccessControlCreateFlags.BiometryCurrentSet
			);

			record.Generic = NSData.FromString(keyValue);

			var result = SecKeyChain.Add(record);
			if (result is not SecStatusCode.Success)
			{
				throw new BiometryException(BiometryExceptionReason.Failed, $"Something went wrong while saving the key '{keyName}'.");
			}

			if (_logger.IsEnabled(LogLevel.Debug))
			{
				_logger.LogDebug("Successfully saved the key '{keyName}'.", keyName);
			}
		}
		else
		{
			throw new BiometryException(BiometryExceptionReason.Failed, $"Something went wrong while checking for duplicate key '{keyName}'. Status = {status}");
		}
	}

	/// <summary>
	/// Get the encrypted value for the key using biometry.
	/// </summary>
	/// <param name="keyName">The key name.</param>
	/// <param name="useOperationPrompt">Biometry user facing description.</param>
	/// <returns></returns>
	/// <exception cref="BiometryException">.</exception>
	private string GetValueForKey(string keyName, string useOperationPrompt)
	{
		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug("Retrieving the key '{keyName}'.", keyName);
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
				_logger.LogDebug("Successfully retrieved value of the key '{keyName}'.", keyName);
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
				reason = BiometryExceptionReason.KeyInvalidated;
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
