﻿#if __IOS__
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
public sealed class BiometryService : BaseBiometryService
{
	/// <summary>
	/// User facing description of the kind of authentication that the application is trying to perform.
	/// </summary>
	/// <remarks>
	/// Set this value to a string that will be displayed to the user when the authentication takes place for the item to give the user some context for the request.
	/// Only used for <see cref="BiometryType.Fingerprint"/>.
	/// </remarks>
	private readonly string _useOperationPrompt;

	private readonly LAContext _laContext;

	/// <summary>
	/// Authentication policies.
	/// </summary>
	private readonly LAPolicy _localAuthenticationPolicy;

	private readonly bool _fallbackOnPasscodeAuthentication = false;

	/// <summary>
	/// Initializes a new instance of the <see cref="BiometryService" /> class.
	/// </summary>
	/// <param name="useOperationPrompt">Biometry user facing description when using <see cref="BiometryType.Fingerprint"/>.</param>
	/// <param name="laContext"><see cref="LAContext" />.</param>
	/// <param name="localAuthenticationPolicy"><see cref="LAPolicy"/>.</param>
	/// <param name="loggerFactory"><see cref="ILoggerFactory"/>.</param>
	public BiometryService(
		string useOperationPrompt,
		LAContext laContext = null,
		LAPolicy localAuthenticationPolicy = LAPolicy.DeviceOwnerAuthentication,
		ILoggerFactory loggerFactory = null
	) : base(loggerFactory)
	{
		_useOperationPrompt = useOperationPrompt;
		_laContext = laContext ?? new LAContext();
		_localAuthenticationPolicy = localAuthenticationPolicy;
	}

	/// <inheritdoc/>
	public override Task<BiometryCapabilities> GetCapabilities(CancellationToken ct)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug("Assessing biometry capabilities.");
		}

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
			var status = (LAStatus)(long)laError.Code;
			switch (status)
			{
				case LAStatus.BiometryNotAvailable:
				case LAStatus.BiometryNotEnrolled:
					biometryIsEnabled = false;
					break;
				case LAStatus.PasscodeNotSet:
					passcodeIsSet = false;
					biometryIsEnabled = false;
					break;
				default:
					throw new BiometryException(BiometryExceptionReason.Failed, $"Unknown or unmanaged error occured during policy evaluation. Status '{status}'.");
			}
		}

		if (Logger.IsEnabled(LogLevel.Information))
		{
			Logger.LogDebug("Biometry capabilities has been successfully assessed.");
		}

		return Task.FromResult(new BiometryCapabilities(biometryType, biometryIsEnabled, passcodeIsSet));
	}

	/// <inheritdoc/>
	public override async Task ScanBiometry(CancellationToken ct)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug("Scanning biometry.");
		}

		if (_laContext.BiometryType is LABiometryType.FaceId)
		{
			if (Logger.IsEnabled(LogLevel.Trace))
			{
				Logger.LogTrace("Checks that `Info.plist` file contains NSFaceIDUsageDescription.");
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
			if (Logger.IsEnabled(LogLevel.Information))
			{
				Logger.LogDebug("Biometry has been successfully scanned.");
			}
		}
	}

	/// <inheritdoc/>
	public override async Task Encrypt(CancellationToken ct, string key, string value)
	{
		try
		{
			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("Encrypting the key '{key}'.", key);
			}

			await ValidateBiometryCapabilities(ct);

			SetValueForKey(key, value);

			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("The key '{key}' has been successfully encrypted.", key);
			}
		}
		catch
		{
			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("The key '{key}' has not been successfully encrypted.", key);
			}
			throw;
		}
	}

	/// <inheritdoc/>
	public override async Task<string> Decrypt(CancellationToken ct, string key)
	{
		try
		{
			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("Decrypting the key '{key}'.", key);
			}

			await ValidateBiometryCapabilities(ct);

			var value = GetValueForKey(key);

			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("The key '{key}' has been successfully decrypted.", key);
			}

			return value;
		}
		catch
		{
			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("The key '{key}' has not been successfully decrypted.", key);
			}
			throw;
		}
	}

	/// <inheritdoc/>
	public override void Remove(string key)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug("Removing the key '{key}'.", key);
		}

		var record = new SecRecord(SecKind.GenericPassword)
		{
			Service = key.ToLowerInvariant(),
			UseOperationPrompt = _useOperationPrompt
		};

		var status = SecKeyChain.Remove(record);
		if (status is not SecStatusCode.Success)
		{
			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("The key '{key}' has not been successfully removed. Status = {status}.", key, status);
			}
			throw new BiometryException(BiometryExceptionReason.Failed, $"Something went wrong while removing the key '{key}'. Status = {status}.");
		}

		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug("The key '{key}' has been successfully removed.", key);
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
	/// <param name="key">The key name.</param>
	/// <param name="value">The key value.</param>
	/// <exception cref="BiometryException">.</exception>
	private void SetValueForKey(string key, string value)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug("Saving the key '{key}'.", key);
		}

		var record = new SecRecord(SecKind.GenericPassword)
		{
			Service = key.ToLowerInvariant(),
		};

		// Check for duplicate key.
		var status = SecKeyChain.Remove(record);
		if (status is SecStatusCode.Success || status is SecStatusCode.ItemNotFound)
		{
			// Set biometry type to access the key.
			record.AccessControl = new SecAccessControl(
				SecAccessible.WhenPasscodeSetThisDeviceOnly,
				_fallbackOnPasscodeAuthentication ? SecAccessControlCreateFlags.UserPresence : SecAccessControlCreateFlags.BiometryCurrentSet
			);

			record.Generic = NSData.FromString(value);

			var result = SecKeyChain.Add(record);
			if (result is not SecStatusCode.Success)
			{
				throw new BiometryException(BiometryExceptionReason.Failed, $"Something went wrong while saving the key '{key}'. Status = {result}.");
			}

			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("Successfully saved the key '{key}'.", key);
			}
		}
		else
		{
			throw new BiometryException(BiometryExceptionReason.Failed, $"Something went wrong while checking for duplicate key '{key}'. Status = {status}.");
		}
	}

	/// <summary>
	/// Get the encrypted value for the key using biometry.
	/// </summary>
	/// <param name="key">The key name.</param>
	/// <returns>Key value.</returns>
	/// <exception cref="BiometryException">.</exception>
	/// <exception cref="OperationCanceledException">.</exception>
	private string GetValueForKey(string key)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug("Retrieving the key '{key}'.", key);
		}

		var record = new SecRecord(SecKind.GenericPassword)
		{
			Service = key.ToLowerInvariant(),
			UseOperationPrompt = _useOperationPrompt
		};

		var keyResult = SecKeyChain.QueryAsRecord(record, out var result);

		if (result is SecStatusCode.Success)
		{
			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("Successfully retrieved value of the key '{key}'.", key);
			}
			return keyResult.Generic.ToString();
		}

		var reason = BiometryExceptionReason.Failed;
		var message = $"Something went wrong while retrieving value of the key '{key}'.";

		switch (result)
		{
			case SecStatusCode.AuthFailed:
				reason = BiometryExceptionReason.Failed;
				message = $"Authentication failed. Could not retrieve value of the key '{key}'.";
				break;
			case SecStatusCode.ItemNotFound:
				message = $"Key '{key}' not found.";
				reason = BiometryExceptionReason.KeyInvalidated;
				break;
			case SecStatusCode.UserCanceled:
				throw new OperationCanceledException();
		}

		if (Logger.IsEnabled(LogLevel.Error))
		{
			Logger.LogError(message);
		}
		throw new BiometryException(reason, message);
	}
}
#endif
