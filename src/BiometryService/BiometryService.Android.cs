#if __ANDROID__
using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Security.Keystore;
using Android.Util;
using AndroidX.Biometric;
using AndroidX.Core.Content;
using AndroidX.Fragment.App;
using Java.Lang;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace BiometryService;

/// <summary>
/// Implementation of the <see cref="IBiometryService" /> for Android.
/// </summary>
public sealed class BiometryService : BaseBiometryService
{
	private const string ANDROID_KEYSTORE = "AndroidKeyStore"; // Android constant, cannot be changed.
	private const string CIPHER_NAME = "AES/CBC/PKCS7Padding";
	private const string PREFERENCE_NAME = "BiometricPreferences";

	private readonly FragmentActivity _activity;
	private readonly Func<BiometricPrompt.PromptInfo> _promptInfoBuilder;
	private readonly Context _applicationContext;
	private readonly BiometricManager _biometricManager;
	private readonly KeyStore _keyStore;

	private TaskCompletionSource<BiometricPrompt.AuthenticationResult> _authenticationCompletionSource;

	/// <summary>
	/// Initializes a new instance of the <see cref="BiometryService" /> class.
	/// </summary>
	/// <param name="fragmentActivity"><see cref="FragmentActivity"/>.</param>
	/// <param name="promptInfoBuilder">Biometry configuration.</param>
	/// <param name="loggerFactory"><see cref="ILoggerFactory"/>.</param>
	public BiometryService(
		FragmentActivity fragmentActivity,
		Func<BiometricPrompt.PromptInfo> promptInfoBuilder,
		ILoggerFactory loggerFactory = null
	) : base(loggerFactory)
	{
		_activity = fragmentActivity ?? throw new ArgumentNullException(nameof(fragmentActivity));
		_promptInfoBuilder = promptInfoBuilder ?? throw new ArgumentNullException(nameof(promptInfoBuilder));

		_applicationContext = Application.Context;
		_biometricManager = BiometricManager.From(_applicationContext);

		_keyStore = KeyStore.GetInstance(ANDROID_KEYSTORE);
		_keyStore.Load(null);
	}

	/// <inheritdoc/>
	public override Task<BiometryCapabilities> GetCapabilities(CancellationToken ct)
	{
		var biometryType = BiometryType.None;

		if (_activity.PackageManager.HasSystemFeature(PackageManager.FeatureFingerprint))
		{
			biometryType |= BiometryType.Fingerprint;
		}

		if (_activity.PackageManager.HasSystemFeature(PackageManager.FeatureFace))
		{
			biometryType |= BiometryType.Face;
		}

		var isEnabled = _biometricManager.CanAuthenticate(BiometricManager.Authenticators.BiometricStrong) == BiometricManager.BiometricSuccess;
		var devicePinAvailable = _biometricManager.CanAuthenticate(BiometricManager.Authenticators.DeviceCredential) == BiometricManager.BiometricSuccess;

		return Task.FromResult(new BiometryCapabilities(biometryType, isEnabled, devicePinAvailable));
	}

	/// <inheritdoc/>
	public override async Task ScanBiometry(CancellationToken ct)
	{
		await AuthenticateBiometry(ct);
	}

	/// <inheritdoc/>
	public override async Task Encrypt(CancellationToken ct, string key, string value)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug($"Encrypting the fingerprint for the key '{key}'.");
		}

		await ValidateBiometryCapabilities(ct);

		var crypto = CreateCryptoObject(key);
		var result = await AuthenticateBiometry(ct, crypto);
		var valueToEncrypt = Encoding.UTF8.GetBytes(value);
		var encryptedData = result.CryptoObject.Cipher.DoFinal(valueToEncrypt);
		var iv = result.CryptoObject.Cipher.GetIV();

		var bytes = new byte[iv.Length + encryptedData.Length];
		iv.CopyTo(bytes, 0);
		encryptedData.CopyTo(bytes, iv.Length);

		if (Logger.IsEnabled(LogLevel.Information))
		{
			Logger.LogInformation($"Succcessfully encrypted the fingerprint for the key '{key}'.");
		}

		var encodedData = Base64.EncodeToString(bytes, Base64Flags.NoWrap);
		var sharedpref = _applicationContext.GetSharedPreferences(PREFERENCE_NAME, FileCreationMode.Private);
		sharedpref.Edit().PutString(key, encodedData).Apply();
	}

	/// <inheritdoc/>
	public override async Task<string> Decrypt(CancellationToken ct, string key)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug($"Decrypting the fingerprint for the key '{key}'.");
		}

		await ValidateBiometryCapabilities(ct);

		var sharedpref = _applicationContext.GetSharedPreferences(PREFERENCE_NAME, FileCreationMode.Private);
		var storedData = sharedpref.GetString(key, null);

		if (storedData == null)
		{
			throw new BiometryException(BiometryExceptionReason.KeyInvalidated, "Encrypted values could not be found. It may have been removed.");
		}

		byte[] data = Base64.Decode(storedData, Base64Flags.NoWrap);

		var iv = new byte[16];
		Array.ConstrainedCopy(
			data,
			0,
			iv,
			0,
			16
		);

		var buffer = new byte[data.Length - 16];
		Array.ConstrainedCopy(
			data,
			16,
			buffer,
			0,
			data.Length - 16
		);

		var crypto = GetCryptoObject(key, iv);
		var result = await AuthenticateBiometry(ct, crypto);
		var decryptedData = result.CryptoObject.Cipher.DoFinal(buffer);

		if (Logger.IsEnabled(LogLevel.Information))
		{
			Logger.LogInformation($"Succcessfully decrypted the fingerprint for the key '{key}'.");
		}

		return Encoding.ASCII.GetString(decryptedData);
	}

	/// <inheritdoc/>
	public override void Remove(string key)
	{
		try
		{
			var sharedpref = _applicationContext.GetSharedPreferences(PREFERENCE_NAME, FileCreationMode.Private);
			sharedpref.Edit().Remove(key).Apply();

			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("The key '{key}' has been successfully removed.", key);
			}
		}
		catch (System.Exception)
		{
			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("The key '{key}' has not been successfully removed.", key);
			}
			throw new BiometryException(BiometryExceptionReason.Failed, $"Something went wrong while removing the key '{key}'.");
		}
	}

	private async Task<BiometricPrompt.AuthenticationResult> AuthenticateBiometry(CancellationToken ct, BiometricPrompt.CryptoObject crypto = null)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug($"Start authenticating the user biometry.");
		}

		// TODO: Refactor this. Why are we doing a version check? Could we juste use the parameter used by the user isntead of BiometricManager.Authenticators.BiometricStrong?
		var authenticateCode = _biometricManager.CanAuthenticate(BiometricManager.Authenticators.BiometricStrong);
		if (Android.OS.Build.VERSION.SdkInt <= Android.OS.BuildVersionCodes.Q)
		{
			authenticateCode = _biometricManager.CanAuthenticate();
		}
		else
		{
			authenticateCode = _biometricManager.CanAuthenticate(BiometricManager.Authenticators.BiometricStrong);
		}

		if (authenticateCode == BiometricManager.BiometricSuccess)
		{
			return await PromptBiometryAuthentication(ct, crypto);
		}

		if (Logger.IsEnabled(LogLevel.Error))
		{
			Logger.LogError($"The device cannot authenticate with biometry.");
		}

		var reason = BiometryExceptionReason.Failed;
		var message = string.Empty;

		switch (authenticateCode)
		{
			case BiometricManager.BiometricErrorNoneEnrolled:
				reason = BiometryExceptionReason.NotEnrolled;
				message = "No biometric(s) registered.";
				break;
			case BiometricManager.BiometricErrorNoHardware:
			case BiometricManager.BiometricErrorHwUnavailable:
			case BiometricManager.BiometricErrorSecurityUpdateRequired:
			case BiometricManager.BiometricErrorUnsupported:
				reason = BiometryExceptionReason.Unavailable;
				message = $"Biometric is not available. Code = {authenticateCode}";
				break;
			default:
				message = $"Something went wrong. Code = {authenticateCode}";
				break;
		}

		throw new BiometryException(reason, message);
	}

	private async Task<BiometricPrompt.AuthenticationResult> PromptBiometryAuthentication(CancellationToken ct, BiometricPrompt.CryptoObject crypto = null)
	{
		_authenticationCompletionSource = new TaskCompletionSource<BiometricPrompt.AuthenticationResult>();

		// Prepare and show UI.
		var callback = new AuthenticationCallback(_authenticationCompletionSource, Logger);
		var executor = ContextCompat.GetMainExecutor(_applicationContext);
		var biometricPrompt = new BiometricPrompt(_activity, executor, callback);

		var prompt = _promptInfoBuilder();
		_activity.RunOnUiThread(() =>
		{
			try
			{
				if (crypto == null)
				{
					biometricPrompt.Authenticate(prompt);
				}
				else
				{
					biometricPrompt.Authenticate(prompt, crypto);
				}
			}
			catch (System.Exception e)
			{
				_authenticationCompletionSource.TrySetException(e);
			}
		});

		var authenticationTask = _authenticationCompletionSource.Task;
		using (ct.Register(() => _authenticationCompletionSource.TrySetCanceled()))
		{
			await authenticationTask;
		}

		if (authenticationTask.IsCompletedSuccessfully)
		{
			if (Logger.IsEnabled(LogLevel.Information))
			{
				Logger.LogInformation($"Successfully authenticated and processed the biometric).");
			}

			return authenticationTask.Result;
		}
		else
		{
			if (authenticationTask.IsCanceled)
			{
				throw new OperationCanceledException();
			}

			throw new BiometryException(BiometryExceptionReason.Failed, "Something went wrong while attempting to complete biometry authentication");
		}
	}

	private BiometricPrompt.CryptoObject CreateCryptoObject(string key)
	{
		var cipher = Cipher.GetInstance(CIPHER_NAME);

		if (_keyStore.IsKeyEntry(key))
		{
			_keyStore.DeleteEntry(key);
		}

		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug($"Generating a symmetric pair (key name: '{key}').");
		}

		var keygen = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, ANDROID_KEYSTORE);

		keygen.Init(new KeyGenParameterSpec.Builder(key, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
			.SetBlockModes(KeyProperties.BlockModeCbc)
			.SetEncryptionPaddings(KeyProperties.EncryptionPaddingPkcs7)
			.SetUserAuthenticationRequired(true)
			.SetInvalidatedByBiometricEnrollment(true) // https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment(boolean)
			.Build()
		);

		keygen.GenerateKey();

		if (Logger.IsEnabled(LogLevel.Information))
		{
			Logger.LogInformation($"Successfully generated a symmetric pair (key name: '{key}').");
		}

		cipher.Init(CipherMode.EncryptMode, _keyStore.GetKey(key, null));

		return new BiometricPrompt.CryptoObject(cipher);
	}

	private BiometricPrompt.CryptoObject GetCryptoObject(string key, byte[] iv = null)
	{
		var cipher = Cipher.GetInstance(CIPHER_NAME);

		if (_keyStore.IsKeyEntry(key))
		{
			try
			{
				cipher.Init(CipherMode.DecryptMode, _keyStore.GetKey(key, null), new IvParameterSpec(iv));

				return new BiometricPrompt.CryptoObject(cipher);
			}
			catch (KeyPermanentlyInvalidatedException)
			{
				if (Logger.IsEnabled(LogLevel.Error))
				{
					Logger.LogError($"Key '{key}' has been permanently invalidated.");
				}

				_keyStore.DeleteEntry(key);

				if (Logger.IsEnabled(LogLevel.Information))
				{
					Logger.LogInformation($"Permanently invalidated key '{key}' has been removed successfully.");
				}

				throw new BiometryException(BiometryExceptionReason.KeyInvalidated, "Something went wrong while generating the CryptoObject used to decrypt.");
			}
		}
		else
		{
			if (Logger.IsEnabled(LogLevel.Error))
			{
				Logger.LogError($"Key '{key}' not found.");
			}
			throw new BiometryException(BiometryExceptionReason.KeyInvalidated, $"Key '{key}' not found.");
		}
	}

	private class AuthenticationCallback : BiometricPrompt.AuthenticationCallback
	{
		private readonly TaskCompletionSource<BiometricPrompt.AuthenticationResult> _tcs;
		private readonly ILogger Logger;

		public AuthenticationCallback(TaskCompletionSource<BiometricPrompt.AuthenticationResult> tcs, ILogger logger)
		{
			_tcs = tcs;
			Logger = logger;
		}

		public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result)
		{
			if (Logger.IsEnabled(LogLevel.Information))
			{
				Logger.LogInformation("User attempt to use biometry succeeded.");
			}

			_tcs.TrySetResult(result);
		}

		public override void OnAuthenticationFailed()
		{
			// This methods is called after an attempt to use biometry.
			// It does not means that it will close the prompt yet.

			if (Logger.IsEnabled(LogLevel.Warning))
			{
				Logger.LogWarning("User attempt to use biometry failed.");
			}
		}

		public override void OnAuthenticationError(int errMsgId, ICharSequence errString)
		{
			var reason = BiometryExceptionReason.Failed;
			switch (errMsgId)
			{
				// Prompt has been cancelled.
				case BiometricPrompt.ErrorNegativeButton:
				case BiometricPrompt.ErrorUserCanceled:
				case BiometricPrompt.ErrorCanceled:
					// Use .NET cancelled exception instead.
					_tcs.SetCanceled();
					return;
				// Error due to biometric not being available.
				case BiometricPrompt.ErrorHwUnavailable:
				case BiometricPrompt.ErrorHwNotPresent:
				case BiometricPrompt.ErrorSecurityUpdateRequired:
				case BiometricPrompt.ErrorVendor:
					reason = BiometryExceptionReason.Unavailable;
					break;
				// Error due to biometric not being enrolled.
				case BiometricPrompt.ErrorNoBiometrics:
					reason = BiometryExceptionReason.NotEnrolled;
					break;
				// Error due to passcode is needed.
				case BiometricPrompt.ErrorNoDeviceCredential:
					reason = BiometryExceptionReason.PasscodeNeeded;
					break;
				// Error due to being locked.
				case BiometricPrompt.ErrorLockout:
				case BiometricPrompt.ErrorLockoutPermanent:
					reason = BiometryExceptionReason.Locked;
					break;
			}

			var message = errString?.ToString() ?? $"Biometry authentication failed with errMsgId = {errMsgId}";
			_tcs.TrySetException(new BiometryException(reason, message));
		}
	}
}
#endif
