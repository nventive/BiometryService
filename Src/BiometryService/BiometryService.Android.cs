#if __ANDROID__
using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Android.App;
using Android.Content;
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
using Uno;
using Uno.Extensions;
using Uno.Logging;
using Uno.Threading;
using Windows.UI.Core;

namespace BiometryService
{
	/// <summary>
	///     Implementation of the <see cref="IBiometryService" /> for Android.
	/// </summary>
	public class BiometryService : IBiometryService
	{
		private const string ANDROID_KEYSTORE = "AndroidKeyStore"; //Android constant, cannot be changed
		private const string CIPHER_NAME = "AES/CBC/PKCS7Padding";
		private const string CRYPTO_OBJECT_KEY_NAME = "BiometricService.UserAuthentication.Services.FingerprintService.CryptoObject";
		private const string CURVE_NAME = "secp256r1";
		private const string SIGNATURE_NAME = "SHA256withECDSA";
		private const string PREFERENCE_NAME = "BiometricPreferences";

		private readonly BiometricPrompt _biometricPrompt;
		private readonly BiometricManager _biometricManager;
		private readonly FuncAsync<BiometricPrompt.PromptInfo> _promptInfoBuilder;
		private readonly KeyStore _keyStore;

		private readonly CoreDispatcher _dispatcher;
		private readonly AsyncLock _asyncLock = new AsyncLock();
		private TaskCompletionSource<BiometricPrompt.AuthenticationResult> _authenticationCompletionSource;
		private readonly Context _applicationContext;

		/// <summary>
		///     Initializes a new instance of the <see cref="BiometryService" /> class.
		/// </summary>
		/// <param name="fragmentActivity"></param>
		/// <param name="dispatcher"></param>
		/// <param name="promptInfoBuilder"></param>
		/// <param name="authenticators"></param>
		public BiometryService(
			FragmentActivity fragmentActivity,
			CoreDispatcher dispatcher,
			FuncAsync<BiometricPrompt.PromptInfo> promptInfoBuilder)
		{

			fragmentActivity.Validation().NotNull(nameof(fragmentActivity));
			_dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
			_promptInfoBuilder = promptInfoBuilder ?? throw new ArgumentNullException(nameof(promptInfoBuilder));

			_applicationContext = Application.Context;
			var executor = ContextCompat.GetMainExecutor(_applicationContext);
			var callback = new AuthenticationCallback(OnAuthenticationSucceeded, OnAuthenticationFailed, OnAuthenticationError);

			_biometricPrompt = new BiometricPrompt(fragmentActivity, executor, callback);
			_biometricManager = BiometricManager.From(_applicationContext);

			_keyStore = KeyStore.GetInstance(ANDROID_KEYSTORE);
			_keyStore.Load(null);

		}

		/// <summary>
		///     Validate the user identity.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <returns>A <see cref="BiometryResult" /> enum value.</returns>
		public async Task<BiometryResult> ValidateIdentity(CancellationToken ct)
		{
			var response = await AuthenticateAndProcess(ct, CRYPTO_OBJECT_KEY_NAME);

			var result = new BiometryResult();

			if (response.AuthenticationType == 0) //BiometryAuthenticationResult.Granted
			{
				result.AuthenticationResult = BiometryAuthenticationResult.Granted;
			}
			else if (response.AuthenticationType == 1) //BiometryAuthenticationResult.Denied
			{
				result.AuthenticationResult = BiometryAuthenticationResult.Denied;
			}
			else if (response.AuthenticationType == 2) //BiometryAuthenticationResult.Cancelled
			{
				result.AuthenticationResult = BiometryAuthenticationResult.Cancelled;
			}

			return result;
		}

		/// <summary>
		///     Retrieve and decrypt data associated to the key.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="key">The key for the value.</param>
		/// <returns>A string</returns>
		public async Task<string> Decrypt(CancellationToken ct, string key)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Decrypting the fingerprint for the key '{key}'.");
			}
			key.Validation().NotNullOrEmpty(nameof(key));

			var sharedpref = _applicationContext.GetSharedPreferences(PREFERENCE_NAME, FileCreationMode.Private);
			var storedData = sharedpref.GetString(key, null);

			byte[] data = Base64.Decode(storedData, Base64Flags.NoWrap);

			var iv = data.ToRangeArray(0, 16);
			var buffer = data.ToRangeArray(16, int.MaxValue);

			var crypto = BuildSymmetricCryptoObject(key, CIPHER_NAME, CipherMode.DecryptMode, iv);
			var result = await AuthenticateAndProcess(ct, key, crypto) ?? throw new System.OperationCanceledException();
			var decryptedData = result.CryptoObject.Cipher.DoFinal(buffer);

			if (this.Log().IsEnabled(LogLevel.Information))
			{
				this.Log().Info($"Succcessfully decrypted the fingerprint for the key '{key}'.");
			}

			return Encoding.ASCII.GetString(decryptedData);
		}

		/// <summary>
		///     Retrieve and decrypt data associated to the key.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="key">The key for the value.</param>
		/// <param name="value">To be decrypt.</param>
		/// <returns>A string</returns>
		public async Task<string> Decrypt(CancellationToken ct, string key, string value)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Decrypting the fingerprint for the key '{key}'.");
			}

			key.Validation().NotNullOrEmpty(nameof(key));
			key.Validation().NotNullOrEmpty(nameof(value));

			byte[] data = Base64.Decode(value, Base64Flags.NoWrap);

			var iv = data.ToRangeArray(0, 16);
			var buffer = data.ToRangeArray(16, int.MaxValue);

			var crypto = BuildSymmetricCryptoObject(key, CIPHER_NAME, CipherMode.DecryptMode, iv);
			var result = await AuthenticateAndProcess(ct, key, crypto) ?? throw new System.OperationCanceledException();
			var decryptedData = result.CryptoObject.Cipher.DoFinal(buffer);

			if (this.Log().IsEnabled(LogLevel.Information))
			{
				this.Log().Info($"Succcessfully decrypted the fingerprint for the key '{key}'.");
			}

			return Encoding.ASCII.GetString(decryptedData);
		}

		/// <summary>
		///     Encrypt the value and store the key into the keytore.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="keyName">The key for the value.</param>
		/// <param name="value">A string value to encrypt.</param>
		/// <returns>A string</returns>
		public async Task Encrypt(CancellationToken ct, string keyName, string value)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Encrypting the fingerprint for the key '{keyName}'.");
			}

			keyName.Validation().NotNullOrEmpty(nameof(keyName));
			value.Validation().NotNull(nameof(value));


			var crypto = BuildSymmetricCryptoObject(keyName, CIPHER_NAME, CipherMode.EncryptMode);
			var result = await AuthenticateAndProcess(ct, keyName, crypto) ?? throw new System.OperationCanceledException();
			var encryptedData = result.CryptoObject.Cipher.DoFinal(Encoding.ASCII.GetBytes(value));
			var iv = result.CryptoObject.Cipher.GetIV();

			var bytes = new byte[iv.Length + encryptedData.Length];
			iv.CopyTo(bytes, 0);
			encryptedData.CopyTo(bytes, iv.Length);

			if (this.Log().IsEnabled(LogLevel.Information))
			{
				this.Log().Info($"Succcessfully encrypted the fingerprint for the key'{keyName}'.");
			}

			string encodedData = Base64.EncodeToString(bytes, Base64Flags.NoWrap);
			var sharedpref = _applicationContext.GetSharedPreferences(PREFERENCE_NAME, FileCreationMode.Private);
			sharedpref.Edit().PutString(keyName, encodedData).Apply();
		}

		/// <summary>
		///     Encrypt the value and store the key into the keytore.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="keyName">The key for the value.</param>
		/// <param name="value">A string value to encrypt.</param>
		/// <returns>A string</returns>
		public async Task<string> EncryptAndReturn(CancellationToken ct, string keyName, string value)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Encrypting the fingerprint for the key '{keyName}'.");
			}

			keyName.Validation().NotNullOrEmpty(nameof(keyName));
			value.Validation().NotNull(nameof(value));

			var crypto = BuildSymmetricCryptoObject(keyName, CIPHER_NAME, CipherMode.EncryptMode);
			var result = await AuthenticateAndProcess(ct, keyName, crypto) ?? throw new System.OperationCanceledException();
			var encryptedData = result.CryptoObject.Cipher.DoFinal(Encoding.ASCII.GetBytes(value));
			var iv = result.CryptoObject.Cipher.GetIV();

			var bytes = new byte[iv.Length + encryptedData.Length];
			iv.CopyTo(bytes, 0);
			encryptedData.CopyTo(bytes, iv.Length);

			if (this.Log().IsEnabled(LogLevel.Information))
			{
				this.Log().Info($"Succcessfully encrypted the fingerprint for the key'{keyName}'.");
			}

			return Base64.EncodeToString(bytes, Base64Flags.NoWrap);
		}

		/// <summary>
		///     Gets the device's current biometric capabilities.
		/// </summary>
		/// <returns>A <see cref="BiometryCapabilities" /> struct instance.</returns>
		public Task<BiometryCapabilities> GetCapabilities()
		{
			bool _isEnabled = false;
			switch (_biometricManager.CanAuthenticate(BiometricManager.Authenticators.BiometricStrong))
			{
				case BiometricManager.BiometricSuccess:
					_isEnabled = true;
					break;
				case BiometricManager.BiometricErrorNoHardware:
					_isEnabled = false;
					break;
				case BiometricManager.BiometricErrorNoneEnrolled:
					_isEnabled = false;
					break;
				case BiometricManager.BiometricErrorSecurityUpdateRequired:
					_isEnabled = false;
					break;
				default:
					break;
			}
			bool devicePinAvailable = Convert.ToBoolean(_biometricManager.CanAuthenticate(BiometricManager.Authenticators.DeviceCredential));

			return Task.Run(() =>
			{
				return new BiometryCapabilities(BiometryType.FaceOrFingerprint, _isEnabled, devicePinAvailable);
			});
		}

		private BiometricPrompt.CryptoObject BuildSymmetricCryptoObject(string keyName, string cipherName, CipherMode mode, byte[] iv = null)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Building a symmetric crypto object (key name: '{keyName}', mode: '{mode}').");
			}

			var cipher = Cipher.GetInstance(cipherName);

			if (_keyStore.IsKeyEntry(keyName))
			{
				if (mode == CipherMode.EncryptMode)
				{
					_keyStore.DeleteEntry(keyName);
				}
				else if (mode == CipherMode.DecryptMode)
				{
					try
					{
						cipher.Init(mode, _keyStore.GetKey(keyName, null), new IvParameterSpec(iv));

						return new BiometricPrompt.CryptoObject(cipher);
					}
					catch (KeyPermanentlyInvalidatedException)
					{
						_keyStore.DeleteEntry(keyName);

						throw;
					}
				}
			}
			else if (mode == CipherMode.DecryptMode)
			{
				throw new ArgumentException("Key not found.");
			}

			GenerateSymmetricKey(keyName);

			cipher.Init(mode, _keyStore.GetKey(keyName, null));

			if (this.Log().IsEnabled(LogLevel.Information))
			{
				this.Log().Info($"Return the symmetric crypto object (key name: '{keyName}', mode: '{mode}').");
			}

			return new BiometricPrompt.CryptoObject(cipher);
		}


		private async Task<BiometricPrompt.AuthenticationResult> AuthenticateAndProcess(CancellationToken ct, string keyName, BiometricPrompt.CryptoObject crypto = null)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Authenticating and processing the fingerprint (key name: '{keyName}').");
			}

			int result = 0;
			if (Android.OS.Build.VERSION.SdkInt <= Android.OS.BuildVersionCodes.Q)
				result = _biometricManager.CanAuthenticate();
			else
				result = _biometricManager.CanAuthenticate(BiometricManager.Authenticators.BiometricStrong);

			if (result == BiometricManager.BiometricSuccess)
			{
				_authenticationCompletionSource = new TaskCompletionSource<BiometricPrompt.AuthenticationResult>();

				// Prepare and show UI
				var prompt = await _promptInfoBuilder(ct);
				await _dispatcher.RunAsync(CoreDispatcherPriority.High, () =>
				{
					try
					{
						if (crypto == null)
						{
							_biometricPrompt.Authenticate(prompt);
						}
						else
						{
							_biometricPrompt.Authenticate(prompt, crypto);
						}
					}
					catch (System.Exception e)
					{
						_authenticationCompletionSource.TrySetException(e);
					}
				});

				var authenticationTask = _authenticationCompletionSource.Task;
				await Task.WhenAny(authenticationTask);

				if (authenticationTask.IsCompletedSuccessfully && this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Successfully authenticated and processed the fingerprint (key name: '{keyName}').");
				}

				if (authenticationTask.IsCanceled)
				{
					throw new OperationCanceledException();
				}
				return authenticationTask.Result;
			}
			else
			{
				if (result == BiometricManager.BiometricErrorNoneEnrolled)
				{
					throw new InvalidOperationException("No fingerprint(s) registered.");
				}
				else
				{
					if (this.Log().IsEnabled(LogLevel.Warning))
					{
						this.Log().Warn($"Fingerprint authentication is not available.");
					}

					throw new NotSupportedException("Fingerprint authentication is not available.");
				}
			}
		}

		private class AuthenticationCallback : BiometricPrompt.AuthenticationCallback
		{
			private readonly Action<BiometricPrompt.AuthenticationResult> _onSuccess;
			private readonly Action _onFailure;
			private readonly Action<int, string> _onError;

			public AuthenticationCallback(Action<BiometricPrompt.AuthenticationResult> onSuccess, Action onFailure, Action<int, string> onError)
			{
				this._onSuccess = onSuccess;
				this._onFailure = onFailure;
				this._onError = onError;
			}

			public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) => _onSuccess(result);

			public override void OnAuthenticationFailed() => _onFailure();

			public override void OnAuthenticationError(int errMsgId, ICharSequence errString) => _onError(errMsgId, errString?.ToString());
		}

		private void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result)
		{
			_authenticationCompletionSource.TrySetResult(result);
		}

		private void OnAuthenticationFailed()
		{
		}

		private void OnAuthenticationError(int code, string message)
		{
			switch (code)
			{
				case BiometricPrompt.ErrorNegativeButton: // Prompt cancellation
				case BiometricPrompt.ErrorUserCanceled:
				case BiometricPrompt.ErrorCanceled:
					_authenticationCompletionSource.SetCanceled();
					return;
				default:
					_authenticationCompletionSource.TrySetException(new BiometryException(code, message));
					return;
			}
		}

		private void GenerateSymmetricKey(string keyName)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Generating a symmetric pair (key name: '{keyName}').");
			}

			var keygen = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, ANDROID_KEYSTORE);

			keygen.Init(new KeyGenParameterSpec.Builder(keyName, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
				.SetBlockModes(KeyProperties.BlockModeCbc)
				.SetEncryptionPaddings(KeyProperties.EncryptionPaddingPkcs7)
				.SetUserAuthenticationRequired(true)
				.Build()
			);

			keygen.GenerateKey();

			if (this.Log().IsEnabled(LogLevel.Information))
			{
				this.Log().Info($"Successfully generated a symmetric pair (key name: '{keyName}').");
			}
		}
	}
}
#endif