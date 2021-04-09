#if __ANDROID__
using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Android.Content;
using Android.Security.Keystore;
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
		private const string ANDROID_KEYSTORE = "AndroidKeyStore";
		private const string CIPHER_NAME = "AES/CBC/PKCS7Padding";
		private const string CRYPTO_OBJECT_KEY_NAME = "BiometricService.UserAuthentication.Services.FingerprintService.CryptoObject";
		private const string CURVE_NAME = "secp256r1";
		private const string SIGNATURE_NAME = "SHA256withECDSA";

		private readonly BiometricPrompt _biometricPrompt;
		private readonly BiometricManager _biometricManager;
		private readonly FuncAsync<BiometricPrompt.PromptInfo> _promptInfoBuilder;
		private readonly KeyStore _keyStore;

		private readonly CoreDispatcher _dispatcher;
		private readonly AsyncLock _asyncLock = new AsyncLock();
		private TaskCompletionSource<BiometricPrompt.AuthenticationResult> _authenticationCompletionSource;

		/// <summary>
		///     Initializes a new instance of the <see cref="BiometryService" /> class.
		/// </summary>
		/// <param name="fragmentActivity"></param>
		/// <param name="applicationContext"></param>
		/// <param name="dispatcher"></param>
		/// <param name="promptInfoBuilder"></param>
		public BiometryService(
			FragmentActivity fragmentActivity,
			Context applicationContext,
			CoreDispatcher dispatcher,
			FuncAsync<BiometricPrompt.PromptInfo> promptInfoBuilder)
		{
		
			fragmentActivity.Validation().NotNull(nameof(fragmentActivity));
			_dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
			_promptInfoBuilder = promptInfoBuilder ?? throw new ArgumentNullException(nameof(promptInfoBuilder));

			var executor = ContextCompat.GetMainExecutor(applicationContext);
			var callback = new AuthenticationCallback(OnAuthenticationSucceeded, OnAuthenticationFailed, OnAuthenticationError);

			_biometricPrompt = new BiometricPrompt(fragmentActivity, executor, callback);
			_biometricManager = BiometricManager.From(applicationContext);

			_keyStore = KeyStore.GetInstance(ANDROID_KEYSTORE);
			_keyStore.Load(null);
		}

		/// <summary>
		///     Authenticate the user using biometrics.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <returns>A <see cref="BiometryResult" /> enum value.</returns>
		public async Task<BiometryResult> ValidateIdentity(CancellationToken ct)
		{
			using (await _asyncLock.LockAsync(ct))
			{
				var response = await AuthenticateAndProcess(ct, CRYPTO_OBJECT_KEY_NAME);

				var result = new BiometryResult();
				return result;
			}
		}

		/// <summary>
		///     Decodes the array of byte data to a string value
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="keyName"></param>
		/// <param name="data"></param>
		/// <returns>A string</returns>
		public async Task<string> Decrypt(CancellationToken ct, string keyName, byte[] data)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Decrypting the fingerprint for the key '{keyName}'.");
			}

			keyName.Validation().NotNullOrEmpty(nameof(keyName));
			data.Validation().NotNull(nameof(data));

			using (await _asyncLock.LockAsync(ct))
			{
				var iv = data.ToRangeArray(0, 16);
				var buffer = data.ToRangeArray(16, int.MaxValue);

				var crypto = BuildSymmetricCryptoObject(keyName, CIPHER_NAME, CipherMode.DecryptMode, iv);
				var result = await AuthenticateAndProcess(ct, keyName, crypto) ?? throw new System.OperationCanceledException();
				var decryptedData = result.CryptoObject.Cipher.DoFinal(buffer);

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Succcessfully decrypted the fingerprint for the key '{keyName}'.");
				}

				return Encoding.ASCII.GetString(decryptedData);
			}
		}

		/// <summary>
		///     Encrypt the string value to an array of byte data
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="keyName"></param>
		/// <param name="value"></param>
		/// <returns>An array of byte</returns>
		public async Task<byte[]> Encrypt(CancellationToken ct, string keyName, string value)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Encrypting the fingerprint for the key '{keyName}'.");
			}

			keyName.Validation().NotNullOrEmpty(nameof(keyName));
			value.Validation().NotNull(nameof(value));

			using (await _asyncLock.LockAsync(ct))
			{
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

				return bytes;
			}
		}

		/// <summary>
		///     Gets the device's current biometric capabilities.
		/// </summary>
		/// <returns>A <see cref="BiometryCapabilities" /> struct instance.</returns>
		public BiometryCapabilities GetCapabilities()
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

			return new BiometryCapabilities(BiometryType.FaceOrFingerprint, _isEnabled, devicePinAvailable);

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

			//TODO parameterize BiometricManager.Authenticators for CanAuthenticate
			var result = _biometricManager.CanAuthenticate(BiometricManager.Authenticators.BiometricWeak);
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
					_authenticationCompletionSource.TrySetException(new AuthenticationError(code, message));
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