#if __ANDROID__
using System;
using System.Collections.Generic;
using System.Reactive;
using System.Reactive.Disposables;
using System.Reactive.Linq;
using System.Reactive.Subjects;
using System.Threading;
using System.Threading.Tasks;
using Android.App;
using Android.Content;
using Android.Security.Keystore;
using AndroidX.Biometry;
using AndroidX.Core.Content;
using AndroidX.Core.Hardware.Fingerprint;
using AndroidX.Core.OS;
using AndroidX.Fragment.App;
using Java.Lang;
using Java.Security;
using Java.Security.Spec;
using Javax.Crypto;
using Javax.Crypto.Spec;
using Microsoft.Extensions.Logging;
using Uno;
using Uno.Extensions;
using Uno.Logging;
using Uno.Threading;
using Windows.UI.Core;
using static System.Reactive.Concurrency.Scheduler;
using IScheduler = System.Reactive.Concurrency.IScheduler;

namespace BiometryService
{
	public class FingerprintService : IFingerprintService
	{
		private const string ANDROID_KEYSTORE = "AndroidKeyStore";
		private const string CIPHER_NAME = "AES/CBC/PKCS7Padding";
		private const string CRYPTO_OBJECT_KEY_NAME = "BiometryService.UserAuthentication.Services.FingerprintService.CryptoObject";
		private const string CURVE_NAME = "secp256r1";
		private const string SIGNATURE_NAME = "SHA256withECDSA";

		private readonly BiometryPrompt _BiometryPrompt;
		private readonly BiometryManager _BiometryManager;
		private readonly FuncAsync<BiometryPrompt.PromptInfo> _promptInfoBuilder;
		private readonly KeyStore _keyStore;

		private readonly CoreDispatcher _dispatcher;
		private readonly AsyncLock _asyncLock = new AsyncLock();
		private TaskCompletionSource<BiometryPrompt.AuthenticationResult> _authenticationCompletionSource;
		private IObservable<int> _canAuthenticate;

		public FingerprintService(
			FragmentActivity fragmentActivity,
			Context applicationContext,
			IObservable<Unit> applicationActivated,
			CoreDispatcher dispatcher,
			IScheduler backgroundScheduler,
			FuncAsync<BiometryPrompt.PromptInfo> promptInfoBuilder)
		{
			fragmentActivity.Validation().NotNull(nameof(fragmentActivity));
			applicationActivated.Validation().NotNull(nameof(applicationActivated));
			backgroundScheduler.Validation().NotNull(nameof(backgroundScheduler));
			_dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
			_promptInfoBuilder = promptInfoBuilder ?? throw new ArgumentNullException(nameof(promptInfoBuilder));

			var executor = ContextCompat.GetMainExecutor(applicationContext);
			var callback = new AuthenticationCallback(OnAuthenticationSucceeded, OnAuthenticationFailed, OnAuthenticationError);
			_BiometryPrompt = new BiometryPrompt(fragmentActivity, executor, callback);
			_BiometryManager = BiometryManager.From(Application.Context);

			_keyStore = KeyStore.GetInstance(ANDROID_KEYSTORE);
			_keyStore.Load(null);

			_canAuthenticate =
				applicationActivated
					.ObserveOn(backgroundScheduler)
					.StartWith(backgroundScheduler, Unit.Default)
					.Select(_ => _BiometryManager.CanAuthenticate())
					.Replay(1, backgroundScheduler)
					.RefCount();
		}

		private void OnAuthenticationSucceeded(BiometryPrompt.AuthenticationResult result)
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
				case BiometryPrompt.InterfaceConsts.ErrorUserCanceled:
				case BiometryPrompt.InterfaceConsts.ErrorNegativeButton:
					_authenticationCompletionSource.TrySetResult(null);
					return;

				default:
					_authenticationCompletionSource.TrySetException(new AuthenticationError(code, message));
					return;
			}
		}

		public async Task<bool> Authenticate(CancellationToken ct)
		{
			using (await _asyncLock.LockAsync(ct))
			{
				var result = await AuthenticateAndProcess(ct, CRYPTO_OBJECT_KEY_NAME);

				return result != null;
			}
		}

		private async Task<BiometryPrompt.AuthenticationResult> AuthenticateAndProcess(CancellationToken ct, string keyName, BiometryPrompt.CryptoObject crypto = null)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Authenticating and processing the fingerprint (key name: '{keyName}').");
			}

			var result = _BiometryManager.CanAuthenticate();
			if (result == BiometryManager.BiometrySuccess)
			{
				_authenticationCompletionSource = new TaskCompletionSource<BiometryPrompt.AuthenticationResult>();

				// Prepare and show UI
				var prompt = await _promptInfoBuilder(ct);
				await _dispatcher.RunAsync(CoreDispatcherPriority.High, () =>
				{
					try
					{
						if (crypto == null)
						{
							_BiometryPrompt.Authenticate(prompt);
						}
						else
						{
							_BiometryPrompt.Authenticate(prompt, crypto);
						}
					}
					catch (System.Exception e)
					{
						_authenticationCompletionSource.TrySetException(e);
					}
				});

				var authenticationTask = _authenticationCompletionSource.Task;
				await Task.WhenAny(authenticationTask);

				// Slight delay so the user sees the final result
				await Task.Delay(300);

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Successfully authenticated and processed the fingerprint (key name: '{keyName}').");
				}

				return authenticationTask.Result;
			}
			else
			{
				if (result == BiometryManager.BiometryErrorNoneEnrolled)
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

		private BiometryPrompt.CryptoObject BuildAsymmetricCryptoObject(string keyName, string signatureName)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Building asymmetric crypto object (key name: '{keyName}').");
			}

			var signature = Signature.GetInstance(signatureName);

			signature.InitSign(((KeyStore.PrivateKeyEntry)_keyStore.GetEntry(keyName, null)).PrivateKey);

			if (this.Log().IsEnabled(LogLevel.Information))
			{
				this.Log().Info($"Return the asymmetric crypto object  (key name: '{keyName}').");
			}

			return new BiometryPrompt.CryptoObject(signature);
		}

		private BiometryPrompt.CryptoObject BuildSymmetricCryptoObject(string keyName, string cipherName, CipherMode mode, byte[] iv = null)
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

						return new BiometryPrompt.CryptoObject(cipher);
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

			return new BiometryPrompt.CryptoObject(cipher);
		}

		public async Task<byte[]> Decrypt(CancellationToken ct, string keyName, byte[] data)
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

				return decryptedData;
			}
		}

		public async Task<byte[]> Encrypt(CancellationToken ct, string keyName, byte[] data)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Encrypting the fingerprint for the key '{keyName}'.");
			}

			keyName.Validation().NotNullOrEmpty(nameof(keyName));
			data.Validation().NotNull(nameof(data));

			using (await _asyncLock.LockAsync(ct))
			{
				var crypto = BuildSymmetricCryptoObject(keyName, CIPHER_NAME, CipherMode.EncryptMode);
				var result = await AuthenticateAndProcess(ct, keyName, crypto) ?? throw new System.OperationCanceledException();
				var encryptedData = result.CryptoObject.Cipher.DoFinal(data);
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

		public async Task Enroll(CancellationToken ct)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug("Enrolling the user for fingerprint authentication.");
			}

			var result = _BiometryManager.CanAuthenticate();
			if (result == BiometryManager.BiometrySuccess || result == BiometryManager.BiometryErrorNoneEnrolled)
			{
				var intent = new Intent(Android.Provider.Settings.ActionSecuritySettings);

				intent.AddFlags(ActivityFlags.NewTask);

				Application.Context.StartActivity(intent);

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info("Successfully enrolled the user for fingerprint authentication.");
				}
			}
			else
			{
				if (this.Log().IsEnabled(LogLevel.Warning))
				{
					this.Log().Warn("Fingerprint authentication is not available.");
				}

				throw new NotSupportedException("Fingerprint authentication is not available.");
			}
		}

		public async Task<byte[]> GenerateKeyPair(CancellationToken ct, string name)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Generating a key pair (name: '{name}').");
			}

			name.Validation().NotNullOrEmpty(nameof(name));

			using (await _asyncLock.LockAsync(ct))
			{
				var keygen = KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmEc, ANDROID_KEYSTORE);

				keygen.Initialize(new KeyGenParameterSpec.Builder(name, KeyStorePurpose.Sign)
					.SetAlgorithmParameterSpec(new ECGenParameterSpec(CURVE_NAME))
					.SetDigests(KeyProperties.DigestSha256)
					.SetUserAuthenticationRequired(true)
					.Build()
				);

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Return the generated key pair (name: '{name}').");
				}

				return keygen.GenerateKeyPair().Public.GetEncoded();
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

		public IObservable<bool> GetAndObserveIsEnabled() => _canAuthenticate.Select(x =>
			x == BiometryManager.BiometrySuccess
		);

		public IObservable<bool> GetAndObserveIsSupported() => _canAuthenticate.Select(x =>
			x == BiometryManager.BiometryErrorNoneEnrolled ||
			x == BiometryManager.BiometrySuccess
		);

		public async Task<bool> RemoveKeyPair(CancellationToken ct, string name)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Removing key pair (name: '{name}').");
			}

			name.Validation().NotNullOrEmpty(nameof(name));

			using (await _asyncLock.LockAsync(ct))
			{
				try
				{
					_keyStore.DeleteEntry(name);

					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info($"Successfully removed the key pair (name: '{name}').");
					}

					return true;
				}
				catch
				{
					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info($"Could not remove the key pair.");
					}

					return false;
				}
			}
		}

		public async Task<byte[]> Sign(CancellationToken ct, string pairName, byte[] data)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Signing a key pair (pair name: '{pairName}').");
			}

			pairName.Validation().NotNullOrEmpty(nameof(pairName));
			data.Validation().NotNull(nameof(data));

			using (await _asyncLock.LockAsync(ct))
			{
				var crypto = BuildAsymmetricCryptoObject(pairName, SIGNATURE_NAME);
				var result = await AuthenticateAndProcess(ct, pairName, crypto) ?? throw new System.OperationCanceledException();
				result.CryptoObject.Signature.Update(data);

				var signed = result.CryptoObject.Signature.Sign();

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Successfully signed the key pair (pair name: '{pairName}').");
				}

				return signed;
			}
		}

		private class AuthenticationCallback : BiometryPrompt.AuthenticationCallback
		{
			private readonly Action<BiometryPrompt.AuthenticationResult> _onSuccess;
			private readonly Action _onFailure;
			private readonly Action<int, string> _onError;

			public AuthenticationCallback(Action<BiometryPrompt.AuthenticationResult> onSuccess, Action onFailure, Action<int, string> onError)
			{
				this._onSuccess = onSuccess;
				this._onFailure = onFailure;
				this._onError = onError;
			}

			public override void OnAuthenticationSucceeded(BiometryPrompt.AuthenticationResult result) => _onSuccess(result);

			public override void OnAuthenticationFailed() => _onFailure();

			public override void OnAuthenticationError(int errMsgId, ICharSequence errString) => _onError(errMsgId, errString?.ToString());
		}

		public class AuthenticationError : System.Exception
		{
			public AuthenticationError(int code, string message) : base (message)
			{
				this.Code = code;
			}

			public int Code { get; }
		}
	}
}
#endif
