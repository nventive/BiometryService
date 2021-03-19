#if __ANDROID__
using System;
using System.Threading;
using System.Threading.Tasks;
using Android.Content;
using AndroidX.Biometric;
using AndroidX.Core.Content;
using AndroidX.Fragment.App;
using Java.Lang;
using Java.Security;
using Microsoft.Extensions.Logging;
using Uno;
using Uno.Extensions;
using Uno.Logging;
using Uno.Threading;
using Windows.UI.Core;

namespace BiometryService
{
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

		public async Task<BiometryResult> ValidateIdentity(CancellationToken ct)
		{
			using (await _asyncLock.LockAsync(ct))
			{
				var response = await AuthenticateAndProcess(ct, CRYPTO_OBJECT_KEY_NAME);

				var result = new BiometryResult();
				return result;
			}
		}

		public Task<string> Decrypt(CancellationToken ct, string key, byte[] data)
		{
			throw new NotImplementedException();
		}

		public Task<byte[]> Encrypt(CancellationToken ct, string key, string value)
		{
			throw new NotImplementedException();
		}

		public BiometryCapabilities GetCapabilities()
		{
			bool IsEnabled = false;
			switch (_biometricManager.CanAuthenticate(BiometricManager.Authenticators.BiometricStrong))
			{
				case BiometricManager.BiometricSuccess:
					IsEnabled = true;
					break;
				case BiometricManager.BiometricErrorNoHardware:
					break;
				case BiometricManager.BiometricErrorNoneEnrolled:
					break;
				case BiometricManager.BiometricErrorSecurityUpdateRequired:
					break;
				default:
					break;
			}
			bool devicePinAvailable = Convert.ToBoolean(_biometricManager.CanAuthenticate(BiometricManager.Authenticators.DeviceCredential));

			return new BiometryCapabilities(BiometryType.Fingerprint, IsEnabled, devicePinAvailable);

		}

		private async Task<BiometricPrompt.AuthenticationResult> AuthenticateAndProcess(CancellationToken ct, string keyName, BiometricPrompt.CryptoObject crypto = null)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Authenticating and processing the fingerprint (key name: '{keyName}').");
			}

			var result = _biometricManager.CanAuthenticate();
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
	}
}
#endif