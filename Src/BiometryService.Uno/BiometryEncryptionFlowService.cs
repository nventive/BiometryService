using System;
using System.Reactive.Linq;
using System.Reactive.Threading.Tasks;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using GeneratedSerializers;
using Microsoft.Extensions.Logging;
using Uno.Extensions;
using Uno.Logging;

namespace BiometryService
{
	public partial class BiometryEncryptionFlowService : IBiometryEncryptionFlowService
	{
		private readonly Func<IObjectSerializer> _serializer;
		private readonly Func<IBiometryService> _fingerprintService;
		private readonly Func<IEventsDelegate> _eventsDelegate;
		private readonly Func<IPersistenceDelegate> _persistenceDelegate;

		public BiometryEncryptionFlowService(
			Func<IObjectSerializer> serializer,
			Func<IBiometryService> fingerprintService,
			Func<IEventsDelegate> eventsDelegate,
			Func<IPersistenceDelegate> persistenceDelegate)
		{
			_serializer = serializer;
			_fingerprintService = fingerprintService;
			_eventsDelegate = eventsDelegate;
			_persistenceDelegate = persistenceDelegate;
		}

		public async Task<bool> TryBiometryEncryption<T>(CancellationToken ct, string objectKey, T objectToEncrypt)
		{
			try
			{
				if (await MustRequestBiometryEncryptionUsage(ct, objectKey))
				{
					if (this.Log().IsEnabled(LogLevel.Debug))
					{
						this.Log().Debug("Requesting permission to use Biometry encryption.");
					}

					var useBiometryEncryption = await _eventsDelegate().RequestBiometryEncryptionUsage(ct, objectKey);
					
					if (useBiometryEncryption)
					{
						if (this.Log().IsEnabled(LogLevel.Debug))
						{
							this.Log().Debug("Using Biometry encryption.");

						}

						return await TryUseBiometryEncryption(ct, objectKey, objectToEncrypt);
					}
					else
					{
						if (this.Log().IsEnabled(LogLevel.Information))
						{
							this.Log().Info("User refuses to use Biometry encryption.");
						}

						await _persistenceDelegate().SetIsBiometryEncryptionEnabled(ct, objectKey, false);

						return false;
					}
				}
				else
				{
					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info($"Biometry encryption will not be used for the key '{objectKey}'.");
					}

					return false;
				}
			}
			catch (Exception e)
			{
				if (this.Log().IsEnabled(LogLevel.Error))
				{
					this.Log().Error($"Biometry encryption failed for the key '{objectKey}'.", e);
				}

				return false;
			}
		}

		public async Task<T> TryBiometryDecryption<T>(CancellationToken ct, string objectKey)
		{
			try
			{
				if (this.Log().IsEnabled(LogLevel.Debug))
				{
					this.Log().Debug($"Requesting permission to use Biometry decryption for the key '{objectKey}'.");
				}

				if (await CanUseBiometryDecryption(ct, objectKey))
				{
					if (this.Log().IsEnabled(LogLevel.Debug))
					{
						this.Log().Debug($"Using Biometry decryption for the key '{objectKey}'.");
					}

					return await TryUseBiometryDecryption<T>(ct, objectKey);
				}
				else
				{
					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info($"Biometry decryption will not be used for the key '{objectKey}'.");
					}

					return default(T);
				}
			}
			catch (Exception e)
			{
				if (this.Log().IsEnabled(LogLevel.Error))
				{
					this.Log().Error($"Biometry decryption failed for the key '{objectKey}'.", e);
				}

				return default(T);
			}
		}

		public IObservable<bool> GetAndObserveCanUseBiometryEncryption()
		{
			return _fingerprintService().GetAndObserveIsEnabled();
		}

		private async Task<bool> TryUseBiometryEncryption<T>(CancellationToken ct, string objectKey, T objectToEncrypt)
		{
			try
			{
				// Encrypt the authentication request.
				var encryptionResult = await Encrypt(ct, objectKey, objectToEncrypt);

				// Save the encryption result to use it later.
				await _persistenceDelegate().SaveEncryptedResult(ct, objectKey, encryptionResult);

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Biometry encryption succeeded for the key '{objectKey}'.");

				}

				return true;
			}
			catch (OperationCanceledException)
			{
				// The user wanted to use Biometry encryption but it was canceled; no interactions required.
				if (this.Log().IsEnabled(LogLevel.Error))
				{
					this.Log().Error($"Biometry encryption canceled for the key '{objectKey}'.");
				}

				return false;
			}
			catch (Exception e)
			{
				// The user wanted to use Biometry encryption but it failed.
				if (this.Log().IsEnabled(LogLevel.Error))
				{
					this.Log().Error($"Biometry encryption failed for the key '{objectKey}'.", e);
				}

				await _eventsDelegate().OnDecryptionFailed(ct, objectKey);

				return false;
			}
		}

		private async Task<T> TryUseBiometryDecryption<T>(CancellationToken ct, string objectKey)
		{
			try
			{
				var encryptionResult = await _persistenceDelegate().LoadEncryptedResult(ct, objectKey);

				var decryptedAuthenticationRequest = await Decrypt<T>(ct, objectKey, encryptionResult);

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Biometry decryption succeeded for key '{objectKey}'.");

				}

				return decryptedAuthenticationRequest;
			}
			catch (OperationCanceledException)
			{
				// There was something to decrypt but it was canceled; no interactions required.
				if (this.Log().IsEnabled(LogLevel.Error))
				{
					this.Log().Error($"Biometry decryption was canceled for the key '{objectKey}'.");
				}
				
				return default(T);
			}
#if __IOS__
			catch (ArgumentException e) when (e.Message.Contains("Key not found"))
			{
				// There was something to decrypt but it failed.
				if (this.Log().IsEnabled(LogLevel.Error))
				{
					this.Log().Error($"Biometry decryption failed. Could not find the encrypted entry for key '{objectKey}'. This is normally an indication that the user modified his fingerprints after setting up fingerprint in the app. Removing fingerprint setup and notifying user.", e);
				}

				await _persistenceDelegate().SaveEncryptedResult(ct, objectKey, default(byte[]));

				await _eventsDelegate().OnEncryptionReset(ct, objectKey);

				return default(T);
			}
#endif
			catch (Exception e)
			{
				// There was something to decrypt but it failed.
				if (this.Log().IsEnabled(LogLevel.Error))
				{
					this.Log().Error($"Biometry decryption failed for the key '{objectKey}'.", e);
				}

				await _eventsDelegate().OnDecryptionFailed(ct, objectKey);

				return default(T);
			}
		}

		#region Conditions
		private async Task<bool> MustRequestBiometryEncryptionUsage(CancellationToken ct, string objectKey)
		{
			return await IsBiometryEnabledOnDevice(ct)
				&& await IsBiometryEnabledInApplication(ct, objectKey)
				&& !(await HasBiometryEncryptedResult(ct, objectKey));
		}

		private async Task<bool> CanUseBiometryDecryption(CancellationToken ct, string objectKey)
		{
			return await IsBiometryEnabledOnDevice(ct)
				&& await IsBiometryEnabledInApplication(ct, objectKey)
				&& await HasBiometryEncryptedResult(ct, objectKey);
		}

		private async Task<bool> IsBiometryEnabledOnDevice(CancellationToken ct)
		{
			return await _fingerprintService().GetAndObserveIsEnabled().FirstAsync(ct);
		}

		private async Task<bool> IsBiometryEnabledInApplication(CancellationToken ct, string objectKey)
		{
			return await _persistenceDelegate().GetIsBiometryEncryptionEnabled(ct, objectKey);
		}

		private async Task<bool> HasBiometryEncryptedResult(CancellationToken ct, string objectKey)
		{
			return (await _persistenceDelegate().LoadEncryptedResult(ct, objectKey)) != null;
		}
		#endregion

		#region Operations
		private async Task<byte[]> Encrypt<T>(CancellationToken ct, string objectKey, T objectToEncrypt)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Encrypting the object for the key '{objectKey}'.");
			}

			var serializedObjectToEncrypt = _serializer().ToString(objectToEncrypt, typeof(T));

			var encodedObjectToEncrypt = Encoding.Unicode.GetBytes(serializedObjectToEncrypt);

			var encryptedObject = await _fingerprintService().Encrypt(ct, objectKey, encodedObjectToEncrypt);

			if (encryptedObject == null)
			{
				throw new ArgumentNullException("Biometry encryption returned null.");
			}

			if (this.Log().IsEnabled(LogLevel.Information))
			{
				this.Log().Info($"Object encrypted for the key '{objectKey}'.");
			}

			return encryptedObject;
		}

		private async Task<T> Decrypt<T>(CancellationToken ct, string objectKey, byte[] encryptionResult)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Decrypting the object for the key '{objectKey}'.");
			}

			var decryptedAuthenticationRequest = await _fingerprintService().Decrypt(ct, objectKey, encryptionResult);

			var decodedAuthenticationRequest = Encoding.Unicode.GetString(decryptedAuthenticationRequest);

			var deserializedAuthenticationRequest = (T)_serializer().FromString(decodedAuthenticationRequest, typeof(T));

			if (this.Log().IsEnabled(LogLevel.Information))
			{
				this.Log().Info($"Object decrypted for the key '{objectKey}'.");
			}

			return deserializedAuthenticationRequest;
		}
		#endregion
	}
}
