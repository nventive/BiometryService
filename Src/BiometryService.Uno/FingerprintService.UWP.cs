#if NETFX_CORE
using System;
using System.IO;
using System.Linq;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Uno.Extensions;
using Uno.Logging;
using Windows.Foundation.Collections;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using AsyncLock = Uno.Threading.AsyncLock;

namespace BiometryService
{
	public class FingerprintServiceMock : IFingerprintService
	{
		private AsyncLock _asyncLock;

		private IObservable<bool> _isEnabled;
		private IObservable<bool> _isSupported;

		private IPropertySet _keys;

		public FingerprintServiceMock(bool supported, bool enrolled, IScheduler backgroundScheduler)
		{
			backgroundScheduler.Validation().NotNull(nameof(backgroundScheduler));

			_keys = ApplicationData.Current.LocalSettings.Values;

			_asyncLock = new AsyncLock();

			_isSupported =
				Observable.Never<bool>()
					.StartWith(supported)
					.Replay(1, backgroundScheduler)
					.RefCount();

			_isEnabled =
				_isSupported
					.Select(isSupported => isSupported && enrolled)
					.Replay(1, backgroundScheduler)
					.RefCount();
		}

		private async Task AssertIsEnabled(CancellationToken ct)
		{
			var enabled = await _isEnabled.FirstAsync();

			if (!enabled)
			{
				var supported = await _isSupported.FirstAsync();

				if (supported)
				{
					throw new InvalidOperationException("No fingerprint(s) registered.");
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
		}

		public async Task<bool> Authenticate(CancellationToken ct)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug("Authenticating the fingerprint.");
			}

			await AssertIsEnabled(ct);

			if (this.Log().IsEnabled(LogLevel.Information))
			{
				this.Log().Info("Successfully authenticated the fingerprint.");
			}

			return true;
		}

		public async Task<byte[]> Decrypt(CancellationToken ct, string keyName, byte[] data)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Decrypting the fingerprint (key name: '{keyName}').");
			}

			keyName.Validation().NotNullOrEmpty(nameof(keyName));
			data.Validation().NotNull(nameof(data));
			data.Validation().IsTrue(array => array.Length >= 32, nameof(data), "Data is invalid.");

			await AssertIsEnabled(ct);

			using (await _asyncLock.LockAsync(ct))
			{
				using (Aes aes = Aes.Create())
				{
					aes.BlockSize = 128;
					aes.KeySize = 256;
					aes.Mode = CipherMode.CBC;
					aes.Padding = PaddingMode.PKCS7;

					var iv = new byte[16];
					Array.ConstrainedCopy(data, 0, iv, 0, 16);

					aes.IV = iv;
					aes.Key = RetrieveKey(keyName);

					using (var ms = new MemoryStream(data))
					using (var outputStream = new MemoryStream())
					using (var cryptoStream = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
					{
						ms.Seek(16, SeekOrigin.Begin);

						await cryptoStream.CopyToAsync(outputStream, 81920, ct);

						if (this.Log().IsEnabled(LogLevel.Information))
						{
							this.Log().Info($"Successfully decrypted the fingerprint (key name: '{keyName}').");
						}

						return outputStream.ToArray();
					}
				}
			}
		}

		public async Task<byte[]> Encrypt(CancellationToken ct, string keyName, byte[] data)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Encrypting the fingerprint (key name: '{keyName}').");
			}

			keyName.Validation().NotNullOrEmpty(nameof(keyName));
			data.Validation().NotNull(nameof(data));

			await AssertIsEnabled(ct);

			using (await _asyncLock.LockAsync(ct))
			{
				using (Aes aes = Aes.Create())
				{
					aes.BlockSize = 128;
					aes.KeySize = 256;
					aes.Mode = CipherMode.CBC;
					aes.Padding = PaddingMode.PKCS7;

					aes.GenerateIV();
					aes.GenerateKey();

					SaveKey(keyName, aes.Key);

					using (var ms = new MemoryStream())
					using (var cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
					{
						await cryptoStream.WriteAsync(data, 0, data.Length, ct);

						cryptoStream.FlushFinalBlock();

						if (this.Log().IsEnabled(LogLevel.Information))
						{
							this.Log().Info($"Successfully encrypted the fingerprint (key name: '{keyName}').");
						}

						return aes.IV
							.Concat(ms.ToArray())
							.ToArray();
					}
				}
			}
		}

		public async Task Enroll(CancellationToken ct)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug("Enrolling the user for fingerprint authentication.");
			}

			var supported = await _isSupported.FirstAsync();

			if (supported)
			{
				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info("Successfully enrolled the user for fingerprint authentication.");
				}
			}
			else
			{
				if (this.Log().IsEnabled(LogLevel.Warning))
				{
					this.Log().Warn("Fingerpring authentication is not available.");
				}

				throw new NotSupportedException("Fingerprint authentication is not available.");
			}
		}

		public IObservable<bool> GetAndObserveIsEnabled() => _isEnabled;

		public IObservable<bool> GetAndObserveIsSupported() => _isSupported;

		public async Task<byte[]> GenerateKeyPair(CancellationToken ct, string name)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Generating a key pair (name: '{name}').");
			}

			name.Validation().NotNullOrEmpty(nameof(name));

			await AssertIsEnabled(ct);

			using (await _asyncLock.LockAsync(ct))
			{
				var algorithm = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.EcdsaP256Sha256);

				var keyPair = algorithm.CreateKeyPair(256);

				SaveKey(name, keyPair.Export().ToArray());

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Return the successfully generated key pair (name: '{name}').");
				}

				return keyPair.ExportPublicKey().ToArray();
			}
		}

		public async Task<bool> RemoveKeyPair(CancellationToken ct, string name)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Removing a key pair (name: '{name}').");
			}

			name.Validation().NotNullOrEmpty(nameof(name));

			await AssertIsEnabled(ct);

			using (await _asyncLock.LockAsync(ct))
			{
				var result = _keys.Remove(name);

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Successfully removed the key pair (name: '{name}').");
				}

				return result;
			}
		}

		private byte[] RetrieveKey(string name)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Retrieving the key (name: '{name}').");
			}

			if (_keys.TryGetValue(name, out var value))
			{
				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Successfully retrieved the key (name: '{name}').");
				}

				return Convert.FromBase64String(value as string);
			}
			else
			{
				if (this.Log().IsEnabled(LogLevel.Error))
				{
					this.Log().Error("The key was not found.");
				}

				throw new ArgumentException("Key not found.");
			}
		}

		private void SaveKey(string name, byte[] key)
		{
			_keys[name] = Convert.ToBase64String(key);
		}

		public async Task<byte[]> Sign(CancellationToken ct, string pairName, byte[] data)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Signing a key pair (pair name: '{pairName}').");
			}

			pairName.Validation().NotNullOrEmpty(nameof(pairName));
			data.Validation().NotNull(nameof(data));

			await AssertIsEnabled(ct);

			using (await _asyncLock.LockAsync(ct))
			{
				var algorithm = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.EcdsaP256Sha256);

				var rawKeyPair = RetrieveKey(pairName).AsBuffer();

				var keyPair = algorithm.ImportKeyPair(rawKeyPair);

				using (var sha256 = SHA256.Create())
				{
					var hash = sha256.ComputeHash(data);

					var signature = await CryptographicEngine.SignHashedDataAsync(keyPair, hash.AsBuffer());

					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info($"Successfully signed a key pair (pair name: '{pairName}').");
					}

					return signature.ToArray();
				}
			}
		}
	}
}
#endif
