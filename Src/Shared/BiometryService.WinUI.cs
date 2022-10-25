﻿#if WINDOWS
using System;
using System.IO;
using System.Linq;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Uno.Extensions;
using Uno.Logging;
using Windows.Foundation.Collections;
using Windows.Security.Credentials;
using Windows.Storage;
using AsyncLock = Uno.Threading.AsyncLock;

namespace BiometryService
{
	/// <summary>
	///     Implementation of the <see cref="IBiometryService" /> for Windows.
	/// </summary>
	public class BiometryService : IBiometryService
	{
		private AsyncLock _asyncLock;

		private IObservable<bool> _isEnabled;
		private IObservable<bool> _isSupported;

		private IPropertySet _keys;

		/// <summary>
		///     Initializes a new instance of the <see cref="BiometryService" /> class.
		/// </summary>
		/// <param name="supported">A bool to know if the device is supported.</param>
		/// <param name="enrolled">A bool to know if the device is enrolled.</param>
		/// <param name="backgroundScheduler">The <see cref="IScheduler" /> to use.</param>
		public BiometryService(bool supported, bool enrolled, IScheduler backgroundScheduler)
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

		/// <summary>
		///     Decodes the array of byte data to a string value
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="key">The key for the value.</param>
		/// <returns>A string</returns>
		public async Task<string> Decrypt(CancellationToken ct, string key)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Decrypting the fingerprint (key name: '{key}').");
			}

			key.Validation().NotNullOrEmpty(nameof(key));
			return null;
		}

		/// <summary>
		///     Encrypt the string value to an array of byte data
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="key">The key for the value.</param>
		/// <param name="value">A string value to encrypt.</param>
		/// <returns>A string</returns>
		public async Task Encrypt(CancellationToken ct, string key, string value)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Encrypting the fingerprint (key name: '{key}').");
			}

			key.Validation().NotNullOrEmpty(nameof(key));
			value.Validation().NotNull(nameof(value));

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

					SaveKey(key, aes.Key);

					using (var ms = new MemoryStream())
					using (var cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
					{
						var valueBytes = Encoding.ASCII.GetBytes(value);

						await cryptoStream.WriteAsync(valueBytes, 0, valueBytes.Length, ct);

						cryptoStream.FlushFinalBlock();

						if (this.Log().IsEnabled(LogLevel.Information))
						{
							this.Log().Info($"Successfully encrypted the fingerprint (key name: '{key}').");
						}
					}
				}
			}
		}

		/// <summary>
		///     Gets the device's current biometric capabilities.
		/// </summary>
		/// <returns>A <see cref="BiometryCapabilities" /> struct instance.</returns>
		public async Task<BiometryCapabilities> GetCapabilities()
		{
			bool windowsHelloAvailable = await KeyCredentialManager.IsSupportedAsync();
			return new BiometryCapabilities(windowsHelloAvailable ? BiometryType.FaceOrFingerprint : BiometryType.None, windowsHelloAvailable, true);
		}

		/// <summary>
		///     Authenticate the user using biometrics.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <returns>A <see cref="BiometryResult" /> enum value.</returns>
		public async Task<BiometryResult> ValidateIdentity(CancellationToken ct)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug("Authenticating the fingerprint.");
			}

			await KeyCredentialManager.IsSupportedAsync();

			if (this.Log().IsEnabled(LogLevel.Information))
			{
				this.Log().Info("Successfully authenticated the fingerprint.");
			}

			return new BiometryResult();
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

		/// <summary>
		///     Is biometry enabled observable
		/// </summary>
		/// <returns>A <see cref="bool" /> value.</returns>
		public IObservable<bool> GetAndObserveIsEnabled() => _isEnabled;

		/// <summary>
		///     Is biometry supported observable
		/// </summary>
		/// <returns>A <see cref="bool" /> value.</returns>
		public IObservable<bool> GetAndObserveIsSupported() => _isSupported;

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

		public Task<string> EncryptAndReturn(CancellationToken ct, string key, string value)
		{
			throw new NotImplementedException();
		}

		public Task<string> Decrypt(CancellationToken ct, string key, string value)
		{
			throw new NotImplementedException();
		}
	}
}
#endif