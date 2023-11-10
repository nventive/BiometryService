#if WINDOWS_UWP
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Windows.Foundation.Collections;
using Windows.Security.Credentials;
using Windows.Storage;

namespace BiometryService;

/// <summary>
/// Windows (UWP) implementation of <see cref="IBiometryService"/>.
/// </summary>
/// <remarks>
/// This implementation is not fully implementeed.
/// </remarks>
public sealed class BiometryService : BaseBiometryService
{
	private readonly IPropertySet _keys;
	private readonly SemaphoreSlim _semaphore;

	/// <summary>
	/// Initializes a new instance of the <see cref="BiometryService" /> class.
	/// </summary>
	/// <param name="loggerFactory">Logger factory</param>
	public BiometryService(ILoggerFactory loggerFactory = null) : base(loggerFactory)
	{
		_keys = ApplicationData.Current.LocalSettings.Values;
		_semaphore = new SemaphoreSlim(1, 1);
	}

	/// <inheritdoc/>
	public override async Task<BiometryCapabilities> GetCapabilities(CancellationToken ct)
	{
		bool windowsHelloAvailable = await KeyCredentialManager.IsSupportedAsync().AsTask(ct);
		return new BiometryCapabilities(windowsHelloAvailable ? BiometryType.Fingerprint : BiometryType.None, windowsHelloAvailable, true);
	}

	/// <inheritdoc/>
	public override async Task ScanBiometry(CancellationToken ct)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug("Authenticating the fingerprint.");
		}

		await KeyCredentialManager.IsSupportedAsync();

		if (Logger.IsEnabled(LogLevel.Information))
		{
			Logger.LogInformation("Successfully authenticated the fingerprint.");
		}
	}

	/// <inheritdoc/>
	public override async Task Encrypt(CancellationToken ct, string key, string value)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug($"Encrypting the fingerprint (key name: '{key}').");
		}

		ValidateProperty(key, nameof(key));
		ValidateProperty(key, nameof(value));

		if (!(await KeyCredentialManager.IsSupportedAsync()))
		{
			throw new BiometryException(BiometryExceptionReason.Unavailable, "Biometry not supported.");
		}

		await _semaphore.WaitAsync(ct);

		try
		{
			using (Aes aes = Aes.Create())
			{
				aes.BlockSize = 128;
				aes.KeySize = 256;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;

				aes.GenerateIV();
				aes.GenerateKey();

				_keys[key] = Convert.ToBase64String(aes.Key);

				using (var ms = new MemoryStream())
				using (var cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
				{
					var valueBytes = Encoding.ASCII.GetBytes(value);

					await cryptoStream.WriteAsync(valueBytes, 0, valueBytes.Length, ct);

					cryptoStream.FlushFinalBlock();

					if (Logger.IsEnabled(LogLevel.Information))
					{
						Logger.LogInformation($"Successfully encrypted the fingerprint (key name: '{key}').");
					}
				}
			}
		}
		finally
		{
			_semaphore.Release();
		}
	}

	/// <inheritdoc/>
	public override Task<string> Decrypt(CancellationToken ct, string key)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug($"Decrypting the fingerprint (key name: '{key}').");
		}

		ValidateProperty(key, nameof(key));

		throw new NotImplementedException("Missing implementation of Decrypt.");
	}

	/// <inheritdoc />
	public override void Remove(string key)
	{
		if (_keys.ContainsKey(key))
		{
			_keys.Remove(key);
		}
		else
		{
			throw new ArgumentException($"{key} does not exists");
		}
	}

	private void ValidateProperty(string propertyValue, string propertyName)
	{
		if (string.IsNullOrEmpty(propertyValue))
		{
			throw new ArgumentNullException(propertyName);
		}
	}
}
#endif
