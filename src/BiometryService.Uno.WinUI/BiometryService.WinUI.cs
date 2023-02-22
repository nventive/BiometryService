#if __WINDOWS__
using System;
using System.IO;
using System.Reactive.Linq;
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
/// WinUI implementation of <see cref="IBiometryService"/>.
/// </summary>
/// <remarks>
/// This implementation is not fully implemented.
/// </remarks>
public sealed class BiometryService : IBiometryService
{
	private readonly ILogger _logger;
	private readonly IPropertySet _keys;
	private readonly SemaphoreSlim _semaphore;

	/// <summary>
	/// Initializes a new instance of the <see cref="BiometryService" /> class.
	/// </summary>
	/// <param name="loggerFactory">Logger factory</param>
	public BiometryService(ILoggerFactory loggerFactory = null)
	{
		_logger = loggerFactory?.CreateLogger<IBiometryService>() ?? NullLogger<IBiometryService>.Instance;
		_keys = ApplicationData.Current.LocalSettings.Values;
		_semaphore = new SemaphoreSlim(1, 1);
	}

	/// <inheritdoc />
	public async Task<BiometryCapabilities> GetCapabilities(CancellationToken ct)
	{
		var windowsHelloAvailable = await KeyCredentialManager.IsSupportedAsync().AsTask(ct);
		return new BiometryCapabilities(windowsHelloAvailable ? BiometryType.Fingerprint : BiometryType.None, windowsHelloAvailable, true);
	}

	/// <inheritdoc />
	public async Task ScanBiometry(CancellationToken ct)
	{
		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug("Authenticating the fingerprint.");
		}

		await KeyCredentialManager.IsSupportedAsync();

		if (_logger.IsEnabled(LogLevel.Information))
		{
			_logger.LogInformation("Successfully authenticated the fingerprint.");
		}
	}

	/// <inheritdoc />
	public async Task Encrypt(CancellationToken ct, string key, string value)
	{
		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug($"Encrypting the fingerprint (key name: '{key}').");
		}

		ValidateProperty(key, nameof(key));
		ValidateProperty(key, nameof(value));

		if (!await KeyCredentialManager.IsSupportedAsync())
		{
			throw new BiometryException(BiometryExceptionReason.Unavailable, "Biometry not supported.");
		}

		await _semaphore.WaitAsync(ct);

		try
		{
			using (var aes = Aes.Create())
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

					if (_logger.IsEnabled(LogLevel.Information))
					{
						_logger.LogInformation($"Successfully encrypted the fingerprint (key name: '{key}').");
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
	public Task<string> Decrypt(CancellationToken ct, string key)
	{
		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug($"Decrypting the fingerprint (key name: '{key}').");
		}

		ValidateProperty(key, nameof(key));

		throw new NotImplementedException("Missing implementation of Decrypt.");
	}

	/// <inheritdoc />
	public void Remove(string key)
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

	/// <summary>
	/// 
	/// </summary>
	/// <param name="propertyValue"></param>
	/// <param name="propertyName"></param>
	/// <exception cref="ArgumentNullException"></exception>
	private void ValidateProperty(string propertyValue, string propertyName)
	{
		if (string.IsNullOrEmpty(propertyValue))
		{
			throw new ArgumentNullException(propertyName);
		}
	}
}
#endif
