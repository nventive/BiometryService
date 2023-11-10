using System;
using System.Threading;
using System.Threading.Tasks;

namespace BiometryService;

/// <summary>
/// This implementation of <see cref="IBiometryService"/> only supports <see cref="GetCapabilities"/> which explicitly yields no biometric capabilities.
/// </summary>
public sealed class UnsupportedBiometryService : IBiometryService
{
	/// <inheritdoc />
	public Task<BiometryCapabilities> GetCapabilities(CancellationToken ct)
	{
		return Task.FromResult(new BiometryCapabilities(BiometryType.None, false, false));
	}

	/// <inheritdoc />
	public Task ScanBiometry(CancellationToken ct)
	{
		throw new NotSupportedException($"{nameof(UnsupportedBiometryService)} doesn't support scanning biometry.");
	}

	/// <inheritdoc />
	public Task Encrypt(CancellationToken ct, string keyName, string keyValue)
	{
		throw new NotSupportedException($"{nameof(UnsupportedBiometryService)} doesn't support encrypting key.");
	}

	/// <inheritdoc />
	public Task<string> Decrypt(CancellationToken ct, string keyName)
	{
		throw new NotSupportedException($"{nameof(UnsupportedBiometryService)} doesn't support decrypting key.");
	}

	/// <inheritdoc />
	public void Remove(string keyName)
	{
		throw new NotSupportedException($"{nameof(UnsupportedBiometryService)} doesn't support removing encrypted key.");
	}
}
