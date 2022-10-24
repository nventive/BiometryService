using System;
using System.Threading;
using System.Threading.Tasks;

namespace BiometryService
{
	/// <summary>
	/// This implementation of <see cref="IBiometryService"/> only supports <see cref="GetCapabilities"/> which explicitly yields no biometric capabilities.
	/// </summary>
	public class UnsupportedBiometryService : IBiometryService
	{
		/// <inheritdoc />
		public Task<BiometryCapabilities> GetCapabilities(CancellationToken ct)
		{
			return Task.FromResult(new BiometryCapabilities(BiometryType.None, false, false));
		}

		/// <inheritdoc />
		public Task ScanBiometry(CancellationToken ct)
		{
			throw new NotSupportedException($"{nameof(UnsupportedBiometryService)} doesn't support identity validation.");
		}

		/// <inheritdoc />
		public Task<string> Decrypt(CancellationToken ct, string key)
		{
			throw new NotSupportedException($"{nameof(UnsupportedBiometryService)} doesn't support decrypting.");
		}

		/// <inheritdoc />
		public Task<string> Decrypt(CancellationToken ct, string key, string value)
		{
			throw new NotSupportedException($"{nameof(UnsupportedBiometryService)} doesn't support decrypting.");
		}

		/// <inheritdoc />
		public Task Encrypt(CancellationToken ct, string key, string value)
		{
			throw new NotSupportedException($"{nameof(UnsupportedBiometryService)} doesn't support encrypting.");
		}

		/// <inheritdoc />
		public Task<string> EncryptAndReturn(CancellationToken ct, string key, string value)
		{
			throw new NotSupportedException($"{nameof(UnsupportedBiometryService)} doesn't support encrypting.");
		}

		/// <inheritdoc />
		public void Remove(string key)
		{
			throw new NotSupportedException($"{nameof(UnsupportedBiometryService)} doesn't support removing.");
		}
	}
}
