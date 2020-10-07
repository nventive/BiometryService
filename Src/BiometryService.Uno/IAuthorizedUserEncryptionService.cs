using System;
using System.Threading;
using System.Threading.Tasks;

namespace BiometryService
{
	public interface IAuthorizedUserEncryptionService
	{
		Task<byte[]> Decrypt(CancellationToken ct, string keyName, byte[] data);

		Task<byte[]> Encrypt(CancellationToken ct, string keyName, byte[] data);
	}
}
