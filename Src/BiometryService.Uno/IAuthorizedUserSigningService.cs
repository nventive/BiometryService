using System;
using System.Threading;
using System.Threading.Tasks;

namespace BiometryService
{
	public interface IAuthorizedUserSigningService
	{
		Task<byte[]> GenerateKeyPair(CancellationToken ct, string name);

		Task<bool> RemoveKeyPair(CancellationToken ct, string name);

		Task<byte[]> Sign(CancellationToken ct, string pairName, byte[] data);
	}
}
