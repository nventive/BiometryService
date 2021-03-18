#if __ANDROID__
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BiometryService
{
	public class BiometryService : IBiometryService
	{
		public BiometryService()
		{

		}

		public Task<string> Decrypt(CancellationToken ct, string key)
		{
			throw new NotImplementedException();
		}

		public Task Encrypt(CancellationToken ct, string key, string value)
		{
			throw new NotImplementedException();
		}

		public BiometryCapabilities GetCapabilities()
		{
			throw new NotImplementedException();
		}

		public Task<BiometryResult> ValidateIdentity(CancellationToken ct)
		{
			throw new NotImplementedException();
		}
	}
}
#endif