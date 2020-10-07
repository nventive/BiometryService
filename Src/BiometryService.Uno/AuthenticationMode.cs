using System;

namespace BiometryService
{
	internal enum AuthenticationMode
	{
		Authenticate,
		AuthenticateForDecryption,
		AuthenticateForEncryption,
		AuthenticateForSigning
	}
}
