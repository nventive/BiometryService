using System;

namespace BiometryService
{
	public interface IBiometryService : IUserAuthenticationService, IAuthorizedUserEncryptionService, IAuthorizedUserSigningService
	{
	}
}
