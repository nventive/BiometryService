using System;
using System.Threading;
using System.Threading.Tasks;

namespace BiometryService
{
	public interface IUserAuthenticationService
	{
		Task<bool> Authenticate(CancellationToken ct);

		Task Enroll(CancellationToken ct);

		IObservable<bool> GetAndObserveIsEnabled();

		IObservable<bool> GetAndObserveIsSupported();
	}
}
