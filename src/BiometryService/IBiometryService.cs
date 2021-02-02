using System.Threading;
using System.Threading.Tasks;

namespace BiometryService
{
	/// <summary>
	///     The contract for user authentication using biometrics.
	/// </summary>
	public interface IBiometryService
	{
		/// <summary>
		///     Gets the device's current biometric capabilities.
		/// </summary>
		/// <remarks>
		///     <para>
		///         The result of calling <see cref="GetCapabilities" /> may change when application enters or exits foreground.
		///         This is because the user may change device settings related to biometrics including enrollment and application
		///         permissions. You should call <see cref="GetCapabilities" /> before calling <see cref="Authenticate" />,
		///         <see cref="Encrypt{T}" />, or <see cref="Decrypt" />.
		///     </para>
		/// </remarks>
		/// <returns>A <see cref="BiometryCapabilities" /> struct instance.</returns>
		BiometryCapabilities GetCapabilities();

		/// <summary>
		///     Authenticate the user using biometrics.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <returns>A <see cref="BiometryAuthenticationResult" /> enum value.</returns>
		Task<BiometryAuthenticationResult> Authenticate(CancellationToken ct);

		/// <summary>
		/// TODO.
		/// </summary>
		/// <param name="ct"></param>
		/// <param name="key"></param>
		/// <param name="value"></param>
		/// <typeparam name="T"></typeparam>
		/// <returns></returns>
		Task<BiometryAuthenticationResult> Encrypt<T>(CancellationToken ct, string key, string value);

		/// <summary>
		/// TODO.
		/// </summary>
		/// <param name="ct"></param>
		/// <param name="key"></param>
		/// <returns></returns>
		Task<BiometryAuthenticationResult> Decrypt(CancellationToken ct, string key, out string value);
	}
}
