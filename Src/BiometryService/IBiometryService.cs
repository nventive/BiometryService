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
		///         permissions. You should call <see cref="GetCapabilities" /> before calling <see cref="ValidateIdentity" />,
		///         <see cref="Encrypt" />, or <see cref="Decrypt" />.
		///     </para>
		/// </remarks>
		/// <returns>A <see cref="BiometryCapabilities" /> struct instance.</returns>
		Task<BiometryCapabilities> GetCapabilities();

		/// <summary>
		///     Validate the user identity.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <returns>An <see cref="BiometryResult" /> enum value.</returns>
		Task<BiometryResult> ValidateIdentity(CancellationToken ct);

		/// <summary>
		///     Encrypt the value and store the key into the platform secure storage.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="key">The name of the Key.</param>
		/// <param name="value">The value to be encrypt.</param>
		/// <returns>A string.</returns>
		Task Encrypt(CancellationToken ct, string key, string value);

		/// <summary>
		///     Encrypt the value and return the result.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="key">The name of the Key.</param>
		/// <param name="value">The value to be encrypt.</param>
		/// <returns>A string.</returns>
		Task<string> EncryptAndReturn(CancellationToken ct, string key, string value);

		/// <summary>
		///     Retrieve and decrypt data associated to the key.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="key">The name of the Key.</param>
		/// <returns>A string</returns>
		Task<string> Decrypt(CancellationToken ct, string key);

		/// <summary>
		///     Retrieve and decrypt data associated to the key.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="key">The name of the Key.</param>
		/// <param name="value">The value to be decrypt.</param>
		/// <returns>A string</returns>
		Task<string> Decrypt(CancellationToken ct, string key, string value);
	}
}