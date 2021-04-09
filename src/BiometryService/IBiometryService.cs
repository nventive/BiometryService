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
		BiometryCapabilities GetCapabilities();

		/// <summary>
		///     Authenticate the user using biometrics.
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <returns>A <see cref="BiometryResult" /> enum value.</returns>
		Task<BiometryResult> ValidateIdentity(CancellationToken ct);

		/// <summary>
		/// Encrypt the string value to an array of byte data
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="keyName"></param>
		/// <param name="value"></param>
		/// <returns>An array of byte</returns>
		Task<byte[]> Encrypt(CancellationToken ct, string keyName, string value);

		/// <summary>
		/// Decodes the array of byte data to a string value
		/// </summary>
		/// <param name="ct">The <see cref="CancellationToken" /> to use.</param>
		/// <param name="keyName"></param>
		/// <param name="data"></param>
		/// <returns>A string</returns>
		Task<string> Decrypt(CancellationToken ct, string keyName, byte[] data);
	}
}
