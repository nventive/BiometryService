using System.Threading;
using System.Threading.Tasks;

namespace BiometryService
{
	/// <summary>
	/// The contract that handles biometry.
	/// </summary>
	public interface IBiometryService
	{
		/// <summary>
		/// Gets the device's current biometric capabilities.
		/// </summary>
		/// <remarks>
		///		<para>
		///			The result of calling <see cref="GetCapabilities" /> may change when application enters or exits foreground.
		///			This is because the user may change device settings related to biometrics including enrollment and application
		///			permissions. You should call <see cref="GetCapabilities" /> before calling <see cref="ScanBiometry" />,
		///			<see cref="Encrypt" />, or <see cref="Decrypt" />.
		///		</para>
		/// </remarks>
		/// <returns>A <see cref="BiometryCapabilities" /> struct instance.</returns>
		Task<BiometryCapabilities> GetCapabilities(CancellationToken ct);

		/// <summary>
		/// Attemps to scan the user's biometry.
		/// </summary>
		/// <param name="ct"><see cref="CancellationToken" />.</param>
		Task ScanBiometry(CancellationToken ct);

		/// <summary>
		/// Encrypts the value and stores it into the platform secure storage with the given <paramref name="keyName"/>.
		/// </summary>
		/// <param name="ct"><see cref="CancellationToken" />.</param>
		/// <param name="keyName">The name of the key.</param>
		/// <param name="keyValue">The value to be encrypt.</param>
		Task Encrypt(CancellationToken ct, string keyName, string keyValue);

		/// <summary>
		/// Decrypts and gets the data associated to the given <paramref name="keyName"/>.
		/// </summary>
		/// <param name="ct"><see cref="CancellationToken" />.</param>
		/// <param name="keyName">The name of the Key.</param>
		/// <returns>The decrypted data associated to the key.</returns>
		Task<string> Decrypt(CancellationToken ct, string keyName);

		/// <summary>
		/// Removes the ecrypted value in the platform secure storage.
		/// </summary>
		/// <param name="keyName"></param>
		void Remove(string keyName);
	}
}
