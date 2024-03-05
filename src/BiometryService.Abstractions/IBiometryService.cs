using System;
using System.Threading;
using System.Threading.Tasks;

namespace BiometryService;

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
	/// <exception cref="BiometryException">Thrown when an unknown or unmanaged error occured during policy evaluation.</exception>
	Task<BiometryCapabilities> GetCapabilities(CancellationToken ct);

	/// <summary>
	/// Attemps to scan the user's biometry.
	/// Will throw an exception if it did not succeed.
	/// </summary>
	/// <param name="ct"><see cref="CancellationToken" />.</param>
	/// <exception cref="BiometryException">Thrown for general biometry errors.</exception>
	/// <exception cref="OperationCanceledException">Thrown for user, application and system cancellation.</exception>
	Task ScanBiometry(CancellationToken ct);

	/// <summary>
	/// Encrypts the value and stores it into the platform secure storage with the given <paramref name="key"/>.
	/// </summary>
	/// <remarks>
	/// Catch and throw <see cref="BiometryException"/> for general biometry errors.
	/// </remarks>
	/// <param name="ct"><see cref="CancellationToken" />.</param>
	/// <param name="key">The name of the key.</param>
	/// <param name="value">The value to be encrypted.</param>
	Task Encrypt(CancellationToken ct, string key, string value);

	/// <summary>
	/// Decrypts and gets the data associated to the given <paramref name="key"/>.
	/// </summary>
	/// <remarks>
	/// Catch and throw <see cref="BiometryException"/> for general biometry errors.
	/// Catch and throw <see cref="OperationCanceledException"/> if the user cancelled the operation.
	/// </remarks>
	/// <param name="ct"><see cref="CancellationToken" />.</param>
	/// <param name="key">The name of the Key.</param>
	/// <returns>The decrypted data associated to the key.</returns>
	Task<string> Decrypt(CancellationToken ct, string key);

	/// <summary>
	/// Removes the ecrypted value in the platform secure storage.
	/// </summary>
	/// <param name="key">The name of the Key.</param>
	/// <exception cref="BiometryException">Thrown for general biometry errors.</exception>
	void Remove(string key);
}
