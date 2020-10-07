using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BiometryService
{
	public interface IBiometryEncryptionFlowService
	{
		/// <summary>
		/// Tries to encrypt an object using the device's biometry APIs
		/// and saves it for later use. This is a flow with user interactions.
		/// You can use this in a login flow to encrypt the authentication request
		/// to be able to replay that authentication request again to avoids expired tokens, etc.
		/// </summary>
		/// <typeparam name="T">Type of the object to encrypt</typeparam>
		/// <param name="ct">Cancellation token</param>
		/// <param name="objectKey">
		/// Unique object key for this object. 
		/// Will be used to persist the object for decryption.
		/// Use something you can refer back to for localization or conditionals statements (e.g. "AuthenticationRequest").
		/// </param>
		/// <param name="objectToEncrypt">The object to encrypt</param>
		/// <returns>True if the object has been encrypted. False otherwise.</returns>
		Task<bool> TryBiometryEncryption<T>(CancellationToken ct, string objectKey, T objectToEncrypt);

		/// <summary>
		/// Tries to decrypt the saved object using the device's biometry APIs.
		/// This is a flow with user interactions.
		/// </summary>
		/// <typeparam name="T">Type of the object to decrypt</typeparam>
		/// <param name="ct">Cancellation token</param>
		/// <param name="objectKey">Unique object key for this object. Use the key used for the object's encryption.</param>
		/// <returns>The decrypted object if it has been decrypted. Default(T) otherwise.</returns>
		Task<T> TryBiometryDecryption<T>(CancellationToken ct, string objectKey);

		/// <summary>
		/// Determines if Biometry encryption is supported on the device and
		/// that the user is enrolled in the biometry APIs of the device.
		/// </summary>
		/// <returns>True if the biometry encryption can be used. False otherwise.</returns>
		IObservable<bool> GetAndObserveCanUseBiometryEncryption();
	}
}
