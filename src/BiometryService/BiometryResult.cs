using System;
using System.Collections.Generic;
using System.Text;

namespace BiometryService
{
	/// <summary>
	///     The class for BiometryResult
	/// </summary>
	public class BiometryResult
	{
		/// <value>Gets and sets the value of Code.</value>
		public string Code { get; set; }
		/// <value>Gets and sets the value of AuthenticationResult.</value>
		public BiometryAuthenticationResult AuthenticationResult { get; set; }
		/// <value>Gets and sets the value of Message.</value>
		public string Message { get; set; }
	}

	/// <summary>
	///     The class for BiometryException
	/// </summary>
	public class BiometryException : Exception
	{
		public BiometryException()
		{
		}

		public BiometryException(int code, string message) : base(message)
		{
		}

		public BiometryException(Exception exception)
		{
		}
	}

	/// <summary>
	///     Defines the possible results of user authentication using biometrics.
	/// </summary>
	public enum BiometryAuthenticationResult
	{
		/// <summary>
		///     The user has passed biometric authentication.
		/// </summary>
		Granted = 0,

		/// <summary>
		///     The user has failed biometric authentication.
		/// </summary>
		Denied,

		/// <summary>
		///     The user has refused biometric authentication.
		/// </summary>
		Cancelled
	}
}
