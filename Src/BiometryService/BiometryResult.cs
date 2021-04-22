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
	///     The class for AuthenticationErrors
	/// </summary>
	public class AuthenticationError : Exception
	{
		/// <summary>
		///     Constructor of AuthenticationError
		/// </summary>
		/// <param name="code">An integer Code.</param>
		/// <param name="message">A string message.</param>
		public AuthenticationError(int code, string message) : base(message)
		{
			this.Code = code;
		}

		/// <value>Gets and sets the value of Code.</value>
		public int Code { get; }
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
