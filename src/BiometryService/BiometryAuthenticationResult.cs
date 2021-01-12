namespace BiometryService
{
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
