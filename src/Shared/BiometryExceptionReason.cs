namespace BiometryService
{
	/// <summary>
	/// This enum helps categorize all possibles reasons that <see cref="BiometryException"/> has been raised.
	/// </summary>
	public enum BiometryExceptionReason
	{
		/// <summary>
		/// Any other failures while trying to use the device biometrics.
		/// </summary>
		Failed = 0,

		/// <summary>
		/// The device biometrics is not available.
		/// </summary>
		Unavailable,

		/// <summary>
		/// The device has not been enrolled to use biometrics.
		/// </summary>
		NotEnrolled,

		/// <summary>
		/// The passcode needs to be set on the device.
		/// </summary>
		PasscodeNeeded,

		/// <summary>
		/// The device has been locked from using his biometrics.
		/// Due mostly to too many attempts.
		/// </summary>
		Locked,

		/// <summary>
		/// Biometric information has changed (E.g. Touch ID or Face ID has changed).
		/// User have to set up biometric authentication again.
		/// </summary>
		KeyNotFound
	}
}
