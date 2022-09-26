namespace BiometryService
{
	/// <summary>
	///     The device's current biometry capabilities.
	/// </summary>
	public readonly struct BiometryCapabilities
	{
		/// <summary>
		///     The biometric identifier type supported by the device.
		/// </summary>
		public BiometryType BiometryType { get; }

		/// <summary>
		///     Gets a <see cref="bool" /> indicating whether the device has a passcode/password set by the user.
		/// </summary>
		public bool PasscodeIsSet { get; }

		/// <summary>
		///     Gets a <see cref="bool" /> indicating whether the device has biometrics enabled.
		/// </summary>
		/// <remarks>
		///     <para>
		///         <see cref="IsEnabled" /> can be <c>false</c> if the the user has not enrolled biometrics by adding a finger or
		///         face. <see cref="IsEnabled" /> can also be <c>false</c> if the user has disabled permission for the application
		///         to use biometrics in the device settings.
		///     </para>
		/// </remarks>
		public bool IsEnabled { get; }

		/// <summary>
		///     Gets a <see cref="bool" /> indicating whether the device supports biometrics.
		/// </summary>
		public bool IsSupported => BiometryType != BiometryType.None;

		public BiometryCapabilities(BiometryType biometryType, bool biometryIsEnabled, bool passcodeIsSet)
		{
			BiometryType = biometryType;
			IsEnabled = biometryIsEnabled;
			PasscodeIsSet = passcodeIsSet;
		}
	}
}
