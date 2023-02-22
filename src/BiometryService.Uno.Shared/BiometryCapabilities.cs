namespace BiometryService;

/// <summary>
/// This entity represents the device biometric capabilities.
/// </summary>
public readonly struct BiometryCapabilities
{
	public BiometryCapabilities(BiometryType biometryType, bool isEnabled, bool isPasscodeSet)
	{
		BiometryType = biometryType;
		IsEnabled = isEnabled;
		IsPasscodeSet = isPasscodeSet;
	}

	/// <summary>
	/// Gets the <see cref="BiometryType"/> supported by the device.
	/// </summary>
	public BiometryType BiometryType { get; }

	/// <summary>
	/// Gets whether the passcode has been set on the device.
	/// </summary>
	public bool IsPasscodeSet { get; }

	/// <summary>
	/// Gets whether the device has biometrics enabled.
	/// </summary>
	/// <remarks>
	///		<para>
	///		<see cref="IsEnabled" /> can be <c>false</c> if the the user has not enrolled biometrics by adding a finger or
	///			face. <see cref="IsEnabled" /> can also be <c>false</c> if the user has disabled permission for the application
	///			to use biometrics in the device settings.
	///		</para>
	/// </remarks>
	public bool IsEnabled { get; }

	/// <summary>
	/// Gets whether the device supports biometrics.
	/// </summary>
	public bool IsSupported => BiometryType != 0;
}
