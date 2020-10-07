#if __IOS__
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Foundation;
using LocalAuthentication;
using UIKit;

namespace BiometryService
{
	public partial class BiometryImplementationHelper
	{
		/// <summary>
		/// Minimal version supporting LAContext.BiometryType;
		/// </summary>
		private static readonly Version _minimalVersionBiometryType = new Version("11.0.1");

		private static BiometryImplementation GetBiometryImplementation()
		{
			if (UIDevice.CurrentDevice.CheckSystemVersion(8, 0))
			{
				var context = new LAContext();

				// Evaluate the Biometry policies. Even if the following call fails and returns fals, the
				// context.BiometryType field will still be set, and that's the only information we need.
				// See https://developer.apple.com/documentation/localauthentication/lacontext/1514149-canevaluatepolicy
				// for the doc. The return value is irrelevant for this specific purpose.
				//
				// This is important, because it is possible to get errors here due to various reasons.
				// Either the user has been locked out of Biometrys due to too many failed attempts, or
				// the device does not have an enrolled entity. In both cases, apps might require the
				// biometry type anyways to display an accurate message to the user. 
				// 
				// However, this behaviour does not seem to be the same accross all devices or iOS versions.
				// See this radar for more information about the bug https://openradar.appspot.com/36064151#ag9zfm9wZW5yYWRhci1ocmRyFAsSB0NvbW1lbnQYgICAuMqf8AgM
				// If for some reason the context.BiometryType was not set during the CanEvaluatePolicy call,
				// it will contain the value None (0). If such a value is held, we need to go through the
				// fallback procedure below.
				context.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrys, out NSError error);

				var systemVersion = new Version(UIDevice.CurrentDevice.SystemVersion);
				if (systemVersion >= _minimalVersionBiometryType) // Version 11.0.0 did not contain the BiometryType field. This means we cannot use CheckVersion because it only compares Major.Minor
				{
					switch (context.BiometryType)
					{
						case LABiometryType.TouchId:
							return BiometryImplementation.TouchId;

						case LABiometryType.FaceId:
							return BiometryImplementation.FaceId;

						case LABiometryType.None:
							return BiometryImplementation.Unavailable;
					}
				}

				else
				{
					return BiometryImplementation.TouchId;
				}
			}

			// Anything below iOS 8 does not support Biometrys
			return BiometryImplementation.Unavailable;
		}
	}
}
#endif
