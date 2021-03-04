using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace BiometryService.SampleApp.Uno
{
	/// <summary>
	/// An empty page that can be used on its own or navigated to within a Frame.
	/// </summary>
	public sealed partial class MainPage : Page
	{
		private readonly IBiometryService _biometryService;

		public MainPage()
		{
			this.InitializeComponent();

			var options = new BiometryOptions();
			options.LocalizedReasonBodyText = "REASON THAT APP WANTS TO USE BIOMETRY :)";
			options.LocalizedFallbackButtonText = "FALLBACK :(";
			options.LocalizedCancelButtonText = "CANCEL :'(";

			// use LAPolicy.DeviceOwnerAuthenticationWithBiometrics for biometrics only with no fallback to passcode/password
			// use LAPolicy.DeviceOwnerAuthentication for biometrics+watch with fallback to passcode/password
			//_biometryService = new BiometryService.BiometryService(options, LAPolicy.DeviceOwnerAuthentication);
		}

		private async Task Authenticate(CancellationToken ct)
		{
			var capabilities = _biometryService.GetCapabilities();
			if (!capabilities.PasscodeIsSet || !capabilities.IsSupported || !capabilities.IsEnabled)
			{
				//if (!capabilities.PasscodeIsSet)
				//{
				//	View.BackgroundColor = UIColor.Black;
				//}
				//else if (!capabilities.IsSupported)
				//{
				//	View.BackgroundColor = UIColor.Brown;
				//}
				//else if (!capabilities.IsEnabled)
				//{
				//	View.BackgroundColor = UIColor.SystemGray2Color;
				//}

				return;
			}

			var result = await _biometryService.Authenticate(ct);
			switch (result)
			{
				//case BiometryAuthenticationResult.Granted:
				//	View.BackgroundColor = UIColor.SystemGreenColor;
				//	break;
				//case BiometryAuthenticationResult.Denied:
				//	View.BackgroundColor = UIColor.SystemRedColor;
				//	break;
				//case BiometryAuthenticationResult.Cancelled:
				//	View.BackgroundColor = UIColor.SystemYellowColor;
				//	break;
			}
		}

	}
}
