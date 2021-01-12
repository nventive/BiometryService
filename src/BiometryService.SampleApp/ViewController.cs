using System;
using System.Threading;
using System.Threading.Tasks;
using Foundation;
using LocalAuthentication;
using UIKit;

namespace BiometryService.SampleApp
{
	public partial class ViewController : UIViewController
	{
		private readonly IBiometryService _biometryService;

		public ViewController(IntPtr handle) : base(handle)
		{
			var options = new BiometryOptions();
			options.LocalizedReasonBodyText = "REASON THAT APP WANTS TO USE BIOMETRY :)";
			options.LocalizedFallbackButtonText = "FALLBACK :(";
			options.LocalizedCancelButtonText = "CANCEL :'(";

			// use LAPolicy.DeviceOwnerAuthenticationWithBiometrics for biometrics only with no fallback to passcode/password
			// use LAPolicy.DeviceOwnerAuthentication for biometrics+watch with fallback to passcode/password
			_biometryService = new BiometryService(options, LAPolicy.DeviceOwnerAuthentication);
		}

		public override void ViewDidLoad()
		{
			base.ViewDidLoad();
			// Perform any additional setup after loading the view, typically from a nib.
		}

		public override void DidReceiveMemoryWarning()
		{
			base.DidReceiveMemoryWarning();
			// Release any cached data, images, etc that aren't in use.
		}

		partial void OnClickAuthenticate(NSObject sender)
		{
			var cancellationTokenSource = new CancellationTokenSource();
			var ct = cancellationTokenSource.Token;
			var authenticateTask = Task.Factory.StartNew(
				async () => await Authenticate(ct),
				ct,
				TaskCreationOptions.None,
				TaskScheduler.FromCurrentSynchronizationContext());

			Task.WaitAll(authenticateTask);

			var up = authenticateTask.Result.Exception;
			if (up != null)
			{
				throw up;
			}
		}

		private async Task Authenticate(CancellationToken ct)
		{
			var capabilities = _biometryService.GetCapabilities();
			if (!capabilities.PasscodeIsSet || !capabilities.IsSupported || !capabilities.IsEnabled)
			{
				if (!capabilities.PasscodeIsSet)
				{
					View.BackgroundColor = UIColor.Black;
				}
				else if (!capabilities.IsSupported)
				{
					View.BackgroundColor = UIColor.Brown;
				}
				else if (!capabilities.IsEnabled)
				{
					View.BackgroundColor = UIColor.SystemGray2Color;
				}

				return;
			}

			var result = await _biometryService.Authenticate(ct);
			switch (result)
			{
				case BiometryAuthenticationResult.Granted:
					View.BackgroundColor = UIColor.SystemGreenColor;
					break;
				case BiometryAuthenticationResult.Denied:
					View.BackgroundColor = UIColor.SystemRedColor;
					break;
				case BiometryAuthenticationResult.Cancelled:
					View.BackgroundColor = UIColor.SystemYellowColor;
					break;
			}
		}
	}
}
