using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BiometryService
{
	public partial class BiometryImplementationHelper
	{
		private static BiometryImplementation? _BiometryImplementation;

		public static BiometryImplementation BiometryImplementation
		{
			get
			{
#if __ANDROID__
				// On Android, we need to check the permission everytime.
				_BiometryImplementation = GetBiometryImplementation();
#else
				if (_BiometryImplementation == null)
				{
					_BiometryImplementation = GetBiometryImplementation();
				}
#endif
				return _BiometryImplementation ?? BiometryImplementation.Unavailable;

			}
		}
	}
}
