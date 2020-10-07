#if !__ANDROID__ && !__IOS__
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BiometryService
{
	public partial class BiometryImplementationHelper
	{
		private static BiometryImplementation GetBiometryImplementation()
		{
			return BiometryImplementation.Unavailable;
		}
	}
}
#endif