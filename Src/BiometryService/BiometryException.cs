using System;
using System.Collections.Generic;
using System.Text;

namespace BiometryService
{
    public class BiometryException : Exception
    {
        public BiometryException()
        {
        }

        public BiometryException(string message) : base(message)
        {
        }

        public BiometryException(Exception exception)
        {
        }

        //public BiometryFailedException(NSError message) : base(message)
        //{
        //}
    }

    public class BiometryCanceledException : Exception
    {
        public BiometryCanceledException()
        {
        }

        public BiometryCanceledException(string message) : base(message)
        {
        }

        public BiometryCanceledException(Exception exception)
        {
        }

        //public BiometryCanceledException(NSError message) : base(message)
        //{
        //}

        object NativeError(NSError)
        {

        }
    }
}