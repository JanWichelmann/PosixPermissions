using System;
using System.Collections.Generic;
using System.Text;

namespace PosixPermissions
{
    /// <summary>
    /// Represents generic exceptions occuring during execution of native functions.
    /// </summary>
    public class NativeException : Exception
    {
        /// <summary>
        /// Returns the name of the native API method which returned the error code.
        /// </summary>
        public string NativeMethodName { get; }

        /// <summary>
        /// The error code returned by the native implementation.
        /// </summary>
        public NativeErrorCodes ErrorCode { get; }

        /// <summary>
        /// Returns the last errno value of the native implementation.
        /// </summary>
        public long Errno { get; }

        /// <summary>
        /// Returns the string representation of <see cref="Errno"/> (using strerror()).
        /// </summary>
        public string ErrnoString { get; }

        /// <summary>
        /// Creates a new exception from the given native error code and errno value.
        /// </summary>
        /// <param name="nativeFunctionName">Name of the native API method which returned the error code.</param>
        /// <param name="errorCode">Native error code of this exception.</param>
        /// <param name="errno">Value of errno (or 0, if not applicable).</param>
        /// <param name="errnoString">The string representation of errno (if applicable).</param>
        internal NativeException(string nativeMethodName, NativeErrorCodes errorCode, long errno, string errnoString)
            : this(nativeMethodName, errorCode, errno, errnoString, BuildExceptionMessageString(nativeMethodName, errorCode, errno, errnoString))
        { }

        /// <summary>
        /// Creates a new exception from the given native error code and errno value, using the given exception message.
        /// </summary>
        /// <param name="nativeFunctionName">Name of the native API method which returned the error code.</param>
        /// <param name="errorCode">Native error code of this exception.</param>
        /// <param name="errno">Value of errno (or 0, if not applicable).</param>
        /// <param name="errnoString">The string representation of errno (if applicable).</param>
        /// <param name="message">The exception message to display.</param>
        protected NativeException(string nativeMethodName, NativeErrorCodes errorCode, long errno, string errnoString, string message)
            : base(message)
        {
            NativeMethodName = nativeMethodName;
            ErrorCode = errorCode;
            Errno = errno;
            ErrnoString = errnoString;
        }

        /// <summary>
        /// Combines the exception data into a single generic message string.
        /// </summary>
        /// <param name="nativeMethodName">Name of the native API method which returned the error code.</param>
        /// <param name="errorCode">Native error code of this exception.</param>
        /// <param name="errno">Value of errno.</param>
        /// <param name="errnoString">The string representation of errno.</param>
        private static string BuildExceptionMessageString(string nativeMethodName, NativeErrorCodes errorCode, long errno, string errnoString)
        { 
            string prefix = $"Error in {nativeMethodName}: ";
            string functionErrnoSuffix = $"() failed with errno = {errnoString} [{errno}].";
            return prefix + errorCode switch
            {
                NativeErrorCodes.NATIVE_ERROR_OPEN_FAILED => prefix + "open" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_FSTAT_FAILED => prefix + "fstat" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_GET_ACL_FAILED => prefix + "acl_get_fd" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_GET_ACL_ENTRY_FAILED => prefix + "acl_get_entry" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_GET_ACL_ENTRY_TAG_TYPE_FAILED => prefix + "acl_get_tag_type" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_GET_ACL_ENTRY_QUALIFIER_FAILED => prefix + "acl_get_qualifier" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_GET_ACL_ENTRY_PERMSET_FAILED => prefix + "acl_get_permset" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_GET_ACL_ENTRY_PERM_FAILED => prefix + "acl_get_perm" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_CHOWN_FAILED => prefix + "fchown" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_CHMOD_FAILED => prefix + "fchmod" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_INIT_ACL_FAILED => prefix + "acl_init" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_CREATE_ACL_ENTRY_FAILED => prefix + "acl_create_entry" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_INVALID_TAG_TYPE => prefix + "The given entry tag type was invalid.",
                NativeErrorCodes.NATIVE_ERROR_SET_ACL_ENTRY_TAG_TYPE_FAILED => prefix + "acl_set_tag_type" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_SET_ACL_ENTRY_QUALIFIER_FAILED => prefix + "acl_set_qualifier" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_CLEAR_ACL_ENTRY_PERMS_FAILED => prefix + "acl_clear_perms" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_ADD_ACL_ENTRY_PERM_FAILED => prefix + "acl_add_perm" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_VALIDATE_ACL_FAILED => prefix + "acl_valid" + functionErrnoSuffix,
                NativeErrorCodes.NATIVE_ERROR_SET_ACL_FAILED => prefix + "acl_set_file" + functionErrnoSuffix,
                _ => "Unknown native error.",
            };
        }
    }
}
