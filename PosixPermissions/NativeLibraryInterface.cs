using Mono.Unix.Native;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PosixPermissions
{
    /// <summary>
    /// Exposes a direct interface to the underlying native library.
    /// </summary>
    public class NativeLibraryInterface : INativeLibraryInterface
    {
        /// <summary>
        /// Path to the underlying native library, which is invoked from here.
        /// </summary>
        private const string NativeLibraryPath = "acl_native.so";

        /// <summary>
        /// Used for locking access to native functions (native library isn't thread safe).
        /// </summary>
        private readonly object _nativeFunctionsLock = new object();

        /// <summary>
        /// <para>Opens the ACL of the given file or directory, and reads its permission data.</para>
        /// <para>The file is kept open and must be closed using <see cref="ReadFileAclAndClose(AccessControlListEntry[])"/>.</para>
        /// </summary>
        /// <param name="fileName">The file or directory to query.</param>
        /// <param name="loadDefaultAcl">Specifies whether to load a directory's default ACL (1) or not (0). This must be 0 for files.</param>
        /// <param name="dataContainer">Pointer to container object to store retrieved permissions and assoiated meta data.</param>
        [DllImport(NativeLibraryPath, EntryPoint = "OpenFileAndReadPermissionData")]
        private static extern NativeErrorCodes OpenFileAndReadPermissionData([In, MarshalAs(UnmanagedType.LPUTF8Str)] string fileName, [In] int loadDefaultAcl, [Out] out NativePermissionDataContainer dataContainer);

        /// <summary>
        /// Retrieves the ACL entries from the previously opened file. The file is automatically closed afterwards.
        /// </summary>
        /// <param name="entries">Array with empty ACL entries to be filled by the native implementation.</param>
        [DllImport(NativeLibraryPath, EntryPoint = "ReadFileAclAndClose")]
        private static extern NativeErrorCodes ReadFileAclAndClose([Out] AccessControlListEntry[] entries);

        /// <summary>
        /// Sets the permission data and ACL entries of the given file.
        /// </summary>
        /// <param name="fileName">The file or directory to update.</param>
        /// <param name="setDefaultAcl">Specifies whether to set a directory's default ACL (1) or not (0). This must be 0 for files.</param>
        /// <param name="dataContainer">Pointer to container object with permissions and assoiated meta data.</param>
        /// <param name="entries">Array with ACL entries to be written.</param>
        [DllImport(NativeLibraryPath, EntryPoint = "SetFilePermissionDataAndAcl")]
        private static extern NativeErrorCodes SetFilePermissionDataAndAcl([In, MarshalAs(UnmanagedType.LPUTF8Str)] string fileName, [In] int setDefaultAcl, [In] ref NativePermissionDataContainer dataContainer, [In] AccessControlListEntry[] entries);

        /// <summary>
        /// <para>Returns the last value of "errno" and its string representation.</para>
        /// <para>This function will return 0 and an empty error string if called without an error actually having occured in the last P/Invoke function call.</para>
        /// </summary>
        /// <param name="errnoString">Pointer to <see cref="StringBuilder"/> object to return the last value of strerror().</param>
        /// <param name="errnoStringBufferLength">Length of the error string buffer passed in <paramref name="errnoString"/>.</param>
        [DllImport(NativeLibraryPath, EntryPoint = "GetLastErrnoValue")]
        private static extern long GetLastErrnoValue([Out, MarshalAs(UnmanagedType.LPUTF8Str)] StringBuilder errnoString, [In] int errnoStringBufferLength);

        /// <summary>
        /// Retrieves the error information from the native implementation and constructs a new <see cref="NativeException"/> object, that can be thrown afterwards.
        /// </summary>
        /// <param name="nativeMethodName">Name of the native API method which returned the error code.</param>
        /// <param name="errorCode">The error code returned by the native API method.</param>
        /// <param name="errnoResolvable">This will tell whether the retrieved errno could be resolved into a symbolic representation.</param>
        /// <param name="errnoSymbolic">This will hold the symbolic value of the retrieved errno; check the <paramref name="errnoResolvable"/> parameter beforehand!</param>
        private NativeException RetrieveErrnoAndBuildException(string nativeMethodName, NativeErrorCodes errorCode, out bool errnoResolvable, out Errno errnoSymbolic)
        {
            // Retrieve errno
            var errnoStringBuffer = new StringBuilder(256);
            long errno = GetLastErrnoValue(errnoStringBuffer, errnoStringBuffer.Capacity);

            // Try to resolve to symbolic representation
            errnoResolvable = NativeConvert.TryToErrno((int)errno, out errnoSymbolic);

            // Create native exception object
            return new NativeException(nativeMethodName, errorCode, errno, (errnoResolvable ? errnoSymbolic.ToString() + ", " : "") + errnoStringBuffer.ToString());
        }

        /// <inheritdoc />
        /// <exception cref="UnauthorizedAccessException">Thrown when trying to open a file/directory without having sufficient access permissions.</exception>
        /// <exception cref="FileNotFoundException">Thrown when a file/directory or parts of its path cannot be found.</exception>
        /// <exception cref="NativeException">Generic exception thrown when a native method fails, and the error was not covered by one of the other possible exceptions. This exception is also always included as the <see cref="Exception.InnerException"/>.</exception>
        public AccessControlListEntry[] GetPermissionData(string fileName, int loadDefaultAcl, out NativePermissionDataContainer dataContainer)
        {
            // Ensure exclusive access to native functions
            lock(_nativeFunctionsLock)
            {
                // Read permission data and retrieve ACL size
                NativeErrorCodes err = OpenFileAndReadPermissionData(fileName, loadDefaultAcl, out dataContainer);
                if(err != NativeErrorCodes.NATIVE_ERROR_SUCCESS)
                {
                    // Throw suitable exceptions
                    var nativeException = RetrieveErrnoAndBuildException(nameof(OpenFileAndReadPermissionData), err, out var _, out var errnoSymbolic);
                    switch(err)
                    {
                        // Handle certain special exception cases
                        case NativeErrorCodes.NATIVE_ERROR_OPEN_FAILED when errnoSymbolic == Errno.EACCES:
                            throw new UnauthorizedAccessException($"Could not open \"{fileName}\" for reading.", nativeException);
                        case NativeErrorCodes.NATIVE_ERROR_OPEN_FAILED when errnoSymbolic == Errno.ENOENT:
                            throw new FileNotFoundException($"Could not open \"{fileName}\" for reading.", nativeException);

                        // Unhandled case, just throw generic exception directly
                        default:
                            throw nativeException;
                    }
                }

                // Read ACL
                AccessControlListEntry[] acl = new AccessControlListEntry[dataContainer.AclSize];
                err = ReadFileAclAndClose(acl);
                if(err != NativeErrorCodes.NATIVE_ERROR_SUCCESS)
                    throw RetrieveErrnoAndBuildException(nameof(ReadFileAclAndClose), err, out var _, out var _);
                return acl;
            }
        }

        /// <inheritdoc />
        /// <exception cref="UnauthorizedAccessException">Thrown when trying to open or modify a file/directory without having sufficient access permissions.</exception>
        /// <exception cref="FileNotFoundException">Thrown when a file/directory or parts of its path cannot be found.</exception>
        /// <exception cref="ArgumentException">Thrown when the provided ACL is invalid.</exception>
        /// <exception cref="NativeException">Generic exception thrown when a native method fails, and the error was not covered by one of the other possible exceptions. This exception is also always included as the <see cref="Exception.InnerException"/>.</exception>
        public void SetPermissionData(string fileName, int setDefaultAcl, ref NativePermissionDataContainer dataContainer, AccessControlListEntry[] entries)
        {
            // Ensure exclusive access to native functions
            lock(_nativeFunctionsLock)
            {
                // Make sure the meta data object is valid
                dataContainer.AclSize = entries.Length;

                // Set permissions and ACL
                NativeErrorCodes err = SetFilePermissionDataAndAcl(fileName, setDefaultAcl, ref dataContainer, entries);
                if(err != NativeErrorCodes.NATIVE_ERROR_SUCCESS)
                {
                    // Throw suitable exceptions
                    var nativeException = RetrieveErrnoAndBuildException(nameof(SetFilePermissionDataAndAcl), err, out var _, out var errnoSymbolic);
                    switch(err)
                    {
                        // Handle certain special exception cases
                        case NativeErrorCodes.NATIVE_ERROR_OPEN_FAILED when errnoSymbolic == Errno.EACCES:
                            throw new UnauthorizedAccessException($"Could not open \"{fileName}\" for reading.", nativeException);
                        case NativeErrorCodes.NATIVE_ERROR_OPEN_FAILED when errnoSymbolic == Errno.ENOENT:
                            throw new FileNotFoundException($"Could not open \"{fileName}\" for reading.", nativeException);

                        case NativeErrorCodes.NATIVE_ERROR_CHOWN_FAILED when errnoSymbolic == Errno.EPERM:
                            throw new UnauthorizedAccessException($"Permission denied when using fchown() on \"{fileName}\".", nativeException);

                        case NativeErrorCodes.NATIVE_ERROR_CHMOD_FAILED when errnoSymbolic == Errno.EPERM:
                            throw new UnauthorizedAccessException($"Permission denied when using fchmod() on \"{fileName}\".", nativeException);

                        case NativeErrorCodes.NATIVE_ERROR_VALIDATE_ACL_FAILED when errnoSymbolic == Errno.EINVAL:
                            throw new ArgumentException($"The given ACL is invalid.", nativeException);

                        case NativeErrorCodes.NATIVE_ERROR_SET_ACL_FAILED when errnoSymbolic == Errno.EINVAL:
                            throw new ArgumentException($"Could not assign ACL to file \"{fileName}\" using acl_set_fd().", nativeException);
                        case NativeErrorCodes.NATIVE_ERROR_SET_ACL_FAILED when errnoSymbolic == Errno.EPERM:
                            throw new UnauthorizedAccessException($"Permission denied when assigning ACL using acl_set_fd() on \"{fileName}\".", nativeException);

                        // Unhandled case, just throw generic exception directly
                        default:
                            throw nativeException;
                    }
                }
            }
        }
    }

    /// <summary>
    /// Container object to pass permission data between C# and native code, to avoid a large amount of function parameters.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct NativePermissionDataContainer
    {
        /// <summary>
        /// The UID of the object's owner.
        /// </summary>
        public int OwnerId;

        /// <summary>
        /// The permissions of the object's owner.
        /// </summary>
        public FilePermissions OwnerPermissions;

        /// <summary>
        /// The GID of the object's associated group.
        /// </summary>
        public int GroupId;

        /// <summary>
        /// The permissions of the object's associated group.
        /// </summary>
        public FilePermissions GroupPermissions;

        /// <summary>
        /// The permissions of "others".
        /// </summary>
        public FilePermissions OtherPermissions;

        /// <summary>
        /// The size of the file's associated ACL.
        /// </summary>
        public int AclSize;
    }

    /// <summary>
    /// Defines the error codes that might be returned by the native implementation. Documentation can be found in the respective header file.
    /// </summary>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public enum NativeErrorCodes : int
    {
        NATIVE_ERROR_SUCCESS = 0,
        NATIVE_ERROR_OPEN_FAILED = 1,
        NATIVE_ERROR_FSTAT_FAILED = 2,
        NATIVE_ERROR_GET_ACL_FAILED = 3,
        NATIVE_ERROR_GET_ACL_ENTRY_FAILED = 4,
        NATIVE_ERROR_GET_ACL_ENTRY_TAG_TYPE_FAILED = 5,
        NATIVE_ERROR_GET_ACL_ENTRY_QUALIFIER_FAILED = 6,
        NATIVE_ERROR_GET_ACL_ENTRY_PERMSET_FAILED = 7,
        NATIVE_ERROR_GET_ACL_ENTRY_PERM_FAILED = 8,
        NATIVE_ERROR_CHOWN_FAILED = 9,
        NATIVE_ERROR_CHMOD_FAILED = 10,
        NATIVE_ERROR_INIT_ACL_FAILED = 11,
        NATIVE_ERROR_CREATE_ACL_ENTRY_FAILED = 12,
        NATIVE_ERROR_INVALID_TAG_TYPE = 13,
        NATIVE_ERROR_SET_ACL_ENTRY_TAG_TYPE_FAILED = 14,
        NATIVE_ERROR_SET_ACL_ENTRY_QUALIFIER_FAILED = 15,
        NATIVE_ERROR_CLEAR_ACL_ENTRY_PERMS_FAILED = 16,
        NATIVE_ERROR_ADD_ACL_ENTRY_PERM_FAILED = 17,
        NATIVE_ERROR_VALIDATE_ACL_FAILED = 18,
        NATIVE_ERROR_SET_ACL_FAILED = 19,
    };
}
