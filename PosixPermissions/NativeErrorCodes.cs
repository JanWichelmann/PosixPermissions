using System.Diagnostics.CodeAnalysis;

namespace PosixPermissions
{
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