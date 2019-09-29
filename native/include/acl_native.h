#pragma once
/*
Contains declarations of exposed types and functions (for C# interop).
*/

/* INCLUDES */

#include <stdint.h>
#include <assert.h>


/* TYPES */

// Defines the different types of file permissions.
typedef enum
{
	// No permissions.
	FILE_PERMISSION_NONE = 0,
	
	// The permission to execute (search) the given file (directory).
	FILE_PERMISSION_EXECUTE = 1,
	
	// The permission to write into the given file.
	FILE_PERMISSION_WRITE = 2,
	
	// The permission to read (list) the given file (directory).
	FILE_PERMISSION_READ = 4,
	
	// Set user/group ID on execution (SUID/SGID bit). Only valid for "owner" and "group".
	FILE_PERMISSION_SETID = 8,
	
	// Restricted deletion in directories (sticky bit). Only valid for "owner".
	FILE_PERMISSION_STICKY = 16
	
} native_file_permission_t;
static_assert(sizeof(native_file_permission_t) <= 4, "Native enum size does not match the one in C#. This might cause problems due to different struct sizes. Fix this!");

// ACL entry tag types.
typedef enum
{
	// The entry contains permissions for the owning user.
	ACL_ENTRY_TAG_TYPE_USER_OBJ = 1,
	
	// The entry contains permissions for a certain user.
	ACL_ENTRY_TAG_TYPE_USER = 2,
	
	// The entry contains permissions for the owning group.
	ACL_ENTRY_TAG_TYPE_GROUP_OBJ = 3,

	// The entry contains permissions for a certain group.
	ACL_ENTRY_TAG_TYPE_GROUP = 4,

	// The entry defines the maximum access permissions mask.
	ACL_ENTRY_TAG_TYPE_MASK = 5,

	// The entry contains permissions for subjects that do not match any other entry.
	ACL_ENTRY_TAG_TYPE_OTHER = 6
	
} native_acl_entry_tag_type_t;
static_assert(sizeof(native_acl_entry_tag_type_t) <= 4, "Native enum size does not match the one in C#. This might cause problems due to different struct sizes. Fix this!");

// Contains one POSIX access control list entry.
typedef struct
{
	// The entry tag type.
	native_acl_entry_tag_type_t tagType;

	// The entry tag qualifier (usually user or group ID).
	int32_t tagQualifier;

	// The entry permissions field.
    native_file_permission_t permissions;
		
} native_acl_entry_t;
static_assert(sizeof(native_acl_entry_t) == 3 * 4, "Native struct size does not match the one in C#. This will cause problems during P/Invoke. Fix this!");

// Container object to pass permission data between C# and native code, to avoid a large amount function parameters.
typedef struct
{
	// The UID of the object's owner.
	int32_t ownerId;

	// The permissions of the object's owner.
	native_file_permission_t ownerPermissions;

	// The GID of the object's associated group.
	int32_t groupId;

	// The permissions of the object's associated group.
	native_file_permission_t groupPermissions;

	// The permissions of "others".
	native_file_permission_t otherPermissions;

	// The size of the file's associated ACL.
	int32_t aclSize;
	
} native_permission_data_container_t;
static_assert(sizeof(native_permission_data_container_t) == 6 * 4, "Native struct size does not match the one in C#. This will cause problems during P/Invoke. Fix this!");

// Defines the error codes that might be returned by the native implementation.
typedef enum
{
	// Indicates that the operation completed successfully.
	NATIVE_ERROR_SUCCESS = 0,
	
	// Indicates that the open() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_OPEN_FAILED = 1,
	
	// Indicates that the fstat() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_FSTAT_FAILED = 2,
	
	// Indicates that the acl_get_fd() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_GET_ACL_FAILED = 3,
	
	// Indicates that the acl_get_entry() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_GET_ACL_ENTRY_FAILED = 4,
	
	// Indicates that the acl_get_tag_type() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_GET_ACL_ENTRY_TAG_TYPE_FAILED = 5,
	
	// Indicates that the acl_get_qualifier() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_GET_ACL_ENTRY_QUALIFIER_FAILED = 6,
	
	// Indicates that the acl_get_permset() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_GET_ACL_ENTRY_PERMSET_FAILED = 7,
	
	// Indicates that the acl_get_perm() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_GET_ACL_ENTRY_PERM_FAILED = 8,
	
	// Indicates that the fchown() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_CHOWN_FAILED = 9,
	
	// Indicates that the fchmod() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_CHMOD_FAILED = 10,
	
	// Indicates that the acl_init() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_INIT_ACL_FAILED = 11,
	
	// Indicates that the acl_create_entry() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_CREATE_ACL_ENTRY_FAILED = 12,
	
	// Indicates that an invalid/unknown entry tag type was supplied.
	NATIVE_ERROR_INVALID_TAG_TYPE = 13,
	
	// Indicates that the acl_set_tag_type() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_SET_ACL_ENTRY_TAG_TYPE_FAILED = 14,
	
	// Indicates that the acl_set_qualifier() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_SET_ACL_ENTRY_QUALIFIER_FAILED = 15,
	
	// Indicates that the acl_clear_perms() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_CLEAR_ACL_ENTRY_PERMS_FAILED = 16,
	
	// Indicates that the acl_add_perm() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_ADD_ACL_ENTRY_PERM_FAILED = 17,
	
	// Indicates that the acl_valid() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_VALIDATE_ACL_FAILED = 18,
	
	// Indicates that the acl_set_file() call failed. The corresponding errno value was stored.
	NATIVE_ERROR_SET_ACL_FAILED = 19,

} native_error_code_t;
static_assert(sizeof(native_error_code_t) <= 4, "Native enum size does not match the one in C#. Check this!");


/* FUNCTION DECLARATIONS */

// Opens the ACL of the given file or directory, and reads its permission data. The file is kept open and must be closed using "ReadFileAclAndClose".
//     fileName: The file or directory to query.
//     loadDefaultAcl: Specifies whether to load a directory's default ACL (1) or not (0). This must be 0 for files.
//     dataContainer: Pointer to container object to store retrieved permissions and assoiated meta data.
native_error_code_t OpenFileAndReadPermissionData(const char *fileName, int32_t loadDefaultAcl, native_permission_data_container_t *dataContainer);

// Retrieves the ACL entries from the previously opened file. The file is automatically closed afterwards.
//     entries: Array with empty ACL entries to be filled by the native implementation.
native_error_code_t ReadFileAclAndClose(native_acl_entry_t *entries);

// Sets the permission data and ACL entries of the given file.
//     fileName: The file or directory to update.
//     setDefaultAcl: Specifies whether to set a directory's default ACL (1) or not (0). This must be 0 for files.
//     dataContainer: Pointer to container object with permissions and assoiated meta data.
//     entries: Array with ACL entries to be written.
native_error_code_t SetFilePermissionDataAndAcl(const char *fileName, int32_t setDefaultAcl, native_permission_data_container_t *dataContainer, native_acl_entry_t *entries);

// Returns the last value of "errno" and its string representation.
// This function will return 0 and an empty error string if called without an error actually having occured in the last P/Invoke function call.
//     errnoStringBuffer: Pointer to a string buffer to return the last value of strerror().
//     errnoStringBufferLength: Length of the error string buffer passed in errnoStringBuffer.
int64_t GetLastErrnoValue(char *errnoStringBuffer, int errnoStringBufferLength);