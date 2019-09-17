/* INCLUDES */

#include "acl_native.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/acl.h>
#include <fcntl.h>
#include <errno.h>


/* GLOBAL VARIABLES */

// The file descriptor returned by open().
static int _fd = NULL;

// The current ACL handle.
static acl_t _acl = NULL;

// The last errno value;
static int _lastErrnoValue = 0;

// The last value of str_error().
static char _lastErrnoString[256] = { 0 };


/* UTILITY FUNCTIONS */

// Stores the current value of errno.
static void store_errno(void)
{
	_lastErrnoValue = errno;
	strerror_r(errno, _lastErrnoString, sizeof(_lastErrnoString));
}

// Cleans up the file descriptor and the ACL handle (if set), and returns the given error code.
static native_error_code_t cleanup_with_error_code(native_error_code_t errorCode)
{
	if(_acl)
	{
		acl_free(_acl);
		_acl = NULL;
	}
	if(_fd)
	{
		close(_fd);
		_fd = NULL;
	}
	return errorCode;
}


/* EXPOSED API FUNCTIONS */

extern native_error_code_t OpenFileAndReadPermissionData(const char *fileName, int32_t loadDefaultAcl, native_permission_data_container_t *dataContainer);
{
	// Reset errno
	_lastErrnoValue = 0;
	
	// Open file or directory
	_fd = open(fileName, O_RDONLY);
	if(_fd < 0)
	{
		store_errno();
		return NATIVE_ERROR_OPEN_FAILED;
	}
	
	// Read file metadata
	struct stat fileStat;
	if(fstat(_fd, &fileStat) < 0)
	{
		store_errno();
		return cleanup_with_error_code(NATIVE_ERROR_FSTAT_FAILED);
	}
	
	// Fill basic permission fields
	dataContainer->ownerId = fileStat.st_uid;
	dataContainer->groupId = fileStat.st_git;
	dataContainer->ownerPermissions = ((fileStat.st_mode & S_IRUSR) ? FILE_PERMISSION_READ : FILE_PERMISSION_NONE)
	                                | ((fileStat.st_mode & S_IWUSR) ? FILE_PERMISSION_WRITE : FILE_PERMISSION_NONE)
	                                | ((fileStat.st_mode & S_IXUSR) ? FILE_PERMISSION_EXECUTE : FILE_PERMISSION_NONE)
	                                | ((fileStat.st_mode & S_ISUID) ? FILE_PERMISSION_SETID : FILE_PERMISSION_NONE)
	                                | ((fileStat.st_mode & S_ISVTX) ? FILE_PERMISSION_STICKY : FILE_PERMISSION_NONE);
	dataContainer->groupPermissions = ((fileStat.st_mode & S_IRGRP) ? FILE_PERMISSION_READ : FILE_PERMISSION_NONE)
	                                | ((fileStat.st_mode & S_IWGRP) ? FILE_PERMISSION_WRITE : FILE_PERMISSION_NONE)
	                                | ((fileStat.st_mode & S_IXGRP) ? FILE_PERMISSION_EXECUTE : FILE_PERMISSION_NONE)
	                                | ((fileStat.st_mode & S_ISGID) ? FILE_PERMISSION_SETID : FILE_PERMISSION_NONE);
	dataContainer->otherPermissions = ((fileStat.st_mode & S_IROTH) ? FILE_PERMISSION_READ : FILE_PERMISSION_NONE)
	                                | ((fileStat.st_mode & S_IWOTH) ? FILE_PERMISSION_WRITE : FILE_PERMISSION_NONE)
	                                | ((fileStat.st_mode & S_IXOTH) ? FILE_PERMISSION_EXECUTE : FILE_PERMISSION_NONE);
	
	// Try to load ACL
	_acl = acl_get_fd(_fd, loadDefaultAcl > 0 ? ACL_TYPE_DEFAULT : ACL_TYPE_ACCESS);
	if(!_acl)
	{
		store_errno();
		return cleanup_with_error_code(NATIVE_ERROR_GET_ACL_FAILED);
	}
	
	// Iterate ACL and determine entry count
	int aclSize = 0;
	acl_entry_t currEntry;
	int aclStatus = acl_get_entry(_acl, ACL_FIRST_ENTRY, &currEntry);
	while(aclStatus > 0)
	{
		++aclSize;
		aclStatus = acl_get_entry(_acl, ACL_NEXT_ENTRY, &currEntry);
	}
	if(aclStatus < 0)
	{
		store_errno();
		return cleanup_with_error_code(NATIVE_ERROR_GET_ACL_ENTRY_FAILED);
	}
	dataContainer->aclSize = (int32_t)aclSize;
	
	// Done
	return NATIVE_ERROR_SUCCESS;
}

extern native_error_code_t ReadFileAclAndClose(native_acl_entry_t *entries)
{
	// Reset errno
	_lastErrnoValue = 0;
	
	// Iterate ACL
	acl_entry_t currEntry;
	int aclStatus = acl_get_entry(_acl, ACL_FIRST_ENTRY, &currEntry);
	int i = 0;
	while(aclStatus > 0)
	{
		// Get pointer to current target array entry
		native_acl_entry_t *e = &entries[i];
		
		// Set tag type
		acl_tag_t tagType;
		if(acl_get_tag_type(currEntry, &tagType) < 0)
		{
			store_errno();
			return cleanup_with_error_code(NATIVE_ERROR_GET_ACL_ENTRY_TAG_TYPE_FAILED);
		}
		switch(tagType)
		{
			case ACL_USER_OBJ:      e->tagType = ACL_ENTRY_TAG_TYPE_USER_OBJ;  break;
			case ACL_USER:          e->tagType = ACL_ENTRY_TAG_TYPE_USER;      break;
			case ACL_GROUP_OBJ:     e->tagType = ACL_ENTRY_TAG_TYPE_GROUP_OBJ; break;
			case ACL_GROUP:         e->tagType = ACL_ENTRY_TAG_TYPE_GROUP;     break;
			case ACL_MASK:          e->tagType = ACL_ENTRY_TAG_TYPE_MASK;      break;
			case ACL_OTHER:         e->tagType = ACL_ENTRY_TAG_TYPE_OTHER;     break;
			case ACL_UNDEFINED_TAG: /* TODO */                                 break;
			default:                                                           break;
		}
		
		// Set tag qualifier
		switch(tagType)
		{
			case ACL_USER:
			case ACL_GROUP:
			{
				void *tagQualifier = acl_get_qualifier(currEntry);
				if(!tagQualifier)
				{
					store_errno();
					return cleanup_with_error_code(NATIVE_ERROR_GET_ACL_ENTRY_QUALIFIER_FAILED);
				}
				e->tagQualifier = *(int32_t *)tagQualifier;
				
				acl_free(tagQualifier);
				break;
			}
			
			default:
				e->tagQualifier = 0;
				break;
		}
		
		// Set permissions
		acl_permset_t permset;
		if(acl_get_permset(currEntry, &permset) < 0)
		{
			store_errno();
			return cleanup_with_error_code(NATIVE_ERROR_GET_ACL_ENTRY_PERMSET_FAILED);
		}
		int canRead = acl_get_perm(permset, ACL_READ);
		if(canRead < 0)
		{
			store_errno();
			return cleanup_with_error_code(NATIVE_ERROR_GET_ACL_ENTRY_PERM_FAILED);
		}
		int canWrite = acl_get_perm(permset, ACL_WRITE);
		if(canWrite < 0)
		{
			store_errno();
			return cleanup_with_error_code(NATIVE_ERROR_GET_ACL_ENTRY_PERM_FAILED);
		}
		int canExecute = acl_get_perm(permset, ACL_EXECUTE);
		if(canExecute < 0)
		{
			store_errno();
			return cleanup_with_error_code(NATIVE_ERROR_GET_ACL_ENTRY_PERM_FAILED);
		}
		e->permissions = (canRead > 0 ? FILE_PERMISSION_READ : FILE_PERMISSION_NONE)
		               | (canWrite > 0 ? FILE_PERMISSION_WRITE : FILE_PERMISSION_NONE)
		               | (canExecute > 0 ? FILE_PERMISSION_EXECUTE : FILE_PERMISSION_NONE);
		
		// Next entry
		++i;
		aclStatus = acl_get_entry(_acl, ACL_NEXT_ENTRY, &currEntry);
	}
	if(aclStatus < 0)
	{
		store_errno();
		return cleanup_with_error_code(NATIVE_ERROR_GET_ACL_ENTRY_FAILED);
	}
	
	// Done
	return cleanup_with_error_code(NATIVE_ERROR_SUCCESS);
}

extern native_error_code_t SetFilePermissionDataAndAcl(const char *fileName, int32_t setDefaultAcl, native_permission_data_container_t *dataContainer, native_acl_entry_t *entries)
{
	// Reset errno
	_lastErrnoValue = 0;
	
	// Open file or directory
	_fd = open(fileName, O_RDONLY);
	if(_fd < 0)
	{
		store_errno();
		return NATIVE_ERROR_OPEN_FAILED;
	}
	
	// Read file metadata, to be able to detect whether owner or group are modified
	struct stat fileStat;
	if(fstat(_fd, &fileStat) < 0)
	{
		store_errno();
		return cleanup_with_error_code(NATIVE_ERROR_FSTAT_FAILED);
	}
	
	// Change owner and group
	uid_t newOwner = -1;
	gid_t newGroup = -1;
	if(dataContainer->ownerId != fileStat.st_uid)
		newOwner = dataContainer->ownerId;
	if(dataContainer->groupId != fileStat.st_gid)
		newGroup = dataContainer->groupId;
	if((newOwner != -1 || newGroup != -1) && fchown(_fd, newOwner, newGroup) < 0)
	{
		store_errno();
		return cleanup_with_error_code(NATIVE_ERROR_CHOWN_FAILED);
	}
	
	// Build standard permission bitfield
	mode_t chmodBits = ((dataContainer->ownerPermissions & FILE_PERMISSION_READ) ? S_IRUSR : 0)
	                 | ((dataContainer->ownerPermissions & FILE_PERMISSION_WRITE) ? S_IWUSR : 0)
	                 | ((dataContainer->ownerPermissions & FILE_PERMISSION_EXECUTE) ? S_IXUSR : 0)
	                 | ((dataContainer->ownerPermissions & FILE_PERMISSION_SETID) ? S_ISUID : 0)
	                 | ((dataContainer->ownerPermissions & FILE_PERMISSION_STICKY) ? S_ISVTX : 0)
					 | ((dataContainer->groupPermissions & FILE_PERMISSION_READ) ? S_IRGRP : 0)
	                 | ((dataContainer->groupPermissions & FILE_PERMISSION_WRITE) ? S_IWGRP : 0)
	                 | ((dataContainer->groupPermissions & FILE_PERMISSION_EXECUTE) ? S_IXGRP : 0)
	                 | ((dataContainer->groupPermissions & FILE_PERMISSION_SETID) ? S_ISGID : 0)
					 | ((dataContainer->otherPermissions & FILE_PERMISSION_READ) ? S_IROTH : 0)
	                 | ((dataContainer->otherPermissions & FILE_PERMISSION_WRITE) ? S_IWOTH : 0)
	                 | ((dataContainer->otherPermissions & FILE_PERMISSION_EXECUTE) ? S_IXOTH : 0);
	if(fchmod(_fd, chmodBits) < 0)
	{
		store_errno();
		return cleanup_with_error_code(NATIVE_ERROR_CHMOD_FAILED);
	}
	
	// Create new ACL
	_acl = acl_init(dataContainer->aclSize);
	if(!_acl)
	{
		store_errno();
		return cleanup_with_error_code(NATIVE_ERROR_INIT_ACL_FAILED);
	}
	
	// Build ACL entries
	for(int i = 0; i < dataContainer->aclSize; ++i)
	{
		// Retrieve current entry data
		native_acl_entry_t *entryData = &entries[i];
		
		// Initialize ACL entry
		acl_entry_t aclEntry;
		int aclStatus = acl_create_entry(&_acl, &aclEntry);
		if(aclStatus < 0)
		{
			store_errno();
			return cleanup_with_error_code(NATIVE_ERROR_CREATE_ACL_ENTRY_FAILED);
		}
		
		// Assign tag type
		acl_tag_t tagType;
		switch(entryData->tagType)
		{
			case ACL_ENTRY_TAG_TYPE_USER_OBJ:  tagType = ACL_USER_OBJ;  break;
			case ACL_ENTRY_TAG_TYPE_USER:      tagType = ACL_USER;      break;
			case ACL_ENTRY_TAG_TYPE_GROUP_OBJ: tagType = ACL_GROUP_OBJ; break;
			case ACL_ENTRY_TAG_TYPE_GROUP:     tagType = ACL_GROUP;     break;
			case ACL_ENTRY_TAG_TYPE_MASK:      tagType = ACL_MASK;      break;
			case ACL_ENTRY_TAG_TYPE_OTHER:     tagType = ACL_OTHER;     break;
			default: return cleanup_with_error_code(NATIVE_ERROR_INVALID_TAG_TYPE);
		}
		if(acl_set_tag_type(aclEntry, tagType) < 0)
		{
			store_errno();
			return cleanup_with_error_code(NATIVE_ERROR_SET_ACL_ENTRY_TAG_TYPE_FAILED);
		}
		
		// Assign tag qualifier
		switch(entryData->tagType)
		{
			case ACL_ENTRY_TAG_TYPE_USER:
			case ACL_ENTRY_TAG_TYPE_GROUP:
			{
				if(acl_set_qualifier(aclEntry, &entryData->tagQualifier) < 0)
				{
					store_errno();
					return cleanup_with_error_code(NATIVE_ERROR_SET_ACL_ENTRY_QUALIFIER_FAILED);
				}
				break;
			}
			
			default: break;
		}
		
		// Assign permissions
		acl_permset_t permset;
		if(acl_get_permset(aclEntry, &permset) < 0)
		{
			store_errno();
			return cleanup_with_error_code(NATIVE_ERROR_GET_ACL_ENTRY_PERMSET_FAILED);
		}
		if(acl_clear_perms(permset) < 0)
		{
			store_errno();
			return cleanup_with_error_code(NATIVE_ERROR_CLEAR_ACL_ENTRY_PERMS_FAILED);
		}
		if((entryData->permissions & FILE_PERMISSION_READ) && acl_add_perm(permset, ACL_READ) < 0)
		{
			store_errno();
			return cleanup_with_error_code(NATIVE_ERROR_ADD_ACL_ENTRY_PERM_FAILED);
		}
		if((entryData->permissions & FILE_PERMISSION_WRITE) && acl_add_perm(permset, ACL_WRITE) < 0)
		{
			store_errno();
			return cleanup_with_error_code(NATIVE_ERROR_ADD_ACL_ENTRY_PERM_FAILED);
		}
		if((entryData->permissions & FILE_PERMISSION_EXECUTE) && acl_add_perm(permset, ACL_EXECUTE) < 0)
		{
			store_errno();
			return cleanup_with_error_code(NATIVE_ERROR_ADD_ACL_ENTRY_PERM_FAILED);
		}
	}
	
	// Validate ACL
	if(acl_valid(_acl) < 0)
	{
		store_errno();
		return cleanup_with_error_code(NATIVE_ERROR_VALIDATE_ACL_FAILED);
	}
	
	// Assign ACL to file
	if(acl_set_fd(_fd, _acl) < 0)
	{
		store_errno();
		return cleanup_with_error_code(NATIVE_ERROR_SET_ACL_FAILED);
	}
	
	// Done
	return cleanup_with_error_code(NATIVE_ERROR_SUCCESS);
}

int64_t GetLastErrnoValue(char *errnoStringBuffer, int errnoStringBufferLength)
{
	// Only copy error string if errno is set
	if(_lastErrnoValue == 0)
		errnoStringBuffer[0] = '\0';
	else
		strcpy_s(errnoStringBuffer, errnoStringBufferLength, _lastErrnoString);
	return _lastErrnoValue;
}