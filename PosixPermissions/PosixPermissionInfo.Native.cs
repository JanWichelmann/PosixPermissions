using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PosixPermissions
{
    public partial class PosixPermissionInfo
    { 
        /// <summary>
        /// Object for native operations.
        /// </summary>
        private readonly INativeLibraryInterface _nativeLibraryInterface;

        /// <summary>
        /// Loads the permission data from the given file or directory.
        /// </summary>
        /// <param name="nativeLibraryInterface">Object for native operations.</param>
        /// <param name="fullPath">Full path to the file or directory.</param>
        /// <param name="loadDefaultAcl">Specifies whether to load a directory's default ACL (1) or not (0). This must be 0 for files.</param>
        internal PosixPermissionInfo(INativeLibraryInterface nativeLibraryInterface, string fullPath, int loadDefaultAcl)
        {
            _nativeLibraryInterface = nativeLibraryInterface ?? throw new ArgumentNullException(nameof(nativeLibraryInterface));

            // Get permission data
            // TODO handle/document exceptions
            var acl = _nativeLibraryInterface.GetPermissionData(fullPath, loadDefaultAcl, out var dataContainer);

            // Initialize members
            OwnerId = dataContainer.OwnerId;
            OwnerPermissions = dataContainer.OwnerPermissions;
            GroupId = dataContainer.GroupId;
            GroupPermissions = dataContainer.GroupPermissions;
            OtherPermissions = dataContainer.OtherPermissions;

            // Parse ACL
            foreach(var entry in acl)
            {
                switch(entry.TagType)
                {
                    case AccessControlListEntryTagTypes.User:
                    {
                        // Add user to list
                        if(entry.TagQualifier != OwnerId)
                            _aclUserPermissions[entry.TagQualifier] = entry.Permissions;

                        break;
                    }

                    case AccessControlListEntryTagTypes.Group:
                    {
                        // Add group to list
                        if(entry.TagQualifier != GroupId)
                            _aclGroupPermissions[entry.TagQualifier] = entry.Permissions;

                        break;
                    }
                }
            }
        }

        /// <summary>
        /// Creates a new <see cref="PosixPermissionInfo"/> object from the given file.
        /// </summary>
        /// <param name="nativeLibraryInterface">Object for native operations.</param>
        /// <param name="file">The file to load the permissions for.</param>
        public PosixPermissionInfo(INativeLibraryInterface nativeLibraryInterface, FileInfo file)
            : this(nativeLibraryInterface,file.FullName, 0)
        { }

        /// <summary>
        /// Creates a new <see cref="PosixPermissionInfo"/> object from the given directory.
        /// </summary>
        /// <param name="nativeLibraryInterface">Object for native operations.</param>
        /// <param name="directory">The directory to load the permissions for.</param>
        /// <param name="loadDefaultAcl">Specifies whether the directory's own or default ACL should be loaded.</param>
        public PosixPermissionInfo(INativeLibraryInterface nativeLibraryInterface, DirectoryInfo directory, bool loadDefaultAcl)
            : this(nativeLibraryInterface,directory.FullName, loadDefaultAcl ? 0 : 1)
        { }

        /// <summary>
        /// Applies the contained permissions to the given file.
        /// </summary>
        /// <param name="file">The file to apply the permissions to.</param>
        public void ApplyPermissions(FileInfo file)
            => ApplyPermissions(file.FullName, false);

        /// <summary>
        /// Applies the contained permissions to the given directory.
        /// </summary>
        /// <param name="directory">The directory to apply the permissions to.</param>
        /// <param name="asDefault">Optional. Specifies whether to update the directory's default ACL. When using this option, the contained UNIX permissions are not applied to the file (chown/chmod), but are still assumed as consistent!</param>
        public void ApplyPermissions(DirectoryInfo directory, bool asDefault = false)
            => ApplyPermissions(directory.FullName, asDefault);

        /// <summary>
        /// <para>Applies the contained permissions to the given file or directory.</para>
        /// <para>
        /// Order in ACL:
        /// <list type="number">
        /// <item>UserObj (owner permissions)</item>
        /// <item>GroupObj (group permissions)</item>
        /// <item>Other (other permissions)</item>
        /// <item>User (permissions of other users)</item>
        /// <item>Group (permissions of other groups)</item>
        /// <item>Mask (bitwise OR of all group permissions)</item>
        /// </list>
        /// </para>
        /// </summary>
        /// <param name="fullPath">The file or directory to apply the permissions to.</param>
        /// <param name="asDefault">Optional. Specifies whether to update a directory's default ACL. When using this option, the contained UNIX permissions are not applied to the file (chown/chmod), but are still assumed as consistent! This must be false for files.</param>
        internal void ApplyPermissions(string fullPath, bool asDefault)
        {
            // Calculate ACL size first
            int aclSize = 3 + _aclUserPermissions.Count + _aclGroupPermissions.Count + 1;

            // Collect base permissions
            NativePermissionDataContainer dataContainer = new NativePermissionDataContainer()
            {
                AclSize = aclSize,

                // These are ignored when a directory's default ACL is set
                OwnerId = OwnerId,
                OwnerPermissions = OwnerPermissions,
                GroupId = GroupId,
                GroupPermissions = GroupPermissions,
                OtherPermissions = OtherPermissions
            };

            // Allocate ACL
            AccessControlListEntry[] aclEntries = new AccessControlListEntry[aclSize];
            int pos = 0;

            // Add UNIX permissions
            aclEntries[pos++] = new AccessControlListEntry
            {
                TagType = AccessControlListEntryTagTypes.UserObj,
                TagQualifier = OwnerId,
                Permissions = OwnerPermissions
            };
            aclEntries[pos++] = new AccessControlListEntry
            {
                TagType = AccessControlListEntryTagTypes.GroupObj,
                TagQualifier = GroupId,
                Permissions = GroupPermissions
            };
            aclEntries[pos++] = new AccessControlListEntry
            {
                TagType = AccessControlListEntryTagTypes.Other,
                TagQualifier = -1,
                Permissions = OtherPermissions
            };

            // Add user and group entries
            FilePermissions aclMask = GroupPermissions | OtherPermissions;
            foreach(var perm in _aclUserPermissions)
            {
                aclMask |= perm.Value;
                aclEntries[pos++] = new AccessControlListEntry
                {
                    TagType = AccessControlListEntryTagTypes.User,
                    TagQualifier = perm.Key,
                    Permissions = perm.Value
                };
            }
            foreach(var perm in _aclGroupPermissions)
            {
                aclMask |= perm.Value;
                aclEntries[pos++] = new AccessControlListEntry
                {
                    TagType = AccessControlListEntryTagTypes.Group,
                    TagQualifier = perm.Key,
                    Permissions = perm.Value
                };
            }

            // Add mask
            aclEntries[pos++] = new AccessControlListEntry
            {
                TagType = AccessControlListEntryTagTypes.Mask,
                TagQualifier = -1,
                Permissions = aclMask
            };

            // Apply permissions
            _nativeLibraryInterface.SetPermissionData(fullPath, asDefault ? 1 : 0, ref dataContainer, aclEntries);

            // TODO handle/document exceptions
        }
    }
}
